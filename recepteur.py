import base64
import json
import socket
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

PORT = 5000
MAX_PACKET_SIZE = 10 * 1024 * 1024
BG = "#080d1a"
PANEL = "#0f1729"
FIELD = "#111c32"
EDGE = "#202d49"
TEXT = "#e8efff"
MUTED = "#8392b2"
CYAN = "#18c5dc"
GREEN = "#39d6a0"
AMBER = "#ffbd69"


def dechiffrer(donnees, chemin_cle_privee):
    paquet = json.loads(donnees)
    if paquet.get("alg") != "RSA-OAEP-SHA256+A256GCM":
        raise ValueError("Algorithme ou format de paquet non reconnu.")

    cle_privee = serialization.load_pem_private_key(
        Path(chemin_cle_privee).read_bytes(), password=None
    )
    if not isinstance(cle_privee, rsa.RSAPrivateKey):
        raise ValueError("Le fichier sélectionné ne contient pas une clé privée RSA.")

    cle_aes = cle_privee.decrypt(
        base64.b64decode(paquet["key"], validate=True),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    texte_clair = AESGCM(cle_aes).decrypt(
        base64.b64decode(paquet["nonce"], validate=True),
        base64.b64decode(paquet["ciphertext"], validate=True),
        None,
    )
    return texte_clair.decode("utf-8")


def set_status(title, detail, color):
    status_title.configure(text=title, fg=color)
    status_detail.configure(text=detail)
    status_dot.itemconfigure(status_dot_id, fill=color)


def choisir_cle_privee():
    chemin = filedialog.askopenfilename(
        title="Choisir la clé privée RSA",
        filetypes=(("Clé privée PEM", "*.pem *.key"), ("Tous les fichiers", "*.*")),
    )
    if chemin:
        entry_private.delete(0, tk.END)
        entry_private.insert(0, chemin)
        set_status("CLE PRIVEE CHARGEE", Path(chemin).name, GREEN)


def generer_cles():
    dossier = filedialog.askdirectory(title="Choisir le dossier des clés sur ce PC")
    if not dossier:
        return

    chemin_prive = Path(dossier) / "cle_privee.pem"
    chemin_public = Path(dossier) / "cle_publique.pem"
    if (chemin_prive.exists() or chemin_public.exists()) and not messagebox.askyesno(
        "Remplacer les clés ?",
        "Un fichier de clé existe déjà dans ce dossier. Le remplacer peut rendre "
        "illisibles les messages chiffrés avec l'ancienne clé. Continuer ?",
    ):
        return

    paire = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    chemin_prive.write_bytes(
        paire.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    chemin_public.write_bytes(
        paire.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    entry_private.delete(0, tk.END)
    entry_private.insert(0, str(chemin_prive))
    set_status("PAIRE DE CLES CREEE", f"Transfère uniquement : {chemin_public}", GREEN)


def recevoir_paquet(donnees):
    try:
        message = dechiffrer(donnees, entry_private.get().strip())
    except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError,
            InvalidTag, UnicodeDecodeError) as erreur:
        set_status("DECHIFFREMENT IMPOSSIBLE", str(erreur), AMBER)
        return

    txt_message.configure(state="normal")
    txt_message.delete("1.0", tk.END)
    txt_message.insert("1.0", message)
    txt_message.configure(state="disabled")
    set_status("MESSAGE DECHIFFRE", "Message reçu et authentifié par AES-GCM.", GREEN)


def boucle_reception(ecoute, arret):
    while not arret.is_set():
        try:
            connexion, adresse = ecoute.accept()
        except socket.timeout:
            continue
        except OSError:
            break

        with connexion:
            connexion.settimeout(10)
            morceaux = []
            taille = 0
            try:
                while True:
                    morceau = connexion.recv(65536)
                    if not morceau:
                        break
                    taille += len(morceau)
                    if taille > MAX_PACKET_SIZE:
                        raise ValueError("Le paquet dépasse la taille maximale autorisée.")
                    morceaux.append(morceau)
            except (OSError, ValueError) as erreur:
                root.after(0, set_status, "RECEPTION IMPOSSIBLE", str(erreur), AMBER)
                continue

        if morceaux:
            root.after(0, recevoir_paquet, b"".join(morceaux))
            root.after(0, status_detail.configure,
                       {"text": f"Connexion reçue depuis {adresse[0]}:{adresse[1]}."})


def demarrer_ecoute():
    chemin = entry_private.get().strip()
    if not chemin:
        set_status("CLE PRIVEE REQUISE", "Choisis ou génère la clé privée du destinataire.", AMBER)
        return

    try:
        cle = serialization.load_pem_private_key(Path(chemin).read_bytes(), password=None)
        if not isinstance(cle, rsa.RSAPrivateKey):
            raise ValueError("Le fichier sélectionné ne contient pas une clé privée RSA.")
        ecoute = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ecoute.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        ecoute.bind(("0.0.0.0", PORT))
        ecoute.listen()
        ecoute.settimeout(0.5)
    except (OSError, TypeError, ValueError) as erreur:
        set_status("DEMARRAGE IMPOSSIBLE", str(erreur), AMBER)
        return

    stop_event.clear()
    start_button.configure(state="disabled")
    stop_button.configure(state="normal")
    set_status("EN ECOUTE", f"Port TCP {PORT} · utilise l'IP locale de ce PC sur l'émetteur.", GREEN)
    threading.Thread(target=boucle_reception, args=(ecoute, stop_event), daemon=True).start()
    root.server_socket = ecoute


def arreter_ecoute():
    stop_event.set()
    ecoute = getattr(root, "server_socket", None)
    if ecoute is not None:
        try:
            ecoute.close()
        except OSError:
            pass
        root.server_socket = None
    start_button.configure(state="normal")
    stop_button.configure(state="disabled")
    set_status("ECOUTE ARRETEE", "Le récepteur n'accepte plus de connexions.", MUTED)


def fermer():
    arreter_ecoute()
    root.destroy()


def make_panel(parent):
    return tk.Frame(parent, bg=PANEL, highlightbackground=EDGE, highlightthickness=1)


root = tk.Tk()
root.title("PC 2 - Recepteur RSA")
root.geometry("900x700")
root.minsize(760, 600)
root.configure(bg=BG)
root.protocol("WM_DELETE_WINDOW", fermer)
stop_event = threading.Event()

outer = tk.Frame(root, bg=BG)
outer.pack(fill="both", expand=True, padx=28, pady=22)

header = tk.Frame(outer, bg=BG)
header.pack(fill="x", pady=(0, 18))
logo = tk.Canvas(header, width=38, height=38, bg=FIELD, highlightthickness=0)
logo.pack(side="left", padx=(0, 11))
logo.create_arc(9, 8, 29, 29, start=35, extent=290, style="arc", outline=CYAN, width=3)
logo.create_line(14, 20, 18, 24, 26, 14, fill=GREEN, width=2, capstyle="round")
heading = tk.Frame(header, bg=BG)
heading.pack(side="left", anchor="w")
tk.Label(heading, text="PC 2 - RECEPTEUR", bg=BG, fg=TEXT,
         font=("Segoe UI", 15, "bold")).pack(anchor="w")
tk.Label(heading, text="RSA-OAEP + AES-GCM  ·  Socket TCP  ·  Port 5000",
         bg=BG, fg=MUTED, font=("Segoe UI", 9)).pack(anchor="w", pady=(2, 0))

status_area = tk.Frame(header, bg=BG)
status_area.pack(side="right", anchor="ne", pady=10)
status_dot = tk.Canvas(status_area, width=10, height=10, bg=BG, highlightthickness=0)
status_dot.pack(side="left", padx=(0, 6))
status_dot_id = status_dot.create_oval(1, 1, 9, 9, fill=MUTED, outline="")
status_title = tk.Label(status_area, text="ARRETE", bg=BG, fg=MUTED,
                        font=("Segoe UI", 8, "bold"))
status_title.pack(side="left")

keys = make_panel(outer)
keys.pack(fill="x", pady=(0, 14))
keys.columnconfigure(0, weight=1)
tk.Label(keys, text="CLE PRIVEE DU DESTINATAIRE", bg=PANEL, fg=MUTED,
         font=("Segoe UI", 8, "bold")).grid(row=0, column=0, columnspan=2,
                                             sticky="w", padx=15, pady=(12, 6))
entry_private = tk.Entry(keys, bg=FIELD, fg=TEXT, insertbackground=CYAN, relief="flat",
                         highlightthickness=1, highlightbackground=EDGE,
                         highlightcolor=CYAN, font=("Consolas", 9))
entry_private.grid(row=1, column=0, sticky="ew", padx=(15, 7), pady=(0, 10), ipady=8)
tk.Button(keys, text="Parcourir", command=choisir_cle_privee, bg=FIELD, fg=CYAN,
          activebackground=EDGE, activeforeground=TEXT, relief="flat", bd=0,
          cursor="hand2", padx=12).grid(row=1, column=1, padx=(0, 15), pady=(0, 10))
tk.Label(keys, text="Pas encore de clés ? Génère-les ici. Transfère uniquement cle_publique.pem vers le PC émetteur.",
         bg=PANEL, fg=MUTED, font=("Segoe UI", 8), anchor="w").grid(
             row=2, column=0, sticky="ew", padx=15, pady=(0, 12))
tk.Button(keys, text="Generer une paire RSA", command=generer_cles, bg=FIELD, fg=GREEN,
          activebackground=EDGE, activeforeground=TEXT, relief="flat", bd=0,
          cursor="hand2", padx=12, pady=7).grid(row=2, column=1, padx=(0, 15), pady=(0, 12))

controls = tk.Frame(outer, bg=BG)
controls.pack(fill="x", pady=(0, 14))
start_button = tk.Button(controls, text="DEMARRER L'ECOUTE", command=demarrer_ecoute,
                         bg=CYAN, fg="#06121b", activebackground="#55d9e8",
                         activeforeground="#06121b", relief="flat", bd=0,
                         cursor="hand2", font=("Segoe UI", 9, "bold"),
                         padx=20, pady=11)
start_button.pack(side="left")
stop_button = tk.Button(controls, text="ARRETER", command=arreter_ecoute,
                        bg=FIELD, fg=TEXT, activebackground=EDGE,
                        activeforeground=AMBER, relief="flat", bd=0,
                        cursor="hand2", font=("Segoe UI", 9, "bold"),
                        padx=18, pady=11, state="disabled")
stop_button.pack(side="left", padx=(8, 0))
tk.Label(controls, text=f"TCP  ·  {PORT}", bg=BG, fg=MUTED,
         font=("Consolas", 9)).pack(side="right", pady=11)

message_panel = make_panel(outer)
message_panel.pack(fill="both", expand=True, pady=(0, 12))
message_panel.columnconfigure(0, weight=1)
message_panel.rowconfigure(1, weight=1)
tk.Label(message_panel, text="MESSAGE DECHIFFRE", bg=PANEL, fg=TEXT,
         font=("Segoe UI", 8, "bold")).grid(row=0, column=0, sticky="w",
                                             padx=15, pady=(13, 8))
txt_message = tk.Text(message_panel, height=8, wrap="word", bg=FIELD, fg=GREEN,
                      relief="flat", padx=12, pady=10, font=("Segoe UI", 10),
                      highlightthickness=1, highlightbackground=EDGE)
txt_message.insert("1.0", "Le message reçu apparaîtra ici.")
txt_message.configure(state="disabled")
txt_message.grid(row=1, column=0, sticky="nsew", padx=15, pady=(0, 14))

status_detail = tk.Label(outer, text="La clé privée reste sur ce PC.", bg=BG, fg=MUTED,
                         font=("Segoe UI", 8), anchor="w")
status_detail.pack(fill="x")

root.mainloop()