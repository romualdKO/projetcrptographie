import base64
import json
import os
import socket
import tkinter as tk
from pathlib import Path
from tkinter import filedialog

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

PORT = 5000
BG = "#080d1a"
PANEL = "#0f1729"
FIELD = "#111c32"
EDGE = "#202d49"
TEXT = "#e8efff"
MUTED = "#8392b2"
CYAN = "#18c5dc"
GREEN = "#39d6a0"
AMBER = "#ffbd69"


def chiffrer(texte, chemin_cle_publique):
    """Chiffre le message avec AES-GCM et protège la clé AES avec RSA-OAEP."""
    cle_pem = Path(chemin_cle_publique).read_bytes()
    cle_publique = serialization.load_pem_public_key(cle_pem)
    if not isinstance(cle_publique, rsa.RSAPublicKey):
        raise ValueError("Le fichier sélectionné ne contient pas une clé publique RSA.")
    if cle_publique.key_size < 2048:
        raise ValueError("La clé RSA doit faire au moins 2048 bits.")

    cle_aes = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(12)
    cle_aes_chiffree = cle_publique.encrypt(
        cle_aes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    texte_chiffre = AESGCM(cle_aes).encrypt(nonce, texte.encode("utf-8"), None)

    paquet = {
        "alg": "RSA-OAEP-SHA256+A256GCM",
        "key": base64.b64encode(cle_aes_chiffree).decode("ascii"),
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ciphertext": base64.b64encode(texte_chiffre).decode("ascii"),
    }
    return json.dumps(paquet, separators=(",", ":"))


def envoyer():
    chemin_cle = entry_cle.get().strip()
    texte = txt_clair.get("1.0", tk.END).strip()
    ip = entry_ip.get().strip()
    if not chemin_cle or not texte or not ip:
        set_status("CHAMPS MANQUANTS", "Renseigne l'adresse, la clé publique et le message.", AMBER)
        return

    try:
        crypte = chiffrer(texte, chemin_cle)
    except (OSError, TypeError, ValueError) as e:
        set_status("CLE PUBLIQUE INVALIDE", str(e), AMBER)
        return

    txt_crypte.configure(state="normal")
    txt_crypte.delete("1.0", tk.END)
    txt_crypte.insert(tk.END, crypte)
    txt_crypte.configure(state="disabled")
    set_status("CONNEXION EN COURS", f"Transmission vers {ip}:{PORT}...", CYAN)
    root.update_idletasks()

    try:
        with socket.create_connection((ip, PORT), timeout=5) as s:
            s.sendall(crypte.encode("ascii"))
        set_status("TRANSMISSION REUSSIE", f"Données envoyées vers {ip}:{PORT}.", GREEN)
    except OSError as e:
        set_status("ERREUR RESEAU", str(e), AMBER)


def set_status(title, detail, color):
    status_title.configure(text=title, fg=color)
    status_detail.configure(text=detail)
    status_dot.itemconfigure(status_dot_id, fill=color)


def choisir_cle_publique():
    chemin = filedialog.askopenfilename(
        title="Choisir la clé publique RSA du destinataire",
        filetypes=(("Clé publique PEM", "*.pem *.pub"), ("Tous les fichiers", "*.*")),
    )
    if chemin:
        entry_cle.delete(0, tk.END)
        entry_cle.insert(0, chemin)
        set_status("CLE PUBLIQUE CHARGEE", Path(chemin).name, GREEN)


def copier_crypte():
    texte = txt_crypte.get("1.0", tk.END).strip()
    if texte:
        root.clipboard_clear()
        root.clipboard_append(texte)
        set_status("COPIE", "Texte encodé copié dans le presse-papiers.", CYAN)


def update_count(_event=None):
    txt_clair.edit_modified(False)
    count = len(txt_clair.get("1.0", "end-1c"))
    char_count.configure(text=f"{count} CARACTERES")


def make_panel(parent, **kwargs):
    return tk.Frame(parent, bg=PANEL, highlightbackground=EDGE,
                    highlightthickness=1, **kwargs)


root = tk.Tk()
root.title("PC 1 - Emetteur")
root.geometry("1060x820")
root.minsize(820, 700)
root.configure(bg=BG)

outer = tk.Frame(root, bg=BG)
outer.pack(fill="both", expand=True, padx=28, pady=22)

header = tk.Frame(outer, bg=BG)
header.pack(fill="x", pady=(0, 18))
logo = tk.Canvas(header, width=38, height=38, bg=FIELD, highlightthickness=0)
logo.pack(side="left", padx=(0, 11))
logo.create_arc(9, 8, 29, 29, start=35, extent=290, style="arc", outline=CYAN, width=3)
logo.create_line(14, 20, 18, 24, 26, 14, fill=GREEN, width=2, capstyle="round")

title_area = tk.Frame(header, bg=BG)
title_area.pack(side="left", anchor="w")
tk.Label(title_area, text="PC 1 - EMETTEUR", bg=BG, fg=TEXT,
         font=("Segoe UI", 15, "bold")).pack(anchor="w")
tk.Label(title_area, text="RSA-OAEP + AES-GCM  ·  Socket TCP  ·  Port 5000", bg=BG, fg=MUTED,
         font=("Segoe UI", 9)).pack(anchor="w", pady=(2, 0))

header_right = tk.Frame(header, bg=BG)
header_right.pack(side="right", anchor="ne", pady=5)
tk.Label(header_right, text="RSA + AES-GCM", bg=FIELD, fg=CYAN,
         font=("Segoe UI", 8, "bold"), padx=10, pady=6).pack(side="left", padx=(0, 10))
status_dot = tk.Canvas(header_right, width=10, height=10, bg=BG, highlightthickness=0)
status_dot.pack(side="left", padx=(0, 6))
status_dot_id = status_dot.create_oval(1, 1, 9, 9, fill=GREEN, outline="")
status_title = tk.Label(header_right, text="PRET", bg=BG, fg=GREEN,
                        font=("Segoe UI", 8, "bold"))
status_title.pack(side="left")

route = make_panel(outer)
route.pack(fill="x", pady=(0, 14))
tk.Label(route, text="DESTINATAIRE", bg=PANEL, fg=MUTED,
         font=("Segoe UI", 8, "bold")).grid(row=0, column=0, sticky="w", padx=(15, 8), pady=(12, 5))
tk.Label(route, text="CLE PUBLIQUE RSA", bg=PANEL, fg=MUTED,
         font=("Segoe UI", 8, "bold")).grid(row=0, column=1, sticky="w", padx=8, pady=(12, 5))
tk.Label(route, text="PORT", bg=PANEL, fg=MUTED,
         font=("Segoe UI", 8, "bold")).grid(row=0, column=2, sticky="w", padx=(8, 15), pady=(12, 5))
route.columnconfigure(0, weight=5, uniform="route")
route.columnconfigure(1, weight=5, uniform="route")

entry_ip = tk.Entry(route, bg=FIELD, fg=TEXT, insertbackground=CYAN, relief="flat",
                    highlightthickness=1, highlightbackground=EDGE,
                    highlightcolor=CYAN, font=("Consolas", 10))
entry_ip.insert(0, "127.0.0.1")
entry_ip.grid(row=1, column=0, sticky="ew", padx=(15, 8), pady=(0, 13), ipady=8)
key_area = tk.Frame(route, bg=PANEL)
key_area.grid(row=1, column=1, sticky="ew", padx=8, pady=(0, 13))
key_area.columnconfigure(0, weight=1)
entry_cle = tk.Entry(key_area, bg=FIELD, fg=TEXT, insertbackground=CYAN, relief="flat",
                     highlightthickness=1, highlightbackground=EDGE,
                     highlightcolor=CYAN, font=("Consolas", 10))
entry_cle.grid(row=0, column=0, sticky="ew", ipady=8)
key_button = tk.Button(key_area, text="Parcourir", command=choisir_cle_publique, bg=FIELD, fg=CYAN,
                       activebackground=EDGE, activeforeground=TEXT, relief="flat",
                       bd=0, cursor="hand2", padx=8)
key_button.grid(row=0, column=1, padx=(5, 0), sticky="ns")
tk.Label(route, text=str(PORT), bg=FIELD, fg=GREEN, font=("Consolas", 10, "bold"),
         padx=14, pady=8).grid(row=1, column=2, sticky="w", padx=(8, 15), pady=(0, 13))

compose = make_panel(outer)
compose.pack(fill="both", expand=True, pady=(0, 12))
compose.columnconfigure(0, weight=1)
compose.rowconfigure(1, weight=1)
compose_heading = tk.Frame(compose, bg=PANEL)
compose_heading.grid(row=0, column=0, sticky="ew", padx=15, pady=(11, 7))
tk.Label(compose_heading, text="TEXTE EN CLAIR", bg=PANEL, fg=TEXT,
         font=("Segoe UI", 8, "bold")).pack(side="left")
char_count = tk.Label(compose_heading, text="0 CARACTERES", bg=PANEL, fg=MUTED,
                      font=("Segoe UI", 8))
char_count.pack(side="right")
txt_clair = tk.Text(compose, height=6, wrap="word", bg=FIELD, fg=TEXT,
                    insertbackground=CYAN, relief="flat", padx=12, pady=10,
                    highlightthickness=1, highlightbackground=EDGE,
                    highlightcolor=CYAN, font=("Segoe UI", 10))
txt_clair.grid(row=1, column=0, sticky="nsew", padx=15, pady=(0, 14))
txt_clair.bind("<<Modified>>", update_count)

send_row = tk.Frame(outer, bg=BG)
send_row.pack(fill="x", pady=(0, 12))
send_button = tk.Button(send_row, text="CHIFFRER ET ENVOYER  >", command=envoyer,
                        bg=CYAN, fg="#06121b", activebackground="#55d9e8",
                        activeforeground="#06121b", relief="flat", bd=0,
                        cursor="hand2", font=("Segoe UI", 9, "bold"),
                        padx=22, pady=11)
send_button.pack()

result = make_panel(outer)
result.pack(fill="both", expand=True, pady=(0, 12))
result.columnconfigure(0, weight=1)
result.rowconfigure(1, weight=1)
result_heading = tk.Frame(result, bg=PANEL)
result_heading.grid(row=0, column=0, sticky="ew", padx=15, pady=(11, 7))
tk.Label(result_heading, text="TEXTE CRYPTE", bg=PANEL, fg=TEXT,
         font=("Segoe UI", 8, "bold")).pack(side="left")
tk.Label(result_heading, text="RSA-OAEP + AES-256-GCM", bg=FIELD, fg=CYAN,
         font=("Segoe UI", 8), padx=8, pady=4).pack(side="left", padx=(9, 0))
copy_button = tk.Button(result_heading, text="Copier", command=copier_crypte,
                        bg=FIELD, fg=TEXT, activebackground=EDGE,
                        activeforeground=CYAN, relief="flat", bd=0,
                        cursor="hand2", padx=10, pady=5)
copy_button.pack(side="right")
txt_crypte = tk.Text(result, height=5, wrap="char", bg="#080d1b", fg=GREEN,
                     relief="flat", padx=12, pady=10, font=("Consolas", 9),
                     highlightthickness=1, highlightbackground=EDGE)
txt_crypte.grid(row=1, column=0, sticky="nsew", padx=15, pady=(0, 14))
txt_crypte.configure(state="disabled")

footer = tk.Frame(outer, bg=BG)
footer.pack(fill="x")
status_detail = tk.Label(footer, text="Chiffrement hybride  ·  RSA-OAEP protège la clé AES",
                         bg=BG, fg=MUTED, font=("Segoe UI", 8), anchor="w")
status_detail.pack(fill="x")

root.mainloop()
