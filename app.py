import argparse
import ipaddress
import json
import socket
import threading
import uuid
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


PROJECT_DIR = Path(__file__).resolve().parent
WEB_DIR = PROJECT_DIR / "web"
MAX_PACKET_SIZE = 1024 * 1024
MAX_HTTP_BODY = MAX_PACKET_SIZE + 16 * 1024
PACKET_ALGORITHM = "RSA-OAEP-SHA256+A256GCM"
INBOX = []
INBOX_LOCK = threading.Lock()
STOP_EVENT = threading.Event()
LISTENER_STATE = {"ready": False, "error": None}
APP_ROLE = "sender"
TCP_PORT = 5000


def is_valid_packet(packet):
    return (
        isinstance(packet, dict)
        and packet.get("alg") == PACKET_ALGORITHM
        and all(isinstance(packet.get(name), str) for name in ("key", "nonce", "ciphertext"))
        and len(packet["key"]) <= 2048
        and len(packet["nonce"]) == 16
        and len(packet["ciphertext"]) <= MAX_PACKET_SIZE
    )


def receive_loop():
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("0.0.0.0", TCP_PORT))
        listener.listen()
        listener.settimeout(0.5)
        LISTENER_STATE.update(ready=True, error=None)

        while not STOP_EVENT.is_set():
            try:
                connection, address = listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break

            with connection:
                connection.settimeout(10)
                chunks = []
                size = 0
                try:
                    while True:
                        chunk = connection.recv(65536)
                        if not chunk:
                            break
                        size += len(chunk)
                        if size > MAX_PACKET_SIZE:
                            raise ValueError("Paquet trop volumineux")
                        chunks.append(chunk)

                    packet = json.loads(b"".join(chunks).decode("utf-8"))
                    if not is_valid_packet(packet):
                        raise ValueError("Format de paquet non reconnu")
                except (OSError, ValueError, UnicodeDecodeError, json.JSONDecodeError):
                    continue

            message = {
                "id": uuid.uuid4().hex,
                "receivedAt": datetime.now(timezone.utc).isoformat(),
                "senderIp": address[0],
                "packet": packet,
            }
            with INBOX_LOCK:
                INBOX.append(message)
                if len(INBOX) > 100:
                    del INBOX[:-100]
    except OSError as error:
        LISTENER_STATE.update(ready=False, error=str(error))
    finally:
        LISTENER_STATE["ready"] = False
        listener.close()


class RequestHandler(BaseHTTPRequestHandler):
    server_version = "LocalCipher/1.0"

    def log_message(self, _format, *_args):
        return

    def send_bytes(self, status, content, content_type):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(content)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self'; style-src 'self'; "
            "connect-src 'self'; img-src 'self' data:; object-src 'none'; "
            "base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
        )
        self.end_headers()
        self.wfile.write(content)

    def send_json(self, status, payload):
        content = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        self.send_bytes(status, content, "application/json; charset=utf-8")

    def read_json(self):
        try:
            size = int(self.headers.get("Content-Length", "0"))
        except ValueError as error:
            raise ValueError("Longueur de requête invalide") from error
        if size < 1 or size > MAX_HTTP_BODY:
            raise ValueError("Taille de requête invalide")
        try:
            return json.loads(self.rfile.read(size).decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ValueError("JSON invalide") from error

    def do_GET(self):
        routes = {
            "/": (WEB_DIR / "index.html", "text/html; charset=utf-8"),
            "/index.html": (WEB_DIR / "index.html", "text/html; charset=utf-8"),
            "/emetteur": (WEB_DIR / "index.html", "text/html; charset=utf-8"),
            "/recepteur": (WEB_DIR / "index.html", "text/html; charset=utf-8"),
            "/styles.css": (WEB_DIR / "styles.css", "text/css; charset=utf-8"),
            "/app.js": (WEB_DIR / "app.js", "text/javascript; charset=utf-8"),
        }
        if self.path in routes:
            path, content_type = routes[self.path]
            try:
                content = path.read_bytes()
            except OSError:
                self.send_json(500, {"error": "Fichier d'interface introuvable"})
                return
            self.send_bytes(200, content, content_type)
            return

        if self.path == "/api/status":
            self.send_json(200, {
                "role": APP_ROLE,
                "tcpPort": TCP_PORT,
                "listenerReady": LISTENER_STATE["ready"],
                "listenerError": LISTENER_STATE["error"],
            })
            return

        if self.path == "/api/inbox" and APP_ROLE == "receiver":
            with INBOX_LOCK:
                messages = list(INBOX)
            self.send_json(200, {"messages": messages})
            return

        self.send_json(404, {"error": "Route introuvable"})

    def do_POST(self):
        if self.path == "/api/send" and APP_ROLE == "sender":
            self.send_packet()
            return
        if self.path == "/api/ack" and APP_ROLE == "receiver":
            self.acknowledge_packet()
            return
        self.send_json(404, {"error": "Route introuvable"})

    def send_packet(self):
        try:
            request = self.read_json()
            address = str(ipaddress.ip_address(request.get("ip", "")))
            packet = request.get("packet")
            if not is_valid_packet(packet):
                raise ValueError("Paquet chiffré invalide")
            payload = json.dumps(packet, separators=(",", ":")).encode("utf-8")
            if len(payload) > MAX_PACKET_SIZE:
                raise ValueError("Message trop volumineux")
        except (AttributeError, ValueError, TypeError) as error:
            self.send_json(400, {"error": str(error)})
            return

        try:
            with socket.create_connection((address, TCP_PORT), timeout=5) as connection:
                connection.sendall(payload)
            self.send_json(200, {"sent": True})
        except OSError as error:
            self.send_json(502, {"error": f"Envoi réseau impossible : {error}"})

    def acknowledge_packet(self):
        try:
            message_id = self.read_json().get("id")
        except (AttributeError, ValueError) as error:
            self.send_json(400, {"error": str(error)})
            return

        with INBOX_LOCK:
            original_size = len(INBOX)
            INBOX[:] = [message for message in INBOX if message["id"] != message_id]
            removed = len(INBOX) != original_size
        self.send_json(200, {"removed": removed})


class LocalHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def lan_address():
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.connect(("192.0.2.1", 80))
        return probe.getsockname()[0]
    except OSError:
        return "adresse locale introuvable"
    finally:
        probe.close()


def main():
    global APP_ROLE, TCP_PORT
    parser = argparse.ArgumentParser(description="Interface web locale pour la messagerie chiffrée")
    parser.add_argument("--role", choices=("sender", "receiver"), default="sender")
    parser.add_argument("--port", type=int, default=8765, help="Port de l'interface web locale")
    parser.add_argument("--tcp-port", type=int, default=5000, help="Port TCP entre les deux PC")
    parser.add_argument("--no-browser", action="store_true", help="Ne pas ouvrir le navigateur automatiquement")
    args = parser.parse_args()
    APP_ROLE = args.role
    TCP_PORT = args.tcp_port

    if APP_ROLE == "receiver":
        threading.Thread(target=receive_loop, name="encrypted-inbox", daemon=True).start()

    server = LocalHTTPServer(("127.0.0.1", args.port), RequestHandler)
    print(f"Interface {APP_ROLE} : http://127.0.0.1:{args.port}")
    if APP_ROLE == "receiver":
        print(f"Réception chiffrée sur le port TCP {TCP_PORT} de ce PC.")
        print(f"Adresse réseau à saisir sur l'émetteur : {lan_address()}")

    if not args.no_browser:
        threading.Timer(0.6, lambda: __import__("webbrowser").open(
            f"http://127.0.0.1:{args.port}"
        )).start()

    try:
        server.serve_forever(poll_interval=0.25)
    except KeyboardInterrupt:
        print("\nArrêt du serveur.")
    finally:
        STOP_EVENT.set()
        server.server_close()


if __name__ == "__main__":
    main()