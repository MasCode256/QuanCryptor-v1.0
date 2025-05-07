import sqlite3, os.path, json, time, sys
import http.server
import socketserver
from json import JSONDecodeError

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes

parent_directory = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.append(parent_directory + "/utils")
import crypto


public_key = None
private_key = None
public_key_hash = None
external_password_hash = None
internal_password_hash = None


class MyRequestHandler(http.server.BaseHTTPRequestHandler):
    def end_headers(self):
        # Добавляем заголовок для разрешения CORS
        self.send_header("Access-Control-Allow-Origin", "*")
        # Вызовем оригинальный метод для завершения заголовков
        super().end_headers()

    def do_GET(self):
        print(f"[DEBUG] Path: {self.path}")

        if self.path == "/get_public_key":
            print("Receiving public key...")
            self.send_response(200)
            self.send_header("Content-type", "text/plain")
            self.end_headers()
            self.wfile.write(public_key)
        elif self.path == "/get_internal_password_hash":
            print("Receiving internal password hash...")
            self.send_response(200)
            self.send_header("Content-type", "text/plain")
            self.end_headers()
            self.wfile.write(internal_password_hash.encode())
        else:
            print("Error: unknown request type.")
            self.send_response(400)
            self.end_headers()

    def do_POST(self):
        print(f"[DEBUG] Path: {self.path}")

        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()

        # Отправляем ответ
        self.wfile.write(b"<html><body><h1>POST request!</h1></body></html>")


def load_conf(path: str = "settings.json", default={}):
    ret = default

    try:
        with open(path, "r") as file:
            ret = json.loads(file.read())
    except FileNotFoundError:
        with open(path, "w") as file:
            file.write(json.dumps(ret, ensure_ascii=False, sort_keys=True, indent=4))
    except JSONDecodeError:
        print(
            f"[WARNING] Cannot decode {path} (JSONDecodeError). Settings will be default."
        )
    except KeyError:
        print(f"[WARNING] Cannot decode {path} (KeyError). Settings will be default.")
    except TypeError:
        print(f"[WARNING] Cannot decode {path} (TypeError). Settings will be default.")
    except Exception:
        print(f"[WARNING] Exception in decoding {path}.")
    finally:
        return ret


def main():
    print("Loading configuration ('settings.json')...")
    settings = load_conf(
        "settings.json",
        {
            "port": 8000,
            "key_size": 4096,
            "ip": "0.0.0.0",
            "external_password": os.urandom(16).hex(),
            "internal_password": os.urandom(16).hex(),
        },
    )

    SK_PATH = "private_key.pem"

    global public_key
    global private_key
    global public_key_hash
    global external_password_hash
    global internal_password_hash

    external_password_hash = crypto.hash_password(
        settings["external_password"]
    ).decode()
    internal_password_hash = crypto.hash_password(
        settings["internal_password"]
    ).decode()

    """ print(
        f"[TEST] External password hash:",
        external_password_hash,
        crypto.check_password(
            settings["external_password"], external_password_hash.encode()
        ),
    )
    print(
        f"[TEST] Internal password hash:",
        internal_password_hash,
        crypto.check_password(
            settings["internal_password"], internal_password_hash.encode()
        ),
    ) """
    """ print(
        "[TEST]",
        crypto.check_password(
            settings["external_password"],
            crypto.hash_password(settings["external_password"]),
        ),
    ) """

    if os.path.isfile(SK_PATH):
        print(f"Loading keypair ('{SK_PATH}')...")
        with open(SK_PATH, "rb") as file:
            private_key = serialization.load_pem_private_key(
                file.read(), password=None, backend=default_backend()
            )
    else:
        print(f"Generating keypair (key size: {settings["key_size"]})...")
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=settings["key_size"],
            backend=default_backend(),
        )

        print(f"Saving keypair ('{SK_PATH}')...")
        with open(SK_PATH, "wb") as file:
            file.write(
                private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )

    print("Creating public key hash...")
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(public_key)
    public_key_hash = digest.finalize().hex()

    with socketserver.TCPServer(
        (settings["ip"], settings["port"]), MyRequestHandler
    ) as httpd:
        print(
            f"Server started on {settings["ip"]}:{settings["port"]}/{public_key_hash}"
        )
        print(
            f"External password: '{settings["external_password"]}', internal password: '{settings["internal_password"]}'."
        )

        httpd.serve_forever()


if __name__ == "__main__":
    main()
