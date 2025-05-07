import webview, os, sys, json
from datetime import datetime
from pathlib import Path


parent_directory = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.append(parent_directory + "/utils")
import crypto


class Api:
    def show_message(self, message):
        print(message)

    def show_error(selt, error):
        print(f"{datetime.now()} Frontend error: {error}")

    def list_files_in_dir(self, directory_path):
        files = os.listdir(directory_path)
        files = [f for f in files if os.path.isfile(os.path.join(directory_path, f))]
        return files

    def sha256(self, data: str):
        return crypto.sha256(data.encode())

    def check_password(self, password: str, password_hash: str):
        return crypto.check_password(password, password_hash.encode())

    def generate_key(self):
        return crypto.generate_key().decode()

    def decrypt(self, key, msg):
        return crypto.decrypt_message(key=key, encrypted_message=msg)

    def assymetric_encrypt(self, key: str, msg):
        return crypto.assymetric_encrypt_message(
            crypto.decode_public_key(key.encode()), msg
        )

    def write_to_file(self, path: str, data: str):
        try:
            with open(path, "w", encoding="utf-8") as file:
                file.write(data)
                return True
        except Exception as err:
            print(f"[ERROR] {err}")
            return False
        except:
            print(f"Failed to write to file '{path}'.")
            return False

    def is_user_has_account(self):
        print("[DEBUG](Api.is_user_has_account)", end=" ")

        FILENAME = "accounts.json"
        if not Path(FILENAME).is_file():
            print("user not have account.")
            return False
        try:
            with open(FILENAME, "r", encoding="utf-8") as file:
                data = json.load(file)

                print("user have account.")
                return True
        except Exception as e:
            print(f"[ERROR] Could not read file '{FILENAME}': {e}")
            return False


def main():
    if not os.path.isdir("./data"):
        os.mkdir("./data")
        os.mkdir("./data/servers")
        os.mkdir("./data/cache")
    else:
        if not os.path.isdir("./data/servers"):
            os.mkdir("./data/servers")
            os.mkdir("./data/cache")

    api = Api()
    window = webview.create_window(
        "QuanCryptor Client 1.25.05 WebUI", "index.html", js_api=api
    )
    webview.start(storage_path="./data/cache")


if __name__ == "__main__":
    main()
