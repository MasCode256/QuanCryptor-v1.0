from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa, padding

import os, bcrypt, json, codecs, base64


def password_to_key(password: str, salt: bytes, iterations: int = 100000) -> bytes:
    # Создаем KDF (Key Derivation Function) с использованием PBKDF2HMAC
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # Длина ключа (32 байта для AES-256)
        salt=salt,
        iterations=iterations,
        backend=default_backend(),
    )
    # Преобразуем пароль в ключ
    key = kdf.derive(password.encode())
    return key


def hash_password(password: str) -> bytes:
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode("utf-8"), salt)
    return hashed


def check_password(password: str, hashed: bytes) -> bool:
    return bcrypt.checkpw(password.encode("utf-8"), hashed)


def sha256(data: bytes) -> str:
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(data)
    return digest.finalize().hex()


def generate_key():
    return Fernet.generate_key()


def encrypt_message(key, message):
    fernet = Fernet(key)
    encrypted_message = fernet.encrypt(message.encode())
    return encrypted_message


def decrypt_message(key, encrypted_message):
    fernet = Fernet(key)
    decrypted_message = fernet.decrypt(encrypted_message).decode()
    return decrypted_message


def assymetric_encrypt_message(public_key, message: str):
    key = generate_key()
    encrypted_key = public_key.encrypt(
        key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    encrypted_message = encrypt_message(key, message)

    """ return (
        "{'key':'"
        + encrypted_key.hex()
        + "','msg':'"
        + encrypted_message.decode()
        + "'}"
    ) """

    return json.dumps({"key": encrypted_key.hex(), "msg": encrypted_message.decode()})


def assymetric_decrypt_message(private_key, encrypted_data: str):
    message = json.loads(encrypted_data)

    key = private_key.decrypt(
        codecs.decode(message["key"], "hex"),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    return decrypt_message(key, message["msg"])


""" def assymetric_encrypt_message(public_key, message: str):
    key = generate_key()
    encrypted_key = public_key.encrypt(
        key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    encrypted_message = encrypt_message(key, message)

    return json.dumps(
        {
            "key": base64.urlsafe_b64encode(encrypted_key).decode("utf-8"),
            "msg": base64.urlsafe_b64encode(encrypted_message).decode("utf-8"),
        }
    )


def assymetric_decrypt_message(private_key, encrypted_data):
    message = json.loads(encrypted_data)

    key = private_key.decrypt(
        base64.urlsafe_b64decode(message["key"]),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    return decrypt_message(key, base64.urlsafe_b64decode(message["msg"])) """


def decode_public_key(encoded_public_key: bytes):
    print(f"[DEBUG] Decoding {encoded_public_key.decode().encode()}...")
    return serialization.load_pem_public_key(
        encoded_public_key, backend=default_backend()
    )
