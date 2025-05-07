from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os, bcrypt


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
