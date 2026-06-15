import os
import base64

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet


def hash_master_password(password: str, salt: bytes) -> bytes:
    """
    Creates deterministic hash for verifying master password login
    (NOT used for encryption)
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390_000
    )

    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

#===========================
# Key derivation (MASTER PASWORD)
#===========================

def derive_key(master_password: str, salt: bytes) -> bytes:
    """
    Derive encryption key from master password + salt
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390_000,
    )

    key = kdf.derive(master_password.encode())
    return base64.urlsafe_b64encode(key)

#===========================
# Encryption
#===========================

def encrypt(data: str, key: bytes) -> bytes:
    f = Fernet(key)
    return f.encrypt(data.encode())


#===========================
# Decryption
#===========================

def decrypt(token: bytes, key: bytes) -> str:
    f = Fernet(key)
    return f.decrypt(token).decode()


#===========================
# Salt utilities
#===========================

def generate_salt() -> bytes:
    return os.urandom(16)