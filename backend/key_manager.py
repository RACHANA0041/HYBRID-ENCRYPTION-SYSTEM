import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization

class RSAKeyManager:
    """Handles RSA-2048 keypair generation, export, import, and session-key protection using SHA-512 OAEP."""

    def __init__(self, key_size: int = 2048):
        self.key_size = key_size

    def generate_keypair(self):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=self.key_size
        )
        public_key = private_key.public_key()
        return private_key, public_key

    def export_private_key_pem(self, private_key) -> str:
        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        return pem.decode("utf-8")

    def export_public_key_pem(self, public_key) -> str:
        pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return pem.decode("utf-8")

    def load_private_key_pem(self, pem_str: str):
        return serialization.load_pem_private_key(
            pem_str.encode("utf-8"),
            password=None
        )

    def load_public_key_pem(self, pem_str: str):
        return serialization.load_pem_public_key(
            pem_str.encode("utf-8")
        )

    def encrypt_session_key(self, session_key: bytes, public_key) -> bytes:
        return public_key.encrypt(
            session_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA512()),
                algorithm=hashes.SHA512(),
                label=None
            )
        )

    def decrypt_session_key(self, encrypted_session_key: bytes, private_key) -> bytes:
        return private_key.decrypt(
            encrypted_session_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA512()),
                algorithm=hashes.SHA512(),
                label=None
            )
        )
