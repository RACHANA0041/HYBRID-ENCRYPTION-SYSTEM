import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class AESCipherEngine:
    """Handles symmetric AES-256-GCM encryption and decryption."""

    @staticmethod
    def generate_key() -> bytes:
        return AESGCM.generate_key(bit_length=256)

    @staticmethod
    def encrypt(plaintext: bytes, key: bytes, associated_data: bytes = None) -> tuple[bytes, bytes]:
        nonce = os.urandom(12)
        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data)
        return nonce, ciphertext

    @staticmethod
    def decrypt(nonce: bytes, ciphertext: bytes, key: bytes, associated_data: bytes = None) -> bytes:
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, ciphertext, associated_data)
