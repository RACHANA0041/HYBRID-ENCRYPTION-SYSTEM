import json
import base64
from key_manager import RSAKeyManager
from cipher_engine import AESCipherEngine
from digest_engine import SHA512DigestEngine

class HybridSecurityOrchestrator:
    """Integrates key management, symmetric cipher, and SHA-512 digest into standard JSON bundles."""

    def __init__(self):
        self.key_manager = RSAKeyManager()
        self.cipher_engine = AESCipherEngine()
        self.digest_engine = SHA512DigestEngine()

    def encrypt_and_package(self, plaintext: bytes, public_key) -> str:
        payload_digest = self.digest_engine.compute_hash(plaintext)
        session_key = self.cipher_engine.generate_key()
        nonce, ciphertext = self.cipher_engine.encrypt(plaintext, session_key)
        encrypted_session_key = self.key_manager.encrypt_session_key(session_key, public_key)

        bundle = {
            "encrypted_session_key": base64.b64encode(encrypted_session_key).decode("utf-8"),
            "nonce": base64.b64encode(nonce).decode("utf-8"),
            "ciphertext": base64.b64encode(ciphertext).decode("utf-8"),
            "digest": base64.b64encode(payload_digest).decode("utf-8")
        }
        return json.dumps(bundle, indent=2)

    def decrypt_and_verify(self, package_json: str, private_key) -> bytes:
        bundle = json.loads(package_json)

        encrypted_session_key = base64.b64decode(bundle["encrypted_session_key"])
        nonce = base64.b64decode(bundle["nonce"])
        ciphertext = base64.b64decode(bundle["ciphertext"])
        expected_digest = base64.b64decode(bundle["digest"])

        session_key = self.key_manager.decrypt_session_key(encrypted_session_key, private_key)
        decrypted_payload = self.cipher_engine.decrypt(nonce, ciphertext, session_key)

        if not self.digest_engine.verify_hash(decrypted_payload, expected_digest):
            raise ValueError("Integrity verification failed: SHA-512 digest mismatch.")

        return decrypted_payload
