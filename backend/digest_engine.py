import hmac
from cryptography.hazmat.primitives import hashes

class SHA512DigestEngine:
    """Handles SHA-512 cryptographic digest calculation and verification."""

    @staticmethod
    def compute_hash(data: bytes) -> bytes:
        digest = hashes.Hash(hashes.SHA512())
        digest.update(data)
        return digest.finalize()

    @staticmethod
    def verify_hash(data: bytes, expected_hash: bytes) -> bool:
        computed = SHA512DigestEngine.compute_hash(data)
        return hmac.compare_digest(computed, expected_hash)
