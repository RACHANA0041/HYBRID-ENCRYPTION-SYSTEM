import sys
import os
import json
import pytest

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../backend')))

from key_manager import RSAKeyManager
from orchestrator import HybridSecurityOrchestrator

def test_full_hybrid_pipeline():
    key_manager = RSAKeyManager()
    orchestrator = HybridSecurityOrchestrator()

    priv_key, pub_key = key_manager.generate_keypair()
    message = b"Secret PGP Secure Message Payload"

    package = orchestrator.encrypt_and_package(message, pub_key)
    decrypted = orchestrator.decrypt_and_verify(package, priv_key)

    assert decrypted == message

def test_tampered_ciphertext_detection():
    key_manager = RSAKeyManager()
    orchestrator = HybridSecurityOrchestrator()

    priv_key, pub_key = key_manager.generate_keypair()
    message = b"Tamper Test Payload"

    package = orchestrator.encrypt_and_package(message, pub_key)
    bundle = json.loads(package)

    ciphertext_str = bundle["ciphertext"]
    bundle["ciphertext"] = ciphertext_str[:-4] + "AAAA"

    with pytest.raises(Exception):
        orchestrator.decrypt_and_verify(json.dumps(bundle), priv_key)
