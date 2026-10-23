# PGP-Inspired Cryptographic Hybrid Encryption System

A real-world secure message and email communication system combining symmetric and asymmetric cryptography with strong cryptographic integrity.

## Cryptographic Stack
- **AES-256-GCM**: Fast, secure symmetric encryption for message payloads.
- **RSA-2048-OAEP**: Asymmetric protection for the AES session key using SHA-512 padding.
- **SHA-512 Digest Engine**: Generates and verifies cryptographic digests to ensure data integrity and detect tampering.

## System Architecture
- **Backend**: FastAPI Python server running modular cryptographic engines (`key_manager.py`, `cipher_engine.py`, `digest_engine.py`, `orchestrator.py`).
- **Frontend**: Interactive web dashboard (`index.html`, `style.css`, `script.js`) for encrypting messages, viewing JSON packages, and testing tampering attacks.
