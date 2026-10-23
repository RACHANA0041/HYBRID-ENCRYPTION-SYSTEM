from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from key_manager import RSAKeyManager
from orchestrator import HybridSecurityOrchestrator

app = FastAPI(title="Cryptographic Hybrid Encryption System API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

key_manager = RSAKeyManager()
orchestrator = HybridSecurityOrchestrator()

server_private_key, server_public_key = key_manager.generate_keypair()

class EncryptRequest(BaseModel):
    message: str

class DecryptRequest(BaseModel):
    package_json: str

@app.get("/api/keys/public")
def get_public_key():
    pem = key_manager.export_public_key_pem(server_public_key)
    return {"public_key": pem}

@app.post("/api/encrypt")
def encrypt_message(req: EncryptRequest):
    try:
        plaintext = req.message.encode("utf-8")
        package = orchestrator.encrypt_and_package(plaintext, server_public_key)
        return {"status": "success", "package_json": package}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/api/decrypt")
def decrypt_message(req: DecryptRequest):
    try:
        decrypted_bytes = orchestrator.decrypt_and_verify(req.package_json, server_private_key)
        return {"status": "success", "decrypted_message": decrypted_bytes.decode("utf-8")}
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Decryption failed: {type(e).__name__} - {str(e)}")
