from fastapi import APIRouter
from .key_manager import KeyManager
from cryptography.hazmat.primitives import serialization
import base64

router = APIRouter()
key_manager = KeyManager()

def pem_to_jwk(public_pem: str, kid: str):
    pub_key = serialization.load_pem_public_key(public_pem.encode('utf-8'))
    raw_bytes = pub_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    x = base64.urlsafe_b64encode(raw_bytes).decode('utf-8').rstrip('=')
    
    return {
        "kty": "OKP",
        "crv": "Ed25519",
        "x": x,
        "kid": kid,
        "alg": "EdDSA",
        "use": "sig"
    }

@router.get("/.well-known/jwks.json", tags=["JWKS"])
async def get_jwks():
    jwks_keys = []
    for entry in key_manager.get_all_public_keys():
        for k in key_manager.keys:
            if k["kid"] == entry["kid"]:
                jwk = pem_to_jwk(k["public_pem"], k["kid"])
                jwks_keys.append(jwk)
                break
    return {"keys": jwks_keys}