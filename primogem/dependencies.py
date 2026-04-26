from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import jwt
from .key_manager import KeyManager

key_manager = KeyManager()
security = HTTPBearer()


def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials

    for entry in key_manager.get_all_public_keys():
        try:
            payload = jwt.decode(
                token,
                entry["key"],
                algorithms=["EdDSA"],
                issuer="auth.primogem.local",
                audience="company-services",
                options={
                    "verify_signature": True,
                    "require": ["exp", "iat", "sub", "iss", "aud", "jti"]
                }
            )
            return payload
        except jwt.InvalidSignatureError:
            continue
        except jwt.ExpiredSignatureError:
            raise HTTPException(status_code=401, detail="Токен истёк")
        except Exception:
            continue

    raise HTTPException(status_code=401, detail="Недействительный токен")


def require_scope(*required_scopes: str):
    def dependency(payload: dict = Depends(get_current_user)):
        user_scopes = payload.get("scope", "").split()
        for scope in required_scopes:
            if scope in user_scopes:
                return payload
        raise HTTPException(
            status_code=403,
            detail=f"Недостаточно прав. Требуется scope: {required_scopes}"
        )
    return dependency


def require_role(*required_roles: str):
    def dependency(payload: dict = Depends(get_current_user)):
        user_roles = payload.get("roles", [])
        for role in required_roles:
            if role in user_roles:
                return payload
        raise HTTPException(
            status_code=403,
            detail=f"Недостаточно прав. Требуется роль: {required_roles}"
        )
    return dependency