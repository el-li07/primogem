from fastapi import FastAPI, Depends, HTTPException, status, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer
from pydantic import BaseModel
import uvicorn
import jwt
import logging
from datetime import datetime, timedelta, timezone
import uuid
from contextlib import asynccontextmanager
from sqlalchemy.orm import Session

# Rate limiting
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

from .key_manager import KeyManager
from .config import settings
from .database import init_db, get_db, User, hash_password, verify_password
from .dependencies import get_current_user, require_scope, require_role
from .jwks import router as jwks_router

logger = logging.getLogger(__name__)

# Настройка rate limiter
limiter = Limiter(key_func=get_remote_address)

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Primogem Auth Server запускается...")
    init_db()
    key_manager.check_and_rotate_if_needed()
    yield
    logger.info("Сервер остановлен.")

def get_auth_app(cors_origins: list[str] = None) -> FastAPI:
    app = FastAPI(title="Primogem Auth Server", lifespan=lifespan)
    
    origins = cors_origins or settings.CORS_ORIGINS
    
    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    
    app.include_router(jwks_router)
    
    return app

app = get_auth_app()

key_manager = KeyManager()

class LoginRequest(BaseModel):
    username: str
    password: str


@app.post("/login")
async def login(login_data: LoginRequest, db: Session = Depends(get_db)):
    try:
        logger.info(f"Попытка логина пользователя: {login_data.username}")

        user = db.query(User).filter(
            User.username == login_data.username,
            User.is_active == True
        ).first()

        if not user:
            logger.warning(f"Пользователь {login_data.username} не найден")
            raise HTTPException(status_code=401, detail="Неверный логин или пароль")

        logger.debug("Пользователь найден, проверяем пароль...")
        if not verify_password(login_data.password, user.hashed_password):
            logger.warning(f"Неверный пароль для пользователя {login_data.username}")
            raise HTTPException(status_code=401, detail="Неверный логин или пароль")

        logger.debug("Пароль верный, создаём токен...")

        now = datetime.now(timezone.utc)
        expires = now + timedelta(minutes=settings.TOKEN_LIFETIME_MINUTES)

        payload = {
            "iss": settings.ISSUER,
            "sub": user.sub,
            "aud": "company-services",
            "iat": now,
            "exp": expires,
            "jti": str(uuid.uuid4()),
            "roles": user.roles.split(",") if user.roles else [],
            "scope": " ".join(user.scopes.split(",")) if user.scopes else ""
        }

        private_key = key_manager.get_current_private_key()
        logger.debug("Приватный ключ получен успешно")

        token = jwt.encode(
            payload,
            private_key,
            algorithm="EdDSA"
        )

        logger.info(f"Успешный вход: {login_data.username}")
        return {
            "access_token": token,
            "token_type": "Bearer",
            "expires_in": settings.TOKEN_LIFETIME_MINUTES * 60,
            "user_info": {
                "sub": user.sub,
                "username": user.username,
                "full_name": user.full_name,
                "department": user.department
            }
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Внутренняя ошибка при логине")
        raise HTTPException(status_code=500, detail=f"Internal Server Error: {type(e).__name__}")

# ====================== ЗАЩИЩЁННЫЕ ЭНДПОИНТЫ ======================
@app.get("/me")
async def get_current_user(payload: dict = Depends(require_scope("files:read"))):
    return {"user": payload}


@app.get("/files/all")
async def get_all_files(payload: dict = Depends(require_role("admin", "manager"))):
    return {"message": "Здесь будут все файлы компании"}


@app.get("/files/me")
async def get_my_files(payload: dict = Depends(require_scope("files:read"))):
    return {"message": f"Личные файлы пользователя {payload['sub']}"}


# ====================== JWKS ======================
from .jwks import router as jwks_router
app.include_router(jwks_router)