# tests/test_verifier.py
import pytest
import jwt
import os
from primogem.verifier import TokenVerifier
from primogem.key_manager import KeyManager

def test_token_verifier():
    password = os.getenv("PYTEST_ENCRYPTION_PASSWORD")
    assert password is not None and password != "", "PYTEST_ENCRYPTION_PASSWORD не задан или пустой"

    # Создаём KeyManager с тем же паролем
    km = KeyManager(encryption_password=password)
    
    # Создаём верификатор и явно подменяем ему менеджер ключей
    verifier = TokenVerifier()
    verifier.key_manager = km

    # Генерируем токен с помощью этого же KeyManager
    private = km.get_current_private_key()
    payload = {
        "sub": "test-user",
        "iss": "auth.primogem.local",
        "aud": "company-services",
        "exp": 9999999999,
        "iat": 0,
        "jti": "test-jti-123"
    }

    token = jwt.encode(payload, private, algorithm="EdDSA")

    # Проверяем токен
    result = verifier.verify(token)
    assert result is not None, "Токен не прошёл проверку ни одним ключом"
    assert result["sub"] == "test-user"
    assert result.get("iss") == "auth.primogem.local"


def test_verify_token_function():
    assert callable(TokenVerifier)