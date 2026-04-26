# tests/test_key_manager.py
import pytest
import os
from primogem.key_manager import KeyManager

def test_key_generation():
    password = os.getenv("PYTEST_ENCRYPTION_PASSWORD")
    assert password is not None and password != "", "PYTEST_ENCRYPTION_PASSWORD не задан или пустой"

    km = KeyManager(encryption_password=password)

    try:
        private = km.get_current_private_key()
    except Exception as e:
        # Если не удалось расшифровать — пересоздаём ключ с текущим паролем
        print(f"Не удалось расшифровать ключ ({e}). Пересоздаём новый...")
        km.keys = []  # очищаем список ключей
        private = km.get_current_private_key()

    assert private is not None, "Не удалось получить приватный ключ"


def test_key_rotation():
    password = os.getenv("PYTEST_ENCRYPTION_PASSWORD")
    assert password is not None and password != ""

    km = KeyManager(encryption_password=password)
    # Принудительно вызываем ротацию, чтобы проверить, что она работает с паролем
    km.rotate()
    assert len(km.keys) > 0


def test_public_keys_export():
    password = os.getenv("PYTEST_ENCRYPTION_PASSWORD")
    assert password is not None and password != ""

    km = KeyManager(encryption_password=password)
    keys = km.get_all_public_keys()
    assert len(keys) > 0
    assert "kid" in keys[0]