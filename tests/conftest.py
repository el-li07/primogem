# tests/conftest.py
import pytest
import os
from primogem.database import init_db

@pytest.fixture(scope="session", autouse=True)
def setup_test_environment():
    """Передаёт пароль из переменной окружения в KeyManager"""
    test_password = os.getenv("PYTEST_ENCRYPTION_PASSWORD")

    if test_password is None:
        raise ValueError("Для запуска тестов необходимо задать PYTEST_ENCRYPTION_PASSWORD")

    os.environ["KEY_ENCRYPTION_PASSWORD"] = test_password

    init_db()
    yield