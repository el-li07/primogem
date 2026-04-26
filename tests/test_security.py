import pytest
import jwt
import time
import base64
from primogem.key_manager import KeyManager
from primogem.verifier import TokenVerifier

@pytest.fixture
def key_manager():
    return KeyManager()

@pytest.fixture
def verifier(key_manager):
    v = TokenVerifier()
    v.key_manager = key_manager
    return v

@pytest.fixture
def private_key(key_manager):
    return key_manager.get_current_private_key()

@pytest.fixture
def public_key(key_manager):
    all_keys = key_manager.get_all_public_keys()
    return all_keys[-1]['key'] if all_keys else None

def test_none_algorithm_attack(verifier):
    """None Algorithm"""
    header = base64.urlsafe_b64encode(b'{"alg": "none", "typ": "JWT"}').decode().rstrip("=")
    payload = base64.urlsafe_b64encode(b'{"sub": "user-hacker"}').decode().rstrip("=")
    malicious_token = f"{header}.{payload}."
    
    with pytest.raises(Exception): 
        verifier.verify(malicious_token)

def test_algorithm_substitution(verifier, public_key):
    """Подмена алгоритма"""
    payload = {"sub": "user-hacker"}
    
    try:
        from cryptography.hazmat.primitives import serialization
        pub_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        malicious_token = jwt.encode(payload, pub_bytes, algorithm="HS256")
        
        with pytest.raises(Exception):
            verifier.verify(malicious_token)
    except (TypeError, ValueError, Exception):
        pass


def test_time_manipulation(verifier, private_key):
    """Манипуляция временем"""
    current_time = int(time.time())
    
    # Токен истёк
    t_exp = jwt.encode({"sub": "t", "exp": current_time - 3600}, private_key, algorithm="EdDSA")
    with pytest.raises(Exception):
        verifier.verify(t_exp)
        
    # Время использования еще не наступило
    t_nbf = jwt.encode({"sub": "t", "nbf": current_time + 3600}, private_key, algorithm="EdDSA")
    with pytest.raises(Exception):
        verifier.verify(t_nbf)
        
    # Выпущен в будущем
    t_iat = jwt.encode({"sub": "t", "iat": current_time + 3600}, private_key, algorithm="EdDSA")
    with pytest.raises(Exception):
        verifier.verify(t_iat)


def test_invalid_issuer_and_audience(verifier, private_key):
    """Проверка iss и aud"""
    t_iss = jwt.encode({"sub": "t", "iss": "evil-auth.com"}, private_key, algorithm="EdDSA")
    with pytest.raises(Exception):
        verifier.verify(t_iss)
        
    t_aud = jwt.encode({"sub": "t", "aud": "another-service"}, private_key, algorithm="EdDSA")
    with pytest.raises(Exception):
        verifier.verify(t_aud)


def test_structural_anomalies(verifier, private_key):
    """Структурные аномалии и DoS"""

    valid_token = jwt.encode({"sub": "test"}, private_key, algorithm="EdDSA")
    with pytest.raises(Exception):
        verifier.verify(valid_token + ".extra_segment")

    huge_payload = {"sub": "A" * 100000}
    huge_token = jwt.encode(huge_payload, private_key, algorithm="EdDSA")
    try:
        verifier.verify(huge_token)
    except Exception:
        pass

    injection_payload = {"sub": "admin' OR '1'='1", "roles": ["<script>alert(1)</script>"]}
    injection_token = jwt.encode(injection_payload, private_key, algorithm="EdDSA")
    try:
        verifier.verify(injection_token)
    except Exception:
        pass