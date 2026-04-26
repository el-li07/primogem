import jwt
import sys
import logging
from .key_manager import KeyManager

logger = logging.getLogger(__name__)
key_manager = KeyManager()

ISSUER = "auth.primogem.local"
DEFAULT_AUDIENCE = "company-services"


class TokenVerifier:
    """Класс для проверки JWT-токенов с подписью Ed25519"""

    def __init__(self, jwks_url: str = None):
        self.jwks_url = jwks_url
        self.key_manager = KeyManager()

    def verify(self, token: str):
        if not token:
            raise ValueError("Токен не передан")

        logger.debug("Начинаем проверку токена...")
        logger.debug(f"Длина токена: {len(token)} символов")

        keys = self.key_manager.get_all_public_keys()
        logger.debug(f"Найдено публичных ключей для проверки: {len(keys)}")

        for i, entry in enumerate(keys):
            kid = entry["kid"]
            logger.debug(f"[{i+1}/{len(keys)}] Пробуем ключ kid={kid}")

            try:
                decoded = jwt.decode(
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
                logger.info(f"Токен успешно проверен ключом {kid}")
                return decoded
            except jwt.InvalidSignatureError:
                logger.debug(f"Подпись не совпадает с ключом {kid}")
                continue
            except jwt.ExpiredSignatureError:
                logger.warning("Токен истёк")
                raise
            except Exception as e:
                logger.error(f"Ошибка при проверке ключа {kid}: {type(e).__name__} - {e}")
                continue

        logger.warning("Токен не прошёл проверку ни одним ключом")
        raise ValueError("Токен не прошёл проверку ни одним ключом")

def verify_token(token: str):
    """Упрощённая функция проверки токена"""
    verifier = TokenVerifier()
    return verifier.verify(token)


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    if len(sys.argv) > 1:
        try:
            verify_token(sys.argv[1])
        except Exception as e:
            logger.error(f"Верификация провалена: {e}")
    else:
        print("Использование: python verifier.py \"токен\"")