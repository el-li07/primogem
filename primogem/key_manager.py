import json
import logging
from datetime import datetime, timedelta
from pathlib import Path
import uuid
import os

from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from .config import settings

logger = logging.getLogger(__name__)

KEYS_DIR = Path(settings.BASE_PATH) / "keys"
ACTIVE_FILE = KEYS_DIR / "active_keys.json"
ARCHIVE_DIR = KEYS_DIR / "archive"

KEYS_DIR.mkdir(parents=True, exist_ok=True)
ARCHIVE_DIR.mkdir(parents=True, exist_ok=True)


class KeyManager:
    def __init__(self, encryption_password: str | None = None):
        if encryption_password is not None:
            self.encryption_key = self._derive_encryption_key(encryption_password)
        else:
            self.encryption_key = self._derive_encryption_key(os.getenv("KEY_ENCRYPTION_PASSWORD"))
        
        self.rotation_days = settings.KEY_ROTATION_DAYS
        self.retention_days = settings.KEY_ARCHIVE_RETENTION_DAYS
        
        self.keys = self._load_keys()

    def _derive_encryption_key(self, password: str | None):
        if not password:
            return None

        kdf = Scrypt(
            salt=b'primogem-secure-salt-2026',
            length=32,
            n=2**14,
            r=8,
            p=1
        )
        return kdf.derive(password.encode('utf-8'))

    def _load_keys(self):
        if ACTIVE_FILE.exists():
            with open(ACTIVE_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        return []

    def _save_keys(self):
        with open(ACTIVE_FILE, "w", encoding="utf-8") as f:
            json.dump(self.keys, f, indent=2, ensure_ascii=False)

    def _archive_old_key(self, old_key: dict):
        date_str = datetime.now().strftime("%Y-%m-%d_%H-%M")
        archive_name = f"{old_key['kid']}_{date_str}.pem"
        archive_path = ARCHIVE_DIR / archive_name
        with open(archive_path, "w", encoding="utf-8") as f:
            f.write(old_key["private_pem"])
        logger.info(f"Старый ключ заархивирован: {archive_name}")

    def generate_new_key(self):
        private_key = ed25519.Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        kid = f"primogem-{datetime.now().strftime('%Y-%m-%d')}-{uuid.uuid4().hex[:8]}"

        if self.encryption_key:
            private_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.BestAvailableEncryption(self.encryption_key)
            ).decode("utf-8")
            encrypted = True
            status = "Зашифрован"
        else:
            private_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ).decode("utf-8")
            encrypted = False
            status = "НЕ ЗАШИФРОВАН"

        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode("utf-8")

        new_key = {
            "kid": kid,
            "private_pem": private_pem,
            "public_pem": public_pem,
            "created_at": datetime.now().isoformat(),
            "is_current": True,
            "encrypted": encrypted
        }

        for k in self.keys:
            if k.get("is_current"):
                self._archive_old_key(k)
                k["is_current"] = False

        self.keys.append(new_key)
        self._save_keys()

        logger.info(f"Создан новый ключ: {kid} ({status})")
        return new_key

    def rotate(self):
        logger.info("Принудительная ротация приватного ключа...")
        self.generate_new_key()
        self._cleanup_archive()

    def check_and_rotate_if_needed(self):
        if not self.keys:
            self.generate_new_key()
            return

        current = next((k for k in self.keys if k.get("is_current")), None)
        if not current:
            self.generate_new_key()
            return

        created = datetime.fromisoformat(current["created_at"])
        days_passed = (datetime.now() - created).days

        if days_passed >= self.rotation_days:
            logger.info(f"Прошло {days_passed} дней. Автоматическая ротация")
            self.generate_new_key()
            self._cleanup_archive()
        else:
            logger.debug(f"Ключ актуален (осталось {self.rotation_days - days_passed} дней)")

    def get_current_private_key(self):
        for k in self.keys:
            if k.get("is_current"):
                if k.get("encrypted") and self.encryption_key:
                    return serialization.load_pem_private_key(
                        k["private_pem"].encode("utf-8"),
                        password=self.encryption_key
                    )
                else:
                    return serialization.load_pem_private_key(
                        k["private_pem"].encode("utf-8"),
                        password=None
                    )
        logger.warning("Ключей не найдено. Создаём новый...")
        new_key = self.generate_new_key()
        return serialization.load_pem_private_key(
            new_key["private_pem"].encode("utf-8"),
            password=self.encryption_key if new_key.get("encrypted") else None
        )

    def get_all_public_keys(self):
        result = []
        for k in self.keys:
            pub_key = serialization.load_pem_public_key(k["public_pem"].encode("utf-8"))
            result.append({"kid": k["kid"], "key": pub_key})
        return result

    def _cleanup_archive(self):
        """Очистка старых ключей из архива"""
        cutoff = datetime.now() - timedelta(days=self.retention_days)
        deleted = 0
        for file in ARCHIVE_DIR.glob("*.pem"):
            try:
                if datetime.fromtimestamp(file.stat().st_mtime) < cutoff:
                    file.unlink()
                    deleted += 1
            except:
                pass
        if deleted:
            logger.info(f"Очищено {deleted} старых ключей из архива")

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    km = KeyManager()
    km.rotate()