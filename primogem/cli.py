import sys
import argparse
import getpass
import json
from pathlib import Path
import bcrypt
import os
from datetime import datetime, timedelta, timezone

from .database import init_db, get_db, User, hash_password
from .key_manager import KeyManager

CONFIG_DIR = Path(".primogem")
CONFIG_FILE = CONFIG_DIR / "config.json"
ENV_FILE = Path(".env")

def load_config():
    if CONFIG_FILE.exists():
        with open(CONFIG_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    return None


def verify_master_password(entered_password: str) -> bool:
    config = load_config()
    if not config or "master_password_hash" not in config:
        return False
    return bcrypt.checkpw(
        entered_password.encode('utf-8'),
        config["master_password_hash"].encode('utf-8')
    )


def update_env_file(key: str, value: str):
    """Обновляет или добавляет значение в файле .env"""
    lines = []
    if ENV_FILE.exists():
        lines = ENV_FILE.read_text(encoding="utf-8").splitlines()

    found = False
    new_line = f"{key}={value}"
    for i, line in enumerate(lines):
        if line.startswith(f"{key}="):
            lines[i] = new_line
            found = True
            break
    
    if not found:
        lines.append(new_line)
    
    ENV_FILE.write_text("\n".join(lines) + "\n", encoding="utf-8")


def setup_system():
    """Первичная настройка системы"""
    print("Первичная настройка Primogem Auth System")
    print("=" * 65)

    CONFIG_DIR.mkdir(exist_ok=True)

    if CONFIG_FILE.exists():
        print("Система уже настроена.")
        print("Для повторной настройки удалите папку .primogem")
        return

    org_name = input("Название организации: ").strip() or "Моя Компания"

    default_path = os.getcwd()
    base_path = input(f"Введите путь для хранения ключей и БД (по умолчанию {default_path}): ").strip()
    
    if not base_path:
        base_path = default_path
    
    Path(base_path).mkdir(parents=True, exist_ok=True)
    update_env_file("BASE_PATH", base_path)

    while True:
        master_pass = getpass.getpass("Введите мастер-пароль (минимум 12 символов): ")
        if len(master_pass) < 12:
            print("Пароль слишком короткий.")
            continue
        confirm = getpass.getpass("Подтвердите мастер-пароль: ")
        if master_pass != confirm:
            print("Пароли не совпадают.")
            continue
        break

    hashed = bcrypt.hashpw(master_pass.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    config = {
        "organization_name": org_name,
        "master_password_hash": hashed,
        "setup_completed": True,
        "created_at": datetime.now().isoformat()
    }

    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2, ensure_ascii=False)

    print("\nНастройка завершена!")
    print(f"   Организация : {org_name}")
    print(f"   Путь установлен: {base_path}")
    print("   Мастер-пароль установлен и защищён.")


def create_user(args):
    db = next(get_db())
    if db.query(User).filter(User.username == args.username).first():
        print(f"Пользователь '{args.username}' уже существует.")
        return

    new_user = User(
        username=args.username,
        hashed_password=hash_password(args.password),
        sub=f"user-{args.username}",
        full_name=args.full_name,
        department=args.department,
        roles=args.roles,
        scopes=args.scopes
    )

    db.add(new_user)
    db.commit()
    print(f"Пользователь '{args.username}' создан!")


def run_server(args):
    print("Primogem Auth Server")
    password = getpass.getpass("Введите мастер-пароль: ")

    if not verify_master_password(password):
        print("Неверный мастер-пароль.")
        return

    import os
    os.environ["KEY_ENCRYPTION_PASSWORD"] = password

    print("Запускаем сервер...")
    import subprocess
    try:
        subprocess.run(["uvicorn", "primogem.auth_server:app", "--reload"], check=True)
    except KeyboardInterrupt:
        print("\nСервер остановлен.")
    except Exception as e:
        print(f"Ошибка: {e}")


def rotate_key(args):
    """Принудительная ротация ключа"""
    print("Принудительная ротация приватного ключа")

    password = getpass.getpass("Введите мастер-пароль: ")

    if not verify_master_password(password):
        print("Неверный мастер-пароль.")
        return

    import os
    os.environ["KEY_ENCRYPTION_PASSWORD"] = password

    km = KeyManager()
    km.rotate()
    km._cleanup_archive()


def config_system(args):
    """Обновляет сроки жизни ключей"""
    updates = False
    if args.rotation:
        update_env_file("KEY_ROTATION_DAYS", str(args.rotation))
        print(f"Период ротации изменен на {args.rotation} дн.")
        updates = True
    if args.retention:
        update_env_file("KEY_ARCHIVE_RETENTION_DAYS", str(args.retention))
        print(f"Срок хранения архива изменен на {args.retention} дн.")
        updates = True

    if not updates:
        print("Укажите параметры для изменения. Например: --rotation 45")


def main():
    parser = argparse.ArgumentParser(description="Primogem CLI")
    subparsers = parser.add_subparsers(dest="command", help="Команды")

    subparsers.add_parser("setup", help="Первичная настройка системы (мастер-пароль)")

    conf = subparsers.add_parser("config", help="Изменить сроки жизни ключей")
    conf.add_argument("--rotation", type=int, help="Дней до ротации ключа")
    conf.add_argument("--retention", type=int, help="Дней хранения ключей в архиве")

    path_cmd = subparsers.add_parser("set-path", help="Изменить путь хранения данных")
    path_cmd.add_argument("path", help="Новый путь")

    create = subparsers.add_parser("create-user", help="Создать пользователя")
    create.add_argument("username")
    create.add_argument("password")
    create.add_argument("full_name")
    create.add_argument("department")
    create.add_argument("--roles", default="employee")
    create.add_argument("--scopes", default="files:read")

    subparsers.add_parser("run-server", help="Запустить сервер")
    subparsers.add_parser("rotate-key", help="Принудительно обновить ключ")

    args = parser.parse_args()

    init_db()

    if args.command == "setup":
        setup_system()
    elif args.command == "set-path":
        update_env_file("BASE_PATH", args.path)
        print(f"BASE_PATH обновлен на: {args.path}. Перезапустите сервер.")
    elif args.command == "config":
        config_system(args)
    elif args.command == "create-user":
        create_user(args)
    elif args.command == "run-server":
        run_server(args)
    elif args.command == "rotate-key":
        rotate_key(args)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
