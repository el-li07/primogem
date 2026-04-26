from sqlalchemy import create_engine, Column, String, Boolean, DateTime
from sqlalchemy.orm import declarative_base, sessionmaker
from sqlalchemy.sql import func
from pathlib import Path
import bcrypt
from .config import settings

Base = declarative_base()

class User(Base):
    __tablename__ = "users"

    username = Column(String, primary_key=True, index=True)
    hashed_password = Column(String, nullable=False)
    sub = Column(String, unique=True, nullable=False)
    full_name = Column(String, nullable=False)
    department = Column(String, nullable=False)
    roles = Column(String, nullable=False)
    scopes = Column(String, nullable=False)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

db_dir = Path(settings.BASE_PATH)
db_dir.mkdir(parents=True, exist_ok=True)
DB_PATH = db_dir / settings.DATABASE_NAME

DATABASE_URL = f"sqlite:///{DB_PATH}"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def init_db():
    """Создаёт таблицы, если их ещё нет"""
    Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def hash_password(password: str) -> str:
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))