from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    BASE_PATH: str = "."
    DATABASE_NAME: str = "primogem.db"
    
    KEY_ROTATION_DAYS: int = 30
    KEY_ARCHIVE_RETENTION_DAYS: int = 90
    TOKEN_LIFETIME_MINUTES: int = 30

    ISSUER: str = "auth.primogem.local"
    DEFAULT_AUDIENCE: str = "company-services"

    KEY_ENCRYPTION_PASSWORD: str = ""

    CORS_ORIGINS: list[str] = ["http://localhost:3000", "http://localhost:8000"]

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        env_nested_delimiter=",", 
        extra="ignore"
    )

settings = Settings()