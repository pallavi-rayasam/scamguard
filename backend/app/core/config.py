"""Application configuration from environment variables."""
from dataclasses import dataclass
import os
from dotenv import load_dotenv

load_dotenv()


@dataclass(frozen=True)
class Settings:
    app_env: str = os.getenv("APP_ENV", "development")
    secret_key: str = os.getenv("APP_SECRET_KEY", "")
    cookie_secure: bool = os.getenv("COOKIE_SECURE", "false").lower() == "true"
    database_url: str = os.getenv(
        "DATABASE_URL",
        "sqlite:///./local.db" if os.getenv("APP_ENV", "development") == "development"
        else "postgresql+psycopg://scamguard:replace-me@localhost:5432/scamguard",
    )
    frontend_origin: str = os.getenv("FRONTEND_ORIGIN", "http://localhost:5173")
    url_scanner_url: str = os.getenv("URL_SCANNER_URL", "")
    llm_provider: str = os.getenv("LLM_PROVIDER", "openai").lower()
    openai_api_key: str = os.getenv("OPENAI_API_KEY", "")
    openai_model: str = os.getenv("OPENAI_MODEL", "gpt-6-luna")
    google_safe_browsing_key: str = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", "")
    virustotal_api_key: str = os.getenv("VIRUSTOTAL_API_KEY", "")


settings = Settings()
