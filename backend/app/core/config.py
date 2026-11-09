"""Application configuration from environment variables."""
from dataclasses import dataclass
import math
from pathlib import Path
import os
from dotenv import load_dotenv

load_dotenv()


def _bounded_seconds(name: str, default: float, maximum: float) -> float:
    raw = os.getenv(name)
    if raw is None or not raw.strip():
        return default
    try:
        value = float(raw)
    except ValueError as exc:
        raise ValueError(f"{name} must be a number between 0 and {maximum} seconds") from exc
    if not math.isfinite(value) or value <= 0 or value > maximum:
        raise ValueError(f"{name} must be greater than 0 and no more than {maximum} seconds")
    return value


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
    gemini_api_key: str = os.getenv("GEMINI_API_KEY", "")
    gemini_model: str = os.getenv("GEMINI_MODEL", "gemini-3.8-flash")
    gemini_connect_timeout_seconds: float = _bounded_seconds("GEMINI_CONNECT_TIMEOUT_SECONDS", 5.0, 15.0)
    gemini_read_timeout_seconds: float = _bounded_seconds("GEMINI_READ_TIMEOUT_SECONDS", 30.0, 60.0)
    gemini_write_timeout_seconds: float = _bounded_seconds("GEMINI_WRITE_TIMEOUT_SECONDS", 10.0, 15.0)
    gemini_pool_timeout_seconds: float = _bounded_seconds("GEMINI_POOL_TIMEOUT_SECONDS", 5.0, 15.0)
    gemini_total_timeout_seconds: float = _bounded_seconds("GEMINI_TOTAL_TIMEOUT_SECONDS", 40.0, 90.0)
    groq_api_key: str = os.getenv("GROQ_API_KEY", "")
    groq_model: str = os.getenv("GROQ_MODEL", "openai/gpt-oss-20b")
    groq_connect_timeout_seconds: float = _bounded_seconds("GROQ_CONNECT_TIMEOUT_SECONDS", 5.0, 15.0)
    groq_read_timeout_seconds: float = _bounded_seconds("GROQ_READ_TIMEOUT_SECONDS", 30.0, 60.0)
    groq_write_timeout_seconds: float = _bounded_seconds("GROQ_WRITE_TIMEOUT_SECONDS", 10.0, 15.0)
    groq_pool_timeout_seconds: float = _bounded_seconds("GROQ_POOL_TIMEOUT_SECONDS", 5.0, 15.0)
    groq_total_timeout_seconds: float = _bounded_seconds("GROQ_TOTAL_TIMEOUT_SECONDS", 40.0, 90.0)
    google_safe_browsing_key: str = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", "")
    virustotal_api_key: str = os.getenv("VIRUSTOTAL_API_KEY", "")
    tesseract_cmd: str = os.getenv("TESSERACT_CMD", "")
    ml_model_enabled: bool = os.getenv("ML_MODEL_ENABLED", "true").lower() == "true"
    ml_model_version: str = os.getenv("ML_MODEL_VERSION", "message-text-v1")
    ml_model_path: str = os.getenv(
        "ML_MODEL_PATH",
        str(Path(__file__).resolve().parents[3] / "ml" / "artifacts" / "message-text-v1" / "pipeline.joblib"),
    )


settings = Settings()
