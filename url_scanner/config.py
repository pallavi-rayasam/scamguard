"""Configuration for the isolated URL scanner process."""
import os

from dotenv import load_dotenv

load_dotenv()


class Settings:
    google_safe_browsing_key = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", "")
    virustotal_api_key = os.getenv("VIRUSTOTAL_API_KEY", "")
    cache_ttl_seconds = int(os.getenv("URL_SCANNER_CACHE_TTL_SECONDS", "300"))


settings = Settings()
