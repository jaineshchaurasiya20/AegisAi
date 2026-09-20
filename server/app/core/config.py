"""
AegisAI Core Configuration
Loads settings from config.yaml and environment variables.
"""
import os
import yaml
from pathlib import Path
from pydantic_settings import BaseSettings
from functools import lru_cache
from dotenv import load_dotenv

from app.core.path_utils import get_resource_path

# Load environment variables from .env and server/.env
load_dotenv(dotenv_path=Path(get_resource_path(".env")))
load_dotenv(dotenv_path=Path(get_resource_path("server/.env")))
load_dotenv()

CONFIG_PATH = Path(get_resource_path("server/config.yaml"))
if not CONFIG_PATH.exists():
    CONFIG_PATH = Path(get_resource_path("config.yaml"))
if not CONFIG_PATH.exists():
    CONFIG_PATH = Path(__file__).resolve().parents[2] / "config.yaml"


def _load_yaml() -> dict:
    if CONFIG_PATH.exists():
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            return yaml.safe_load(f) or {}
    return {}


_yaml = _load_yaml()


class Settings(BaseSettings):
    # Server
    HOST: str = _yaml.get("server", {}).get("host", "0.0.0.0")
    PORT: int = _yaml.get("server", {}).get("port", 8000)
    DEBUG: bool = _yaml.get("server", {}).get("debug", True)

    # Security
    SECRET_KEY: str = _yaml.get("security", {}).get("secret_key", "change-me")
    ALGORITHM: str = _yaml.get("security", {}).get("algorithm", "HS256")
    ACCESS_TOKEN_EXPIRE_MINUTES: int = _yaml.get("security", {}).get("access_token_expire_minutes", 60)
    QUORUM_SECRET: str | None = _yaml.get("security", {}).get("quorum_secret", os.getenv("AEGISAI_QUORUM_SECRET") or os.getenv("AegisAI_QUORUM_SECRET"))
    QUORUM_TOKEN_LIFETIME: float = float(_yaml.get("security", {}).get("quorum_token_lifetime", 30.0))
    PCTA_STRICT_MODE: bool = bool(_yaml.get("security", {}).get("pcta_strict_mode", True))
    EPHEMERAL_WIPE_INTERVAL: int = int(_yaml.get("security", {}).get("ephemeral_wipe_interval", 60))

    # Database
    DATABASE_URL: str = _yaml.get("database", {}).get("sqlite_url", "sqlite+aiosqlite:///./aegisai.db")

    # ML
    THREAT_SCORE_THRESHOLD: float = _yaml.get("ml", {}).get("threat_score_threshold", 0.65)
    ANOMALY_CONTAMINATION: float = _yaml.get("ml", {}).get("anomaly_contamination", 0.05)

    # Monitoring
    HOST_POLL_INTERVAL: int = _yaml.get("monitoring", {}).get("host_poll_interval", 2)
    RAM_PAUSE_THRESHOLD: int = _yaml.get("monitoring", {}).get("ram_pause_threshold", 85)

    # Containment safety guardrails
    AUTO_KILL_ENABLED: bool = _yaml.get("containment", {}).get("auto_kill_enabled", False)
    AUTO_ISOLATE_NETWORK: bool = _yaml.get("containment", {}).get("auto_isolate_network", False)
    CRITICAL_ACTION_THRESHOLD: float = _yaml.get("containment", {}).get("critical_action_threshold", 0.90)

    # 4-Agent Architecture Configuration
    AGENT_BASE_THRESHOLD: float = _yaml.get("agents", {}).get("base_threshold", 0.65)
    AGENT_MIN_THRESHOLD: float = _yaml.get("agents", {}).get("min_threshold", 0.50)
    AGENT_MAX_THRESHOLD: float = _yaml.get("agents", {}).get("max_threshold", 0.88)
    AGENT_LOAD_FACTOR: float = _yaml.get("agents", {}).get("load_factor", 0.20)
    AGENT_SAMPLING_INTERVAL: float = _yaml.get("agents", {}).get("sampling_interval", 1.0)
    AGENT_AUDIT_DELAY: float = _yaml.get("agents", {}).get("audit_delay", 0.5)
    AGENT_MAX_FALLBACK_ATTEMPTS: int = _yaml.get("agents", {}).get("max_fallback_attempts", 1)
    PROTECTED_PROCESSES: list[str] = _yaml.get("agents", {}).get("protected_processes", [
        "python.exe", "pythonw.exe", "uvicorn.exe", "explorer.exe",
        "system", "system idle process", "csrss.exe", "smss.exe",
        "wininit.exe", "services.exe", "lsass.exe", "svchost.exe",
        "aegisai.exe"
    ])

    # AWS S3 Immutable Vault & KMS Settings
    AWS_REGION: str = _yaml.get("aws", {}).get("region", os.getenv("AWS_REGION") or os.getenv("AWS_DEFAULT_REGION") or "us-east-1")
    AWS_S3_BUCKET_NAME: str = _yaml.get("aws", {}).get("s3_bucket_name", os.getenv("AWS_S3_BUCKET_NAME") or "aegisai-immutable-audit-vault")
    AWS_KMS_KEY_ID: str | None = _yaml.get("aws", {}).get("kms_key_id", os.getenv("AWS_KMS_KEY_ID"))
    AWS_OBJECT_LOCK_RETENTION_DAYS: int = int(_yaml.get("aws", {}).get("object_lock_retention_days", os.getenv("AWS_OBJECT_LOCK_RETENTION_DAYS") or 7))
    AWS_VAULT_ENABLED: bool = bool(_yaml.get("aws", {}).get("vault_enabled", True))

    # AWS EventBridge Fleet Intelligence Settings
    AWS_EVENTBRIDGE_ENABLED: bool = bool(_yaml.get("aws", {}).get("eventbridge_enabled", os.getenv("AWS_EVENTBRIDGE_ENABLED", "true").lower() in ("1", "true", "yes")))
    AWS_EVENTBRIDGE_BUS_NAME: str = _yaml.get("aws", {}).get("eventbridge_bus_name", os.getenv("AWS_EVENTBRIDGE_BUS_NAME") or "default")

    class Config:
        env_file = ".env"
        extra = "ignore"


@lru_cache
def get_settings() -> Settings:
    return Settings()
