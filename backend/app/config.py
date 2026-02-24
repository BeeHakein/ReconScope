"""
ReconScope application configuration.

Loads settings from environment variables with sensible defaults for local
development.  Uses Pydantic BaseSettings so every value can be overridden via
an environment variable or a ``.env`` file placed next to the backend root.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Optional

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Central configuration for the ReconScope backend.

    All attributes can be overridden through environment variables of the same
    name (case-insensitive).  For example, set ``DATABASE_URL`` in the shell or
    in a ``.env`` file to change the default database connection string.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ── Application ─────────────────────────────────────────────────────────
    APP_NAME: str = "ReconScope"
    API_V1_PREFIX: str = "/api/v1"
    DEBUG: bool = False

    # ── Database ────────────────────────────────────────────────────────────
    DATABASE_URL: str = (
        "postgresql+asyncpg://reconscope:reconscope@localhost:5432/reconscope"
    )

    # ── Redis / Celery Broker ───────────────────────────────────────────────
    REDIS_URL: str = "redis://localhost:6379/0"

    # ── Security ────────────────────────────────────────────────────────────
    SECRET_KEY: str = "change-me-in-production-use-openssl-rand-hex-32"

    # ── CORS ────────────────────────────────────────────────────────────────
    CORS_ORIGINS: list[str] = ["http://localhost:3000"]

    # ── External API Keys (optional) ────────────────────────────────────────
    NVD_API_KEY: Optional[str] = None
    SHODAN_API_KEY: Optional[str] = None

    # ── Validators ──────────────────────────────────────────────────────────

    @field_validator("CORS_ORIGINS", mode="before")
    @classmethod
    def parse_cors_origins(cls, value: object) -> list[str]:
        """Accept a comma-separated string *or* an actual list."""
        if isinstance(value, str):
            return [origin.strip() for origin in value.split(",") if origin.strip()]
        return list(value)  # type: ignore[arg-type]

    @field_validator("SECRET_KEY", mode="after")
    @classmethod
    def warn_default_secret(cls, value: str) -> str:
        """Emit a warning when the default secret key is still in use."""
        if value == "change-me-in-production-use-openssl-rand-hex-32":
            import warnings
            warnings.warn(
                "SECRET_KEY is set to its default value. "
                "Generate a proper key with: openssl rand -hex 32",
                UserWarning,
                stacklevel=2,
            )
        return value


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return a cached singleton of the application settings.

    Using ``lru_cache`` ensures the ``.env`` file is read only once and the
    same ``Settings`` instance is reused across the entire process.
    """
    return Settings()
