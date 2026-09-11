"""Environment-driven settings for the gateway."""

from __future__ import annotations

from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    env: str = Field(default="development", alias="ARGUS_ENV")
    log_level: str = Field(default="info", alias="ARGUS_LOG_LEVEL")

    database_url: str = Field(
        default="postgresql+asyncpg://argus:argus@localhost:5432/argus",
        alias="DATABASE_URL",
    )
    redis_url: str = Field(default="redis://localhost:6379/0", alias="REDIS_URL")

    jwt_secret: str = Field(default="dev-insecure-change-me", alias="JWT_SECRET")
    jwt_access_ttl_minutes: int = Field(default=30, alias="JWT_ACCESS_TTL_MINUTES")
    jwt_refresh_ttl_days: int = Field(default=14, alias="JWT_REFRESH_TTL_DAYS")
    secret_encryption_key: str = Field(default="", alias="SECRET_ENCRYPTION_KEY")

    api_host: str = Field(default="0.0.0.0", alias="ARGUS_API_HOST")  # noqa: S104
    api_port: int = Field(default=8000, alias="ARGUS_API_PORT")
    cors_origins: str = Field(default="http://localhost:3000", alias="ARGUS_CORS_ORIGINS")

    allow_setup: bool = Field(default=True, alias="ARGUS_ALLOW_SETUP")
    allow_seed: bool = Field(default=False, alias="ARGUS_ALLOW_SEED")

    orch_internal_token: str = Field(default="", alias="ORCH_INTERNAL_TOKEN")

    s3_endpoint: str = Field(default="http://localhost:9000", alias="S3_ENDPOINT")
    s3_bucket: str = Field(default="argus-artifacts", alias="S3_BUCKET")

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    @property
    def sync_database_url(self) -> str:
        """Alembic uses a sync driver (psycopg 3)."""
        if self.database_url.startswith("sqlite"):
            return self.database_url.replace("+aiosqlite", "")
        return self.database_url.replace("+asyncpg", "+psycopg").replace(
            "postgresql://", "postgresql+psycopg://"
        )


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
