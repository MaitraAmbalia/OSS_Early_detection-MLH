from functools import lru_cache
from typing import Annotated, Literal

from pydantic import field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    app_env: Literal["development", "test", "production"] = "development"
    data_mode: Literal["github", "snowflake"] = "github"
    cors_origins: Annotated[list[str], NoDecode] = ["http://localhost:5173"]

    snowflake_account: str | None = None
    snowflake_user: str | None = None
    snowflake_private_key_file: str | None = None
    snowflake_private_key_passphrase: str | None = None
    snowflake_role: str = "INGESTION_ROLE"
    snowflake_warehouse: str = "INGEST_WH"
    snowflake_database: str = "SUPPLY_CHAIN_MONITOR"
    snowflake_schema: str = "DETECTION"
    snowflake_persistence_enabled: bool = False

    github_api_url: str = "https://api.github.com"
    github_api_version: str = "2026-03-10"
    github_token: str | None = None
    github_webhook_secret: str | None = None
    request_timeout_seconds: float = 15.0

    @field_validator("cors_origins", mode="before")
    @classmethod
    def parse_origins(cls, value: object) -> object:
        if isinstance(value, str):
            return [origin.strip() for origin in value.split(",") if origin.strip()]
        return value

    def require_snowflake(self) -> None:
        required = {
            "SNOWFLAKE_ACCOUNT": self.snowflake_account,
            "SNOWFLAKE_USER": self.snowflake_user,
            "SNOWFLAKE_PRIVATE_KEY_FILE": self.snowflake_private_key_file,
        }
        missing = [name for name, value in required.items() if not value]
        if missing:
            raise RuntimeError(f"Missing Snowflake configuration: {', '.join(missing)}")

    @property
    def snowflake_configured(self) -> bool:
        return bool(
            self.snowflake_account
            and self.snowflake_user
            and self.snowflake_private_key_file
        )


@lru_cache
def get_settings() -> Settings:
    return Settings()
