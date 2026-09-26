from functools import lru_cache

from app.config import Settings, get_settings
from app.services.snowflake import SnowflakeRepository


@lru_cache
def _snowflake_repository() -> SnowflakeRepository:
    return SnowflakeRepository(get_settings())


def settings_dependency() -> Settings:
    return get_settings()


def snowflake_dependency() -> SnowflakeRepository:
    return _snowflake_repository()
