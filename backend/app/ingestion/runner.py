import asyncio
import logging
from datetime import UTC, datetime, timedelta

from app.config import Settings
from app.ingestion.gharchive import download_hour
from app.services.github import GitHubClient
from app.services.osv import OsvClient
from app.services.snowflake import SnowflakeRepository

logger = logging.getLogger(__name__)


async def ingest_gharchive(
    settings: Settings, repository: SnowflakeRepository, lookback_hours: int
) -> int:
    now = datetime.now(UTC).replace(minute=0, second=0, microsecond=0)
    total = 0
    for offset in reversed(range(1, lookback_hours + 1)):
        hour = now - timedelta(hours=offset)
        source = f"gharchive:{hour.isoformat()}"
        if repository.checkpoint_completed(source):
            continue
        rows = await download_hour(hour)
        repository.merge_gharchive_events(rows)
        repository.complete_checkpoint(source, len(rows))
        total += len(rows)
        logger.info("Loaded %s relevant events for %s", len(rows), hour.isoformat())
    return total


async def ingest_advisories(settings: Settings, repository: SnowflakeRepository) -> int:
    advisories = await GitHubClient(settings, settings.github_token).global_advisories()
    repository.merge_github_advisories(advisories)
    repository.complete_checkpoint("github_advisories", len(advisories))
    return len(advisories)


async def refresh_osv(settings: Settings, repository: SnowflakeRepository) -> int:
    packages = repository.dependency_packages(limit=1000)
    results = await OsvClient(settings).query_batch(packages)
    repository.merge_osv_results(results)
    repository.complete_checkpoint("osv_queries", len(results))
    return len(results)


async def run(sources: set[str], lookback_hours: int = 2) -> dict[str, int]:
    settings = Settings()
    settings.require_snowflake()
    repository = SnowflakeRepository(settings)
    counts: dict[str, int] = {}
    if "all" in sources or "gharchive" in sources:
        counts["gharchive"] = await ingest_gharchive(settings, repository, lookback_hours)
    if "all" in sources or "advisories" in sources:
        counts["advisories"] = await ingest_advisories(settings, repository)
    if "all" in sources or "osv" in sources:
        counts["osv"] = await refresh_osv(settings, repository)
    counts["dependency_exposures"] = repository.refresh_dependency_exposures()
    repository.refresh_risk_scores()
    return counts


def run_sync(sources: set[str], lookback_hours: int = 2) -> dict[str, int]:
    return asyncio.run(run(sources, lookback_hours))
