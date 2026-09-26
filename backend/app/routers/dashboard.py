from datetime import UTC, datetime, timedelta
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Query

from app import mock_data
from app.config import Settings
from app.dependencies import settings_dependency, snowflake_dependency
from app.models import DashboardOverview, FindingsPage, RepositoryRisk
from app.services.snowflake import SnowflakeRepository

router = APIRouter(prefix="/api/v1", tags=["dashboard"])
SettingsDep = Annotated[Settings, Depends(settings_dependency)]
SnowflakeDep = Annotated[SnowflakeRepository, Depends(snowflake_dependency)]
FindingsLimit = Annotated[int, Query(ge=1, le=200)]


def date_window(start: datetime | None, end: datetime | None) -> tuple[datetime, datetime]:
    window_end = end or datetime.now(UTC)
    window_start = start or window_end - timedelta(days=30)
    if window_start >= window_end:
        raise HTTPException(status_code=422, detail="start must be before end")
    return window_start, window_end


@router.get("/dashboard/overview", response_model=DashboardOverview)
def dashboard_overview(
    settings: SettingsDep,
    snowflake: SnowflakeDep,
    start: datetime | None = None,
    end: datetime | None = None,
) -> DashboardOverview:
    window_start, window_end = date_window(start, end)
    if settings.data_mode == "mock":
        return mock_data.overview()
    try:
        return snowflake.overview(window_start, window_end)
    except Exception as error:
        raise HTTPException(status_code=502, detail="Snowflake overview query failed") from error


@router.get("/findings", response_model=FindingsPage)
def list_findings(
    settings: SettingsDep,
    snowflake: SnowflakeDep,
    severity: Literal["critical", "high", "medium", "low"] | None = None,
    limit: FindingsLimit = 50,
) -> FindingsPage:
    if settings.data_mode == "mock":
        page = mock_data.findings()
        if severity:
            page.items = [item for item in page.items if item.risk_level == severity]
        page.items = page.items[:limit]
        return page
    try:
        return snowflake.findings(severity, limit)
    except Exception as error:
        raise HTTPException(status_code=502, detail="Snowflake findings query failed") from error


@router.get("/repositories/{owner}/{repo}/risk", response_model=RepositoryRisk)
def repository_risk(
    owner: str,
    repo: str,
    settings: SettingsDep,
    snowflake: SnowflakeDep,
    start: datetime | None = None,
    end: datetime | None = None,
) -> RepositoryRisk:
    window_start, window_end = date_window(start, end)
    repo_name = f"{owner}/{repo}"
    if settings.data_mode == "mock":
        return mock_data.repository_risk(repo_name, window_start, window_end)
    try:
        return snowflake.repository_risk(repo_name, window_start, window_end)
    except LookupError as error:
        raise HTTPException(status_code=404, detail=str(error)) from error
    except Exception as error:
        raise HTTPException(status_code=502, detail="Snowflake repository query failed") from error
