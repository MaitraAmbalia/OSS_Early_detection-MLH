from datetime import UTC, datetime, timedelta
from typing import Annotated

from fastapi import APIRouter, Depends, Header, HTTPException

from app import mock_data
from app.config import Settings
from app.dependencies import settings_dependency, snowflake_dependency
from app.models import GitHubIdentity, RepositoryAnalysis
from app.services.github import GitHubApiError, GitHubClient
from app.services.snowflake import SnowflakeRepository

router = APIRouter(prefix="/api/v1", tags=["github"])
SettingsDep = Annotated[Settings, Depends(settings_dependency)]
SnowflakeDep = Annotated[SnowflakeRepository, Depends(snowflake_dependency)]
GitHubToken = Annotated[str | None, Header(include_in_schema=False)]


def token_value(x_github_token: str | None) -> str | None:
    return x_github_token.strip() if x_github_token else None


@router.post("/github/validate", response_model=GitHubIdentity)
async def validate_github_token(
    settings: SettingsDep,
    x_github_token: GitHubToken = None,
) -> GitHubIdentity:
    try:
        return await GitHubClient(settings, token_value(x_github_token)).validate_identity()
    except GitHubApiError as error:
        raise HTTPException(status_code=error.status_code, detail=error.message) from error


@router.post("/repositories/{owner}/{repo}/analyze", response_model=RepositoryAnalysis)
async def analyze_repository(
    owner: str,
    repo: str,
    settings: SettingsDep,
    snowflake: SnowflakeDep,
    x_github_token: GitHubToken = None,
) -> RepositoryAnalysis:
    client = GitHubClient(settings, token_value(x_github_token))
    try:
        repository = await client.repository(owner, repo)
        packages = await client.sbom(owner, repo)
    except GitHubApiError as error:
        raise HTTPException(status_code=error.status_code, detail=error.message) from error

    end = datetime.now(UTC)
    start = end - timedelta(days=30)
    if settings.data_mode == "mock":
        risk = mock_data.repository_risk(f"{owner}/{repo}", start, end)
    else:
        try:
            snowflake.merge_repository_dependencies(f"{owner}/{repo}", packages)
            risk = snowflake.repository_risk(f"{owner}/{repo}", start, end)
        except Exception as error:
            raise HTTPException(
                status_code=502, detail="Snowflake repository query failed"
            ) from error

    ecosystems = sorted(
        {
            package.purl.split(":", 1)[1].split("/", 1)[0]
            for package in packages
            if package.purl and ":" in package.purl
        }
    )
    return RepositoryAnalysis(
        repository=repository["full_name"],
        default_branch=repository["default_branch"],
        visibility=repository.get("visibility", "public"),
        dependency_count=len(packages),
        ecosystems=ecosystems,
        packages=packages[:100],
        risk=risk,
    )
