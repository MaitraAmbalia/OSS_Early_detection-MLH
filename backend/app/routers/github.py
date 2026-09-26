from datetime import UTC, datetime, timedelta
from typing import Annotated

from fastapi import APIRouter, Depends, Header, HTTPException

from app.config import Settings
from app.dependencies import settings_dependency
from app.models import (
    DependencyExposure,
    GitHubIdentity,
    GitHubRepositories,
    GitHubRepositorySummary,
    RepositoryAnalysis,
    RepositoryRisk,
)
from app.services.github import GitHubApiError, GitHubClient

router = APIRouter(prefix="/api/v1", tags=["github"])
SettingsDep = Annotated[Settings, Depends(settings_dependency)]
GitHubToken = Annotated[str | None, Header(include_in_schema=False)]


def token_value(x_github_token: str | None, fallback: str | None = None) -> str | None:
    value = x_github_token or fallback
    return value.strip() if value and value.strip() else None


@router.post("/github/validate", response_model=GitHubIdentity)
async def validate_github_token(
    settings: SettingsDep,
    x_github_token: GitHubToken = None,
) -> GitHubIdentity:
    try:
        return await GitHubClient(
            settings, token_value(x_github_token, settings.github_token)
        ).validate_identity()
    except GitHubApiError as error:
        raise HTTPException(status_code=error.status_code, detail=error.message) from error


@router.get("/github/repositories", response_model=GitHubRepositories)
async def list_github_repositories(
    settings: SettingsDep,
    x_github_token: GitHubToken = None,
) -> GitHubRepositories:
    credential = token_value(x_github_token, settings.github_token)
    if not credential:
        raise HTTPException(status_code=401, detail="A GitHub token is required")
    try:
        repositories = await GitHubClient(settings, credential).repositories()
    except GitHubApiError as error:
        raise HTTPException(status_code=error.status_code, detail=error.message) from error
    return GitHubRepositories(
        items=[
            GitHubRepositorySummary(
                full_name=item["full_name"],
                private=bool(item.get("private")),
                default_branch=item.get("default_branch") or "main",
                html_url=item["html_url"],
                updated_at=item["updated_at"],
                archived=bool(item.get("archived")),
            )
            for item in repositories
        ]
    )


def github_risk(
    repo_name: str,
    alerts: list[dict[str, object]],
    start: datetime,
    end: datetime,
) -> RepositoryRisk:
    severity_scores = {"critical": 95, "high": 75, "medium": 45, "low": 20}
    exposures: list[DependencyExposure] = []
    severity_counts = {severity: 0 for severity in severity_scores}

    for alert in alerts:
        dependency = alert.get("dependency") or {}
        advisory = alert.get("security_advisory") or {}
        vulnerability = alert.get("security_vulnerability") or {}
        if not isinstance(dependency, dict) or not isinstance(advisory, dict):
            continue
        if not isinstance(vulnerability, dict):
            vulnerability = {}
        package = vulnerability.get("package") or dependency.get("package") or {}
        if not isinstance(package, dict):
            package = {}
        first_patched = vulnerability.get("first_patched_version") or {}
        if not isinstance(first_patched, dict):
            first_patched = {}
        severity = str(advisory.get("severity") or "low").lower()
        if severity not in severity_scores:
            severity = "low"
        severity_counts[severity] += 1
        exposures.append(
            DependencyExposure(
                ecosystem=str(package.get("ecosystem") or "unknown"),
                package_name=str(package.get("name") or "unknown"),
                resolved_version=None,
                advisory_source="github_dependabot",
                advisory_id=str(advisory.get("ghsa_id") or alert.get("number") or "unknown"),
                advisory_type="dependabot_alert",
                severity=severity,
                match_status="open",
                match_reason=str(vulnerability.get("vulnerable_version_range") or "GitHub alert"),
            )
        )

    score = max((severity_scores[item.severity] for item in exposures), default=0)
    risk_level = "critical" if score >= 90 else "high" if score >= 70 else "medium" if score >= 40 else "low"
    return RepositoryRisk(
        repo=repo_name,
        composite_score=score,
        risk_level=risk_level,
        signals={
            "github_dependabot_alerts": {
                "fired": bool(exposures),
                "score": score,
                "open_alerts": len(exposures),
                "by_severity": severity_counts,
            }
        },
        ai_explanation=None,
        blast_radius_repos=[],
        dependency_exposures=exposures,
        window_start=start,
        window_end=end,
        data_sources=["github_dependency_graph", "github_dependabot_alerts"],
        computed_at=end,
    )


@router.post("/repositories/{owner}/{repo}/analyze", response_model=RepositoryAnalysis)
async def analyze_repository(
    owner: str,
    repo: str,
    settings: SettingsDep,
    x_github_token: GitHubToken = None,
) -> RepositoryAnalysis:
    credential = token_value(x_github_token, settings.github_token)
    if not credential:
        raise HTTPException(status_code=401, detail="A GitHub token is required")
    client = GitHubClient(settings, credential)
    try:
        repository = await client.repository(owner, repo)
        packages = await client.sbom(owner, repo)
    except GitHubApiError as error:
        raise HTTPException(status_code=error.status_code, detail=error.message) from error

    end = datetime.now(UTC)
    start = end - timedelta(days=30)
    vulnerability_status = "available"
    vulnerability_message = None
    try:
        alerts = await client.dependabot_alerts(owner, repo)
    except GitHubApiError as error:
        if error.status_code not in {403, 404}:
            raise HTTPException(status_code=error.status_code, detail=error.message) from error
        alerts = []
        vulnerability_status = "unavailable"
        vulnerability_message = (
            "Dependabot alerts are unavailable. Enable Dependabot alerts and grant the "
            "fine-grained token Dependabot alerts: read permission for this repository."
        )
    risk = github_risk(f"{owner}/{repo}", alerts, start, end)

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
        packages=packages[:250],
        risk=risk,
        vulnerability_status=vulnerability_status,
        vulnerability_message=vulnerability_message,
    )
