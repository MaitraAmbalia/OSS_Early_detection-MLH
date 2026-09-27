from datetime import UTC, datetime, timedelta
from typing import Annotated

from fastapi import APIRouter, Depends, Header, HTTPException

from app.config import Settings
from app.dependencies import settings_dependency
from app.domain.detection import (
    Event,
    Signal,
    combined_score,
    new_collaborator_fast_push,
    risk_level,
    suspicious_commit_messages,
)
from app.models import (
    ContributorSignal,
    ContributorTrust,
    ContributorTrustPage,
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


def github_contributor_trust(
    repo_name: str,
    contributors: list[dict[str, object]],
    raw_events: list[dict[str, object]],
) -> ContributorTrustPage:
    events: list[Event] = []
    event_counts: dict[str, int] = {}

    for item in raw_events:
        actor = item.get("actor") or {}
        payload = item.get("payload") or {}
        created_at = item.get("created_at")
        if not isinstance(actor, dict) or not isinstance(payload, dict):
            continue
        login = str(actor.get("login") or "")
        if not login or not isinstance(created_at, str):
            continue
        try:
            observed_at = datetime.fromisoformat(created_at)
        except ValueError:
            continue
        commits = payload.get("commits") or []
        messages = tuple(
            str(commit.get("message"))
            for commit in commits
            if isinstance(commit, dict) and commit.get("message")
        )
        member = payload.get("member") or {}
        member_login = (
            str(member.get("login"))
            if isinstance(member, dict) and member.get("login")
            else None
        )
        events.append(
            Event(
                event_id=str(item.get("id") or "unknown"),
                event_type=str(item.get("type") or "unknown"),
                created_at=observed_at,
                actor=login,
                repo=repo_name,
                action=str(payload.get("action")) if payload.get("action") else None,
                member=member_login,
                commit_messages=messages,
            )
        )
        actor_key = login.lower()
        event_counts[actor_key] = event_counts.get(actor_key, 0) + 1

    signals_by_actor: dict[str, list[Signal]] = {}
    signals = [
        *new_collaborator_fast_push(events),
        *suspicious_commit_messages(events),
    ]
    for signal in signals:
        signals_by_actor.setdefault(signal.actor.lower(), []).append(signal)

    items: list[ContributorTrust] = []
    for contributor in contributors:
        login = str(contributor.get("login") or "")
        if not login:
            continue
        actor_signals = signals_by_actor.get(login.lower(), [])
        score = combined_score([signal.score for signal in actor_signals])
        items.append(
            ContributorTrust(
                login=login,
                profile_url=str(
                    contributor.get("html_url") or f"https://github.com/{login}"
                ),
                contributions=int(contributor.get("contributions") or 0),
                observed_events=event_counts.get(login.lower(), 0),
                trust_score=round(100 - score, 1),
                risk_score=score,
                risk_level=risk_level(score),
                signals=[
                    ContributorSignal(
                        name=signal.name,
                        risk_score=signal.score,
                        evidence=signal.evidence,
                        observed_at=signal.observed_at,
                    )
                    for signal in actor_signals
                ],
                assessment=(
                    "signals_detected" if actor_signals else "no_signals_observed"
                ),
            )
        )

    items.sort(key=lambda item: (-item.risk_score, -item.contributions, item.login.lower()))
    return ContributorTrustPage(
        repository=repo_name,
        items=items,
        computed_at=datetime.now(UTC),
        coverage_message=(
            "Repository-scoped heuristic based on GitHub's recent repository event window. "
            "Cross-repository burst detection requires persisted events from multiple connected "
            "repositories and is not included in this snapshot. "
            "A high score means no configured risk signals were observed; it is not proof "
            "of identity or a permanent judgment about a person."
        ),
    )


@router.get(
    "/repositories/{owner}/{repo}/contributors/trust",
    response_model=ContributorTrustPage,
)
async def contributor_trust(
    owner: str,
    repo: str,
    settings: SettingsDep,
    x_github_token: GitHubToken = None,
) -> ContributorTrustPage:
    credential = token_value(x_github_token, settings.github_token)
    if not credential:
        raise HTTPException(status_code=401, detail="A GitHub token is required")
    client = GitHubClient(settings, credential)
    try:
        contributors = await client.contributors(owner, repo)
        events = await client.repository_events(owner, repo)
    except GitHubApiError as error:
        raise HTTPException(status_code=error.status_code, detail=error.message) from error
    return github_contributor_trust(f"{owner}/{repo}", contributors, events)


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
    except GitHubApiError as error:
        raise HTTPException(status_code=error.status_code, detail=error.message) from error

    dependency_status = "available"
    dependency_source = "github_sbom"
    dependency_message = None
    try:
        packages = await client.sbom(owner, repo)
    except GitHubApiError as error:
        if error.status_code not in {403, 404}:
            raise HTTPException(status_code=error.status_code, detail=error.message) from error
        try:
            packages = await client.manifest_dependencies(
                owner, repo, repository.get("default_branch") or "main"
            )
        except GitHubApiError:
            packages = []
        if packages:
            dependency_source = "github_manifests"
            dependency_message = (
                "GitHub's SBOM is unavailable for this repository. Dependencies were read "
                "directly from committed lockfiles and manifests through the GitHub API."
            )
        else:
            dependency_status = "unavailable"
            dependency_source = "unavailable"
            dependency_message = (
                "GitHub's SBOM is unavailable and no supported committed dependency "
                "manifest could be read. Enable the repository Dependency Graph."
            )

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
        dependency_status=dependency_status,
        dependency_source=dependency_source,
        dependency_message=dependency_message,
        risk=risk,
        vulnerability_status=vulnerability_status,
        vulnerability_message=vulnerability_message,
    )
