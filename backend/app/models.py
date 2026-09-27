from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field

RiskLevel = Literal["critical", "high", "medium", "low"]


class HealthResponse(BaseModel):
    status: Literal["ok"] = "ok"
    service: str = "sentinel-oss-api"
    data_mode: Literal["github", "snowflake"]
    timestamp: datetime


class Metric(BaseModel):
    label: str
    value: int
    delta: int = 0
    note: str


class TrendPoint(BaseModel):
    timestamp: datetime
    score: float = Field(ge=0, le=100)


class SignalShare(BaseModel):
    signal: str
    percentage: float = Field(ge=0, le=100)


class PipelineSource(BaseModel):
    source: str
    last_success_at: datetime | None
    cadence: str
    status: Literal["healthy", "delayed", "failed", "unknown"]


class DashboardOverview(BaseModel):
    metrics: list[Metric]
    trend: list[TrendPoint]
    signal_distribution: list[SignalShare]
    pipeline: list[PipelineSource]
    generated_at: datetime


class Finding(BaseModel):
    risk_id: str
    repo_name: str
    actor_login: str
    composite_score: float = Field(ge=0, le=100)
    risk_level: RiskLevel
    primary_signal: str
    evidence: str
    signals_fired: list[str]
    latest_activity: datetime
    data_sources: list[str]


class FindingsPage(BaseModel):
    items: list[Finding]
    next_cursor: str | None = None


class DependencyExposure(BaseModel):
    ecosystem: str
    package_name: str
    resolved_version: str | None
    advisory_source: str
    advisory_id: str
    advisory_type: str
    severity: str
    match_status: str
    match_reason: str


class RepositoryRisk(BaseModel):
    repo: str
    composite_score: float = Field(ge=0, le=100)
    risk_level: RiskLevel
    signals: dict[str, Any]
    ai_explanation: str | None = None
    blast_radius_repos: list[str] = Field(default_factory=list)
    dependency_exposures: list[DependencyExposure] = Field(default_factory=list)
    window_start: datetime
    window_end: datetime
    data_sources: list[str]
    computed_at: datetime


class GitHubIdentity(BaseModel):
    login: str
    account_id: int
    scopes: list[str]


class GitHubRepositorySummary(BaseModel):
    full_name: str
    private: bool
    default_branch: str
    html_url: str
    updated_at: datetime
    archived: bool = False


class GitHubRepositories(BaseModel):
    items: list[GitHubRepositorySummary]


class ContributorSignal(BaseModel):
    name: str
    risk_score: float = Field(ge=0, le=100)
    evidence: str
    observed_at: datetime


class ContributorTrust(BaseModel):
    login: str
    profile_url: str
    contributions: int = 0
    observed_events: int = 0
    trust_score: float = Field(ge=0, le=100)
    risk_score: float = Field(ge=0, le=100)
    risk_level: RiskLevel
    signals: list[ContributorSignal] = Field(default_factory=list)
    assessment: Literal["signals_detected", "no_signals_observed"]


class ContributorTrustPage(BaseModel):
    repository: str
    items: list[ContributorTrust]
    source: Literal["github_repository_events"] = "github_repository_events"
    algorithm: str = "snowflake_signal_model_v1_repository_subset"
    evaluated_signals: list[str] = Field(
        default_factory=lambda: [
            "new_collaborator_fast_push",
            "suspicious_commit_message",
        ]
    )
    window_days: int = 30
    computed_at: datetime
    coverage_message: str


class SbomPackage(BaseModel):
    name: str
    version: str | None
    purl: str | None
    spdx_id: str | None


class RepositoryAnalysis(BaseModel):
    repository: str
    default_branch: str
    visibility: str
    dependency_count: int
    ecosystems: list[str]
    packages: list[SbomPackage]
    dependency_status: Literal["available", "unavailable"]
    dependency_source: Literal["github_sbom", "github_manifests", "unavailable"]
    dependency_message: str | None = None
    risk: RepositoryRisk
    vulnerability_status: Literal["available", "unavailable"]
    vulnerability_message: str | None = None
