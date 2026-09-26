from datetime import UTC, datetime, timedelta

from app.models import (
    DashboardOverview,
    DependencyExposure,
    Finding,
    FindingsPage,
    Metric,
    PipelineSource,
    RepositoryRisk,
    SignalShare,
    TrendPoint,
)


def now_utc() -> datetime:
    return datetime.now(UTC)


def overview() -> DashboardOverview:
    now = now_utc()
    values = [18, 22, 17, 28, 25, 34, 29, 43, 38, 55, 49, 71, 62, 82, 76, 91]
    return DashboardOverview(
        metrics=[
            Metric(label="Critical findings", value=12, delta=4, note="since yesterday"),
            Metric(label="Repos monitored", value=1248, delta=38, note="this week"),
            Metric(label="Exposed packages", value=47, delta=-9, note="resolved"),
            Metric(label="Active actors", value=326, delta=8, note="unusual"),
        ],
        trend=[
            TrendPoint(timestamp=now - timedelta(hours=len(values) - i), score=value)
            for i, value in enumerate(values)
        ],
        signal_distribution=[
            SignalShare(signal="dependency_exposure", percentage=38),
            SignalShare(signal="actor_anomaly", percentage=27),
            SignalShare(signal="cross_repo_burst", percentage=21),
            SignalShare(signal="suspicious_change", percentage=14),
        ],
        pipeline=[
            PipelineSource(
                source="gharchive",
                last_success_at=now - timedelta(minutes=12),
                cadence="hourly",
                status="healthy",
            ),
            PipelineSource(
                source="github_advisories",
                last_success_at=now - timedelta(hours=3),
                cadence="daily",
                status="healthy",
            ),
            PipelineSource(
                source="osv",
                last_success_at=now - timedelta(hours=8),
                cadence="daily",
                status="healthy",
            ),
        ],
        generated_at=now,
    )


def findings() -> FindingsPage:
    now = now_utc()
    return FindingsPage(
        items=[
            Finding(
                risk_id="evt_0187",
                repo_name="asyncapi/generator",
                actor_login="release-helper",
                composite_score=96,
                risk_level="critical",
                primary_signal="cross_repo_propagation",
                evidence="Same install-time change reached 14 repositories in 38 minutes.",
                signals_fired=["cross_repo_burst", "suspicious_change", "new_actor"],
                latest_activity=now - timedelta(minutes=8),
                data_sources=["gharchive_hourly"],
            ),
            Finding(
                risk_id="evt_0184",
                repo_name="acme/checkout-sdk",
                actor_login="dmitry-k",
                composite_score=87,
                risk_level="high",
                primary_signal="new_collaborator_fast_push",
                evidence="First push landed 11 minutes after repository access was granted.",
                signals_fired=["new_collaborator_fast_push", "first_repo_push"],
                latest_activity=now - timedelta(minutes=24),
                data_sources=["gharchive_hourly"],
            ),
            Finding(
                risk_id="evt_0179",
                repo_name="northstar/web-client",
                actor_login="dependabot[bot]",
                composite_score=74,
                risk_level="high",
                primary_signal="dependency_exposure",
                evidence="Build resolves a version covered by a reviewed critical advisory.",
                signals_fired=["dependency_exposure"],
                latest_activity=now - timedelta(hours=1),
                data_sources=["github_advisories", "osv"],
            ),
        ]
    )


def repository_risk(repo: str, start: datetime, end: datetime) -> RepositoryRisk:
    return RepositoryRisk(
        repo=repo,
        composite_score=87,
        risk_level="high",
        signals={
            "new_collaborator_fast_push": {
                "fired": True,
                "score": 84,
                "details": "First push 11 minutes after access was granted.",
            },
            "multi_repo_burst": {"fired": False, "score": 0, "details": None},
            "suspicious_commits": {
                "fired": True,
                "score": 46,
                "details": "Install-time behavior referenced in commit metadata.",
            },
            "delete_after_push": {"fired": False, "score": 0, "details": None},
        },
        ai_explanation="A newly added collaborator pushed an install-related change shortly after receiving access. Review the commit and verify the actor through an independent channel.",
        blast_radius_repos=["acme/payments-sdk", "acme/web-client"],
        dependency_exposures=[
            DependencyExposure(
                ecosystem="npm",
                package_name="lodash",
                resolved_version="4.17.20",
                advisory_source="github",
                advisory_id="GHSA-35jh-r3h4-6jhm",
                advisory_type="reviewed",
                severity="critical",
                match_status="confirmed_vulnerable",
                match_reason="semver_in_range",
            )
        ],
        window_start=start,
        window_end=end,
        data_sources=["gharchive_hourly", "github_advisories"],
        computed_at=now_utc(),
    )
