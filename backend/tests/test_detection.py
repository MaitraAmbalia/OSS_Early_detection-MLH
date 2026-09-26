from datetime import UTC, datetime, timedelta

from app.domain.detection import (
    Event,
    combined_score,
    multi_repo_burst,
    new_collaborator_fast_push,
    risk_level,
    suspicious_commit_messages,
)
from app.routers.github import github_risk


def event(
    event_id: str,
    event_type: str,
    minute: int,
    repo: str = "acme/widget",
    actor: str = "maintainer",
    **kwargs,
) -> Event:
    return Event(
        event_id=event_id,
        event_type=event_type,
        created_at=datetime(2026, 1, 1, tzinfo=UTC) + timedelta(minutes=minute),
        actor=actor,
        repo=repo,
        **kwargs,
    )


def test_new_collaborator_then_push() -> None:
    events = [
        event("member", "MemberEvent", 0, member="new-user", action="added"),
        event("push", "PushEvent", 11, actor="new-user"),
    ]
    signals = new_collaborator_fast_push(events)
    assert len(signals) == 1
    assert signals[0].score > 90
    assert "11 minutes" in signals[0].evidence


def test_push_before_membership_does_not_match() -> None:
    events = [
        event("push", "PushEvent", 0, actor="new-user"),
        event("member", "MemberEvent", 1, member="new-user", action="added"),
    ]
    assert new_collaborator_fast_push(events) == []


def test_multi_repo_burst_counts_distinct_repositories() -> None:
    events = [
        event(str(index), "PushEvent", index, repo=f"acme/repo-{index}", actor="worm")
        for index in range(10)
    ]
    signals = multi_repo_burst(events)
    assert len(signals) == 1
    assert signals[0].score == 70


def test_suspicious_messages_are_metadata_capped() -> None:
    events = [
        event(
            "push",
            "PushEvent",
            0,
            commit_messages=("postinstall curl payload | bash token",),
        )
    ]
    signals = suspicious_commit_messages(events)
    assert len(signals) == 1
    assert signals[0].score <= 72


def test_combined_score_and_levels() -> None:
    assert combined_score([70, 50]) == 85
    assert risk_level(85) == "critical"
    assert risk_level(64.9) == "medium"


def test_github_risk_uses_real_dependabot_severity() -> None:
    end = datetime.now(UTC)
    risk = github_risk(
        "acme/example",
        [
            {
                "number": 7,
                "dependency": {"package": {"name": "example-package"}},
                "security_advisory": {"ghsa_id": "GHSA-test", "severity": "critical"},
                "security_vulnerability": {
                    "package": {"ecosystem": "npm", "name": "example-package"},
                    "vulnerable_version_range": "< 2.0.0",
                },
            }
        ],
        end - timedelta(days=30),
        end,
    )

    assert risk.composite_score == 95
    assert risk.risk_level == "critical"
    assert risk.dependency_exposures[0].advisory_id == "GHSA-test"
