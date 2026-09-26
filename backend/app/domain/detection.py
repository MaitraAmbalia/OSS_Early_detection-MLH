import math
import re
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timedelta


@dataclass(frozen=True)
class Event:
    event_id: str
    event_type: str
    created_at: datetime
    actor: str
    repo: str
    action: str | None = None
    member: str | None = None
    commit_messages: tuple[str, ...] = ()


@dataclass(frozen=True)
class Signal:
    name: str
    score: float
    repo: str
    actor: str
    observed_at: datetime
    evidence: str
    event_ids: tuple[str, ...]


SUSPICIOUS_PATTERNS: tuple[tuple[str, re.Pattern[str], float], ...] = (
    (
        "install_hook",
        re.compile(r"\b(preinstall|postinstall|prepare|setup\.py|install script)\b", re.IGNORECASE),
        42,
    ),
    (
        "obfuscation",
        re.compile(
            r"\b(eval\s*\(|fromcharcode|base64|atob\s*\(|obfuscat|encoded payload)\b",
            re.IGNORECASE,
        ),
        58,
    ),
    (
        "credential_access",
        re.compile(
            r"\b(token|credential|secret|\.npmrc|aws_access_key|github_token)\b",
            re.IGNORECASE,
        ),
        54,
    ),
    (
        "download_execute",
        re.compile(
            r"\b(curl|wget|invoke-webrequest)\b.*\b(sh|bash|powershell|iex)\b", re.IGNORECASE
        ),
        70,
    ),
)


def new_collaborator_fast_push(
    events: list[Event], window: timedelta = timedelta(hours=24)
) -> list[Signal]:
    additions: dict[tuple[str, str], deque[Event]] = defaultdict(deque)
    signals: list[Signal] = []
    for event in sorted(events, key=lambda item: item.created_at):
        if event.event_type == "MemberEvent" and event.action == "added" and event.member:
            additions[(event.repo, event.member)].append(event)
            continue
        if event.event_type != "PushEvent":
            continue
        candidates = additions[(event.repo, event.actor)]
        while candidates and event.created_at - candidates[0].created_at > window:
            candidates.popleft()
        if not candidates:
            continue
        added = candidates[-1]
        minutes = max(0, int((event.created_at - added.created_at).total_seconds() / 60))
        # Fast actions score higher, while the complete 24-hour window still remains visible.
        score = round(55 + 40 * math.exp(-minutes / 180), 1)
        signals.append(
            Signal(
                name="new_collaborator_fast_push",
                score=min(score, 95),
                repo=event.repo,
                actor=event.actor,
                observed_at=event.created_at,
                evidence=f"First observed push occurred {minutes} minutes after access was added.",
                event_ids=(added.event_id, event.event_id),
            )
        )
        candidates.clear()
    return signals


def multi_repo_burst(
    events: list[Event], threshold: int = 10, window: timedelta = timedelta(hours=1)
) -> list[Signal]:
    actor_windows: dict[str, deque[Event]] = defaultdict(deque)
    signals: list[Signal] = []
    emitted: set[tuple[str, datetime]] = set()
    for event in sorted(events, key=lambda item: item.created_at):
        if event.event_type != "PushEvent":
            continue
        current = actor_windows[event.actor]
        while current and event.created_at - current[0].created_at > window:
            current.popleft()
        current.append(event)
        distinct_repos = {item.repo for item in current}
        bucket = event.created_at.replace(minute=0, second=0, microsecond=0)
        if len(distinct_repos) < threshold or (event.actor, bucket) in emitted:
            continue
        emitted.add((event.actor, bucket))
        score = min(98, 70 + (len(distinct_repos) - threshold) * 3)
        signals.append(
            Signal(
                name="multi_repo_burst",
                score=score,
                repo=event.repo,
                actor=event.actor,
                observed_at=event.created_at,
                evidence=(
                    f"Actor pushed to {len(distinct_repos)} distinct repositories within one hour."
                ),
                event_ids=tuple(item.event_id for item in current),
            )
        )
    return signals


def suspicious_commit_messages(events: list[Event]) -> list[Signal]:
    signals: list[Signal] = []
    for event in events:
        if event.event_type != "PushEvent" or not event.commit_messages:
            continue
        matches: list[tuple[str, float]] = []
        for message in event.commit_messages:
            for name, pattern, weight in SUSPICIOUS_PATTERNS:
                if pattern.search(message):
                    matches.append((name, weight))
        if not matches:
            continue
        labels = sorted({name for name, _ in matches})
        # Commit metadata has no diff context, so this signal is deliberately capped.
        score = min(72, max(weight for _, weight in matches) + 4 * (len(labels) - 1))
        signals.append(
            Signal(
                name="suspicious_commit_message",
                score=score,
                repo=event.repo,
                actor=event.actor,
                observed_at=event.created_at,
                evidence=f"Commit metadata matched: {', '.join(labels)}.",
                event_ids=(event.event_id,),
            )
        )
    return signals


def combined_score(scores: list[float]) -> float:
    """Combine independent evidence without allowing a single weak signal to dominate."""
    if not scores:
        return 0.0
    complement = math.prod(1 - min(max(score, 0), 100) / 100 for score in scores)
    return round(min(100, 100 * (1 - complement)), 1)


def risk_level(score: float) -> str:
    if score >= 85:
        return "critical"
    if score >= 65:
        return "high"
    if score >= 40:
        return "medium"
    return "low"


def detect(events: list[Event]) -> list[Signal]:
    return [
        *new_collaborator_fast_push(events),
        *multi_repo_burst(events),
        *suspicious_commit_messages(events),
    ]
