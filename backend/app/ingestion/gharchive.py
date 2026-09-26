import gzip
import json
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx


def hour_url(hour: datetime) -> str:
    normalized = hour.astimezone(UTC).replace(minute=0, second=0, microsecond=0)
    return f"https://data.gharchive.org/{normalized:%Y-%m-%d}-{normalized.hour}.json.gz"


async def download_hour(hour: datetime, timeout: float = 60) -> list[dict[str, Any]]:
    # Windows strftime does not support %-H.
    normalized = hour.astimezone(UTC).replace(minute=0, second=0, microsecond=0)
    url = f"https://data.gharchive.org/{normalized:%Y-%m-%d}-{normalized.hour}.json.gz"
    rows: list[dict[str, Any]] = []
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(suffix=".json.gz", delete=False) as temporary:
            temporary_path = Path(temporary.name)
            async with (
                httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client,
                client.stream("GET", url) as response,
            ):
                if response.status_code == 404:
                    return []
                response.raise_for_status()
                async for chunk in response.aiter_bytes():
                    temporary.write(chunk)
        with gzip.open(temporary_path, "rt", encoding="utf-8") as archive:
            for line in archive:
                raw = json.loads(line)
                if raw.get("type") not in {"PushEvent", "MemberEvent", "ForkEvent"}:
                    continue
                payload = raw.get("payload") or {}
                member = payload.get("member") or {}
                rows.append(
                    {
                        "event_id": str(raw["id"]),
                        "event_created_at": raw["created_at"],
                        "event_type": raw["type"],
                        "actor_login": (raw.get("actor") or {}).get("login"),
                        "actor_id": (raw.get("actor") or {}).get("id"),
                        "repo_name": (raw.get("repo") or {}).get("name"),
                        "repo_id": (raw.get("repo") or {}).get("id"),
                        "org_login": (raw.get("org") or {}).get("login"),
                        "payload": payload,
                        "action": payload.get("action"),
                        "ref": payload.get("ref"),
                        "ref_type": payload.get("ref_type"),
                        "push_id": payload.get("push_id"),
                        "head": payload.get("head"),
                        "before": payload.get("before"),
                        "size": payload.get("size"),
                        "distinct_size": payload.get("distinct_size"),
                        "member_login": member.get("login"),
                        "member_id": member.get("id"),
                        "source_file": url,
                    }
                )
    finally:
        if temporary_path:
            temporary_path.unlink(missing_ok=True)
    return rows
