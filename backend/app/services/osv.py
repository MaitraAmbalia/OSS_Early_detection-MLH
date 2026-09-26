from typing import Any

import httpx

from app.config import Settings
from app.models import SbomPackage


class OsvClient:
    def __init__(self, settings: Settings) -> None:
        self.timeout = settings.request_timeout_seconds

    async def query_batch(self, packages: list[SbomPackage]) -> list[dict[str, Any]]:
        queries = []
        query_packages = []
        for package in packages:
            if not package.purl or not package.version:
                continue
            query_packages.append(package)
            queries.append({"package": {"purl": package.purl}, "version": package.version})
        if not queries:
            return []
        async with httpx.AsyncClient(
            base_url="https://api.osv.dev", timeout=self.timeout
        ) as client:
            response = await client.post("/v1/querybatch", json={"queries": queries})
        response.raise_for_status()
        results: list[dict[str, Any]] = []
        for package, result in zip(query_packages, response.json().get("results", []), strict=True):
            for vulnerability in result.get("vulns", []):
                results.append(
                    {
                        "package": package.model_dump(),
                        "vulnerability": vulnerability,
                    }
                )
        return results
