from typing import Any

import httpx

from app.config import Settings
from app.models import GitHubIdentity, SbomPackage


class GitHubApiError(RuntimeError):
    def __init__(self, status_code: int, message: str) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.message = message


class GitHubClient:
    def __init__(self, settings: Settings, token: str | None = None) -> None:
        self.settings = settings
        self.token = token

    def _headers(self) -> dict[str, str]:
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": self.settings.github_api_version,
            "User-Agent": "sentinel-oss-dashboard",
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        return headers

    async def _get(self, path: str) -> tuple[dict[str, Any], httpx.Headers]:
        async with httpx.AsyncClient(
            base_url=self.settings.github_api_url,
            headers=self._headers(),
            timeout=self.settings.request_timeout_seconds,
        ) as client:
            response = await client.get(path)
        if response.status_code >= 400:
            detail = response.json().get("message", "GitHub request failed")
            raise GitHubApiError(response.status_code, detail)
        return response.json(), response.headers

    async def validate_identity(self) -> GitHubIdentity:
        if not self.token:
            raise GitHubApiError(401, "A GitHub token is required")
        payload, headers = await self._get("/user")
        scopes = [
            scope.strip() for scope in headers.get("x-oauth-scopes", "").split(",") if scope.strip()
        ]
        return GitHubIdentity(login=payload["login"], account_id=payload["id"], scopes=scopes)

    async def repository(self, owner: str, repo: str) -> dict[str, Any]:
        payload, _ = await self._get(f"/repos/{owner}/{repo}")
        return payload

    async def sbom(self, owner: str, repo: str) -> list[SbomPackage]:
        payload, _ = await self._get(f"/repos/{owner}/{repo}/dependency-graph/sbom")
        packages = payload.get("sbom", {}).get("packages", [])
        return [
            SbomPackage(
                name=package.get("name", "unknown"),
                version=package.get("versionInfo"),
                purl=self._purl(package),
                spdx_id=package.get("SPDXID"),
            )
            for package in packages
            if package.get("name")
        ]

    async def global_advisories(
        self, *, per_page: int = 100, max_pages: int = 10
    ) -> list[dict[str, Any]]:
        advisories: list[dict[str, Any]] = []
        async with httpx.AsyncClient(
            base_url=self.settings.github_api_url,
            headers=self._headers(),
            timeout=self.settings.request_timeout_seconds,
        ) as client:
            for page in range(1, max_pages + 1):
                response = await client.get(
                    "/advisories",
                    params={
                        "per_page": per_page,
                        "page": page,
                        "sort": "updated",
                        "direction": "desc",
                    },
                )
                if response.status_code >= 400:
                    detail = response.json().get("message", "GitHub advisory request failed")
                    raise GitHubApiError(response.status_code, detail)
                batch = response.json()
                advisories.extend(batch)
                if len(batch) < per_page:
                    break
        return advisories

    @staticmethod
    def _purl(package: dict[str, Any]) -> str | None:
        for reference in package.get("externalRefs", []):
            if reference.get("referenceType") == "purl":
                return reference.get("referenceLocator")
        return None
