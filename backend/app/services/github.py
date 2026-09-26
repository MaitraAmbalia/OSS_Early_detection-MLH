import base64
import json
import re
import tomllib
from typing import Any
from urllib.parse import quote

import httpx
from packaging.requirements import InvalidRequirement, Requirement

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

    async def _get(
        self, path: str, *, params: dict[str, object] | None = None
    ) -> tuple[Any, httpx.Headers]:
        async with httpx.AsyncClient(
            base_url=self.settings.github_api_url,
            headers=self._headers(),
            timeout=self.settings.request_timeout_seconds,
        ) as client:
            response = await client.get(path, params=params)
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

    async def repositories(self, *, max_pages: int = 10) -> list[dict[str, Any]]:
        if not self.token:
            raise GitHubApiError(401, "A GitHub token is required")
        repositories: list[dict[str, Any]] = []
        for page in range(1, max_pages + 1):
            payload, _ = await self._get(
                "/user/repos",
                params={
                    "affiliation": "owner,collaborator,organization_member",
                    "sort": "updated",
                    "direction": "desc",
                    "per_page": 100,
                    "page": page,
                },
            )
            if not isinstance(payload, list):
                raise GitHubApiError(502, "GitHub returned an invalid repository list")
            repositories.extend(payload)
            if len(payload) < 100:
                break
        return repositories

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

    async def manifest_dependencies(
        self, owner: str, repo: str, ref: str
    ) -> list[SbomPackage]:
        encoded_ref = quote(ref, safe="")
        tree, _ = await self._get(
            f"/repos/{owner}/{repo}/git/trees/{encoded_ref}", params={"recursive": "1"}
        )
        if not isinstance(tree, dict) or tree.get("truncated"):
            raise GitHubApiError(422, "GitHub could not return a complete repository tree")

        manifest_paths = [
            item["path"]
            for item in tree.get("tree", [])
            if isinstance(item, dict)
            and item.get("type") == "blob"
            and self._supported_manifest(str(item.get("path", "")))
        ]
        packages: list[SbomPackage] = []
        for path in manifest_paths[:30]:
            encoded_path = quote(path, safe="/")
            payload, _ = await self._get(
                f"/repos/{owner}/{repo}/contents/{encoded_path}", params={"ref": ref}
            )
            if not isinstance(payload, dict) or payload.get("encoding") != "base64":
                continue
            try:
                content = base64.b64decode(payload.get("content", "")).decode("utf-8")
            except (ValueError, UnicodeDecodeError):
                continue
            packages.extend(self._parse_manifest(path, content))

        unique: dict[tuple[str, str | None], SbomPackage] = {}
        for package in packages:
            unique[(package.purl or package.name, package.version)] = package
        return sorted(unique.values(), key=lambda item: item.name.lower())

    @staticmethod
    def _supported_manifest(path: str) -> bool:
        name = path.rsplit("/", 1)[-1].lower()
        return name in {"package-lock.json", "npm-shrinkwrap.json", "pyproject.toml"} or (
            name.startswith("requirements") and name.endswith(".txt")
        )

    @classmethod
    def _parse_manifest(cls, path: str, content: str) -> list[SbomPackage]:
        name = path.rsplit("/", 1)[-1].lower()
        try:
            if name in {"package-lock.json", "npm-shrinkwrap.json"}:
                return cls._parse_npm_lock(path, json.loads(content))
            if name == "pyproject.toml":
                dependencies = tomllib.loads(content).get("project", {}).get("dependencies", [])
                return cls._python_packages(path, dependencies)
            if name.startswith("requirements") and name.endswith(".txt"):
                dependencies = [
                    line.strip()
                    for line in content.splitlines()
                    if line.strip() and not line.lstrip().startswith(("#", "-"))
                ]
                return cls._python_packages(path, dependencies)
        except (json.JSONDecodeError, tomllib.TOMLDecodeError, TypeError):
            return []
        return []

    @staticmethod
    def _parse_npm_lock(path: str, document: dict[str, Any]) -> list[SbomPackage]:
        packages: list[SbomPackage] = []
        lock_packages = document.get("packages")
        if isinstance(lock_packages, dict):
            for location, item in lock_packages.items():
                if not location or not isinstance(item, dict) or "node_modules/" not in location:
                    continue
                name = location.rsplit("node_modules/", 1)[-1]
                version = str(item["version"]) if item.get("version") is not None else None
                purl_name = quote(name, safe="/")
                purl = f"pkg:npm/{purl_name}@{version}" if version else f"pkg:npm/{purl_name}"
                packages.append(
                    SbomPackage(
                        name=name,
                        version=version,
                        purl=purl,
                        spdx_id=f"manifest:{path}:{name}",
                    )
                )
        return packages

    @staticmethod
    def _python_packages(path: str, dependencies: list[object]) -> list[SbomPackage]:
        packages: list[SbomPackage] = []
        for value in dependencies:
            try:
                requirement = Requirement(str(value))
            except InvalidRequirement:
                continue
            exact_versions = [
                specifier.version
                for specifier in requirement.specifier
                if specifier.operator in {"==", "==="} and "*" not in specifier.version
            ]
            version = exact_versions[0] if len(exact_versions) == 1 else None
            normalized = re.sub(r"[-_.]+", "-", requirement.name).lower()
            purl = f"pkg:pypi/{normalized}@{version}" if version else f"pkg:pypi/{normalized}"
            packages.append(
                SbomPackage(
                    name=requirement.name,
                    version=version,
                    purl=purl,
                    spdx_id=f"manifest:{path}:{requirement.name}",
                )
            )
        return packages

    async def dependabot_alerts(
        self, owner: str, repo: str, *, max_pages: int = 10
    ) -> list[dict[str, Any]]:
        if not self.token:
            raise GitHubApiError(401, "A GitHub token is required")
        alerts: list[dict[str, Any]] = []
        for page in range(1, max_pages + 1):
            payload, _ = await self._get(
                f"/repos/{owner}/{repo}/dependabot/alerts",
                params={"state": "open", "per_page": 100, "page": page},
            )
            if not isinstance(payload, list):
                raise GitHubApiError(502, "GitHub returned invalid Dependabot alert data")
            alerts.extend(payload)
            if len(payload) < 100:
                break
        return alerts

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
