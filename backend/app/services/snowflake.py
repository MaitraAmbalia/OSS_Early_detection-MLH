import json
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime
from typing import Any

import snowflake.connector
from cryptography.hazmat.primitives import serialization

from app.config import Settings
from app.domain.versions import canonical_ecosystem, normalize_package_name, version_is_affected
from app.models import DashboardOverview, FindingsPage, RepositoryRisk, SbomPackage


class SnowflakeRepository:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    def _private_key(self) -> bytes:
        self.settings.require_snowflake()
        assert self.settings.snowflake_private_key_file
        with open(self.settings.snowflake_private_key_file, "rb") as key_file:
            key = serialization.load_pem_private_key(
                key_file.read(),
                password=(self.settings.snowflake_private_key_passphrase or "").encode() or None,
            )
        return key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

    @contextmanager
    def connection(self) -> Iterator[Any]:
        self.settings.require_snowflake()
        connection = snowflake.connector.connect(
            account=self.settings.snowflake_account,
            user=self.settings.snowflake_user,
            private_key=self._private_key(),
            role=self.settings.snowflake_role,
            warehouse=self.settings.snowflake_warehouse,
            database=self.settings.snowflake_database,
            schema=self.settings.snowflake_schema,
            session_parameters={"QUERY_TAG": "sentinel-oss-dashboard"},
        )
        try:
            yield connection
        finally:
            connection.close()

    @staticmethod
    def _decode_variant(value: object) -> dict[str, Any]:
        if isinstance(value, dict):
            return value
        if isinstance(value, str):
            return json.loads(value)
        raise ValueError("Snowflake procedure returned an unsupported payload")

    def repository_risk(self, repo: str, start: datetime, end: datetime) -> RepositoryRisk:
        sql = "CALL CHECK_REPO_RISK(%s, %s, %s)"
        with self.connection() as connection, connection.cursor() as cursor:
            cursor.execute(sql, (repo, start.date().isoformat(), end.date().isoformat()))
            row = cursor.fetchone()
        if not row:
            raise LookupError(f"No risk result found for {repo}")
        return RepositoryRisk.model_validate(self._decode_variant(row[0]))

    def overview(self, start: datetime, end: datetime) -> DashboardOverview:
        # CoCo will expose this procedure/view contract during integration.
        sql = "CALL GET_DASHBOARD_OVERVIEW(%s, %s)"
        with self.connection() as connection, connection.cursor() as cursor:
            cursor.execute(sql, (start.isoformat(), end.isoformat()))
            row = cursor.fetchone()
        if not row:
            raise LookupError("Dashboard overview is empty")
        return DashboardOverview.model_validate(self._decode_variant(row[0]))

    def findings(self, level: str | None, limit: int) -> FindingsPage:
        where = "WHERE RISK_LEVEL = %s" if level else ""
        params: tuple[object, ...] = (level.upper(), limit) if level else (limit,)
        sql = f"""
            SELECT RISK_ID, REPO_NAME, ACTOR_LOGIN, COMPOSITE_SCORE, LOWER(RISK_LEVEL),
                   SIGNALS_FIRED[0]::STRING, AI_EXPLANATION, SIGNALS_FIRED,
                   LATEST_ACTIVITY, DATA_SOURCES
            FROM RISK_SCORES
            {where}
            ORDER BY COMPOSITE_SCORE DESC, LATEST_ACTIVITY DESC
            LIMIT %s
        """
        items: list[dict[str, Any]] = []
        with self.connection() as connection, connection.cursor() as cursor:
            cursor.execute(sql, params)
            for row in cursor.fetchall():
                items.append(
                    {
                        "risk_id": row[0],
                        "repo_name": row[1],
                        "actor_login": row[2],
                        "composite_score": row[3],
                        "risk_level": row[4],
                        "primary_signal": row[5] or "unknown",
                        "evidence": row[6] or "",
                        "signals_fired": self._decode_array(row[7]),
                        "latest_activity": row[8],
                        "data_sources": self._decode_array(row[9]),
                    }
                )
        return FindingsPage.model_validate({"items": items})

    @staticmethod
    def _decode_array(value: object) -> list[str]:
        if value is None:
            return []
        if isinstance(value, list):
            return [str(item) for item in value]
        if isinstance(value, str):
            decoded = json.loads(value)
            return [str(item) for item in decoded]
        return [str(value)]

    def checkpoint_completed(self, source_key: str) -> bool:
        sql = "SELECT STATUS = 'completed' FROM INGESTION_CHECKPOINTS WHERE SOURCE_KEY = %s"
        with self.connection() as connection, connection.cursor() as cursor:
            cursor.execute(sql, (source_key,))
            row = cursor.fetchone()
        return bool(row and row[0])

    def complete_checkpoint(self, source_key: str, row_count: int) -> None:
        sql = """
            MERGE INTO INGESTION_CHECKPOINTS target
            USING (SELECT %s SOURCE_KEY, %s ROW_COUNT) source
              ON target.SOURCE_KEY = source.SOURCE_KEY
            WHEN MATCHED THEN UPDATE SET STATUS='completed', ROW_COUNT=source.ROW_COUNT,
                 COMPLETED_AT=CURRENT_TIMESTAMP(), ERROR_MESSAGE=NULL
            WHEN NOT MATCHED THEN INSERT
                 (SOURCE_KEY, STATUS, ROW_COUNT, COMPLETED_AT)
                 VALUES (source.SOURCE_KEY, 'completed', source.ROW_COUNT, CURRENT_TIMESTAMP())
        """
        with self.connection() as connection, connection.cursor() as cursor:
            cursor.execute(sql, (source_key, row_count))
            connection.commit()

    def merge_gharchive_events(self, rows: list[dict[str, Any]]) -> None:
        if not rows:
            return
        insert = """
            INSERT INTO GHARCHIVE_EVENTS_BUFFER (
                EVENT_ID, EVENT_CREATED_AT, EVENT_TYPE, ACTOR_LOGIN, ACTOR_ID,
                REPO_NAME, REPO_ID, ORG_LOGIN, PAYLOAD, ACTION, REF, REF_TYPE,
                PUSH_ID, HEAD, BEFORE, SIZE, DISTINCT_SIZE, MEMBER_LOGIN,
                MEMBER_ID, SOURCE_FILE
            ) SELECT %s, %s, %s, %s, %s, %s, %s, %s, PARSE_JSON(%s), %s,
                     %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
        """
        values = [
            (
                row["event_id"],
                row["event_created_at"],
                row["event_type"],
                row["actor_login"],
                row["actor_id"],
                row["repo_name"],
                row["repo_id"],
                row["org_login"],
                json.dumps(row["payload"]),
                row["action"],
                row["ref"],
                row["ref_type"],
                row["push_id"],
                row["head"],
                row["before"],
                row["size"],
                row["distinct_size"],
                row["member_login"],
                row["member_id"],
                row["source_file"],
            )
            for row in rows
        ]
        merge = """
            MERGE INTO GHARCHIVE_EVENTS_HOURLY target
            USING GHARCHIVE_EVENTS_BUFFER source ON target.EVENT_ID = source.EVENT_ID
            WHEN NOT MATCHED THEN INSERT ALL BY NAME
        """
        with self.connection() as connection, connection.cursor() as cursor:
            cursor.execute("TRUNCATE TABLE GHARCHIVE_EVENTS_BUFFER")
            cursor.executemany(insert, values)
            cursor.execute(merge)
            cursor.execute("TRUNCATE TABLE GHARCHIVE_EVENTS_BUFFER")
            connection.commit()

    def merge_github_advisories(
        self, advisories: list[dict[str, Any]], source_name: str = "github"
    ) -> None:
        header_sql = """
            MERGE INTO SECURITY_ADVISORIES target USING (
              SELECT %s SOURCE, %s ADVISORY_ID, %s GHSA_ID, %s CVE_ID, %s SEVERITY,
                     %s SUMMARY, %s DESCRIPTION, %s PUBLISHED_AT, %s UPDATED_AT,
                     %s WITHDRAWN_AT, PARSE_JSON(%s) RAW
            ) source ON target.SOURCE=source.SOURCE AND target.ADVISORY_ID=source.ADVISORY_ID
            WHEN MATCHED THEN UPDATE SET GHSA_ID=source.GHSA_ID, CVE_ID=source.CVE_ID,
              SEVERITY=source.SEVERITY, SUMMARY=source.SUMMARY,
              DESCRIPTION=source.DESCRIPTION, PUBLISHED_AT=source.PUBLISHED_AT,
              UPDATED_AT=source.UPDATED_AT, WITHDRAWN_AT=source.WITHDRAWN_AT,
              RAW=source.RAW, INGESTED_AT=CURRENT_TIMESTAMP()
            WHEN NOT MATCHED THEN INSERT
              (SOURCE, ADVISORY_ID, GHSA_ID, CVE_ID, SEVERITY, SUMMARY, DESCRIPTION,
               PUBLISHED_AT, UPDATED_AT, WITHDRAWN_AT, RAW)
              VALUES (source.SOURCE, source.ADVISORY_ID, source.GHSA_ID, source.CVE_ID,
               source.SEVERITY, source.SUMMARY, source.DESCRIPTION, source.PUBLISHED_AT,
               source.UPDATED_AT, source.WITHDRAWN_AT, source.RAW)
        """
        affected_sql = """
            MERGE INTO ADVISORY_AFFECTED_PACKAGES target USING (
              SELECT %s SOURCE, %s ADVISORY_ID, %s ECOSYSTEM, %s PACKAGE_NAME,
                     %s VULNERABLE_RANGE, %s FIRST_PATCHED_VERSION, PARSE_JSON(%s) RAW
            ) source ON target.SOURCE=source.SOURCE AND target.ADVISORY_ID=source.ADVISORY_ID
              AND target.ECOSYSTEM=source.ECOSYSTEM AND target.PACKAGE_NAME=source.PACKAGE_NAME
              AND target.VULNERABLE_RANGE=source.VULNERABLE_RANGE
            WHEN MATCHED THEN UPDATE SET FIRST_PATCHED_VERSION=source.FIRST_PATCHED_VERSION,
              RAW=source.RAW, INGESTED_AT=CURRENT_TIMESTAMP()
            WHEN NOT MATCHED THEN INSERT
              (SOURCE, ADVISORY_ID, ECOSYSTEM, PACKAGE_NAME, VULNERABLE_RANGE,
               FIRST_PATCHED_VERSION, RAW)
              VALUES (source.SOURCE, source.ADVISORY_ID, source.ECOSYSTEM, source.PACKAGE_NAME,
               source.VULNERABLE_RANGE, source.FIRST_PATCHED_VERSION, source.RAW)
        """
        with self.connection() as connection, connection.cursor() as cursor:
            for advisory in advisories:
                advisory_id = advisory.get("ghsa_id") or advisory.get("cve_id")
                cursor.execute(
                    header_sql,
                    (
                        source_name,
                        advisory_id,
                        advisory.get("ghsa_id"),
                        advisory.get("cve_id"),
                        advisory.get("severity"),
                        advisory.get("summary"),
                        advisory.get("description"),
                        advisory.get("published_at"),
                        advisory.get("updated_at"),
                        advisory.get("withdrawn_at"),
                        json.dumps(advisory),
                    ),
                )
                for vulnerability in advisory.get("vulnerabilities", []):
                    package = vulnerability.get("package") or {}
                    patched = vulnerability.get("first_patched_version") or {}
                    cursor.execute(
                        affected_sql,
                        (
                            source_name,
                            advisory_id,
                            package.get("ecosystem"),
                            package.get("name"),
                            vulnerability.get("vulnerable_version_range"),
                            patched.get("identifier"),
                            json.dumps(vulnerability),
                        ),
                    )
            connection.commit()

    def dependency_packages(self, limit: int = 1000) -> list[SbomPackage]:
        sql = """
            SELECT PACKAGE_NAME, RESOLVED_VERSION, PURL, SPDX_ID
            FROM REPOSITORY_DEPENDENCIES
            QUALIFY ROW_NUMBER() OVER (PARTITION BY PURL, RESOLVED_VERSION ORDER BY OBSERVED_AT DESC)=1
            LIMIT %s
        """
        with self.connection() as connection, connection.cursor() as cursor:
            cursor.execute(sql, (limit,))
            return [
                SbomPackage(name=row[0], version=row[1], purl=row[2], spdx_id=row[3])
                for row in cursor.fetchall()
            ]

    def merge_repository_dependencies(self, repo: str, packages: list[SbomPackage]) -> None:
        sql = """
            MERGE INTO REPOSITORY_DEPENDENCIES target USING (
              SELECT %s REPO_NAME, %s PACKAGE_NAME, %s RESOLVED_VERSION, %s PURL, %s SPDX_ID
            ) source ON target.REPO_NAME=source.REPO_NAME AND target.PURL=source.PURL
              AND COALESCE(target.RESOLVED_VERSION, '')=COALESCE(source.RESOLVED_VERSION, '')
            WHEN MATCHED THEN UPDATE SET OBSERVED_AT=CURRENT_TIMESTAMP(), SPDX_ID=source.SPDX_ID
            WHEN NOT MATCHED THEN INSERT
              (REPO_NAME, PACKAGE_NAME, RESOLVED_VERSION, PURL, SPDX_ID, OBSERVED_AT)
              VALUES (source.REPO_NAME, source.PACKAGE_NAME, source.RESOLVED_VERSION,
                      source.PURL, source.SPDX_ID, CURRENT_TIMESTAMP())
        """
        with self.connection() as connection, connection.cursor() as cursor:
            cursor.executemany(
                sql,
                [(repo, item.name, item.version, item.purl, item.spdx_id) for item in packages],
            )
            connection.commit()

    def merge_osv_results(self, results: list[dict[str, Any]]) -> None:
        advisories = []
        for result in results:
            vulnerability = result["vulnerability"]
            normalized_vulnerabilities: list[dict[str, Any]] = []
            for affected in vulnerability.get("affected", []):
                package = affected.get("package") or {}
                for affected_range in self._osv_ranges(affected.get("ranges", [])):
                    normalized_vulnerabilities.append(
                        {
                            "package": {
                                "ecosystem": package.get("ecosystem"),
                                "name": package.get("name"),
                            },
                            "vulnerable_version_range": affected_range[0],
                            "first_patched_version": {"identifier": affected_range[1]}
                            if affected_range[1]
                            else None,
                        }
                    )
            advisories.append(
                {
                    "ghsa_id": vulnerability.get("id"),
                    "cve_id": next(
                        (
                            alias
                            for alias in vulnerability.get("aliases", [])
                            if alias.startswith("CVE-")
                        ),
                        None,
                    ),
                    "severity": (vulnerability.get("database_specific") or {}).get(
                        "severity", "unknown"
                    ),
                    "summary": vulnerability.get("summary"),
                    "description": vulnerability.get("details"),
                    "published_at": vulnerability.get("published"),
                    "updated_at": vulnerability.get("modified"),
                    "withdrawn_at": vulnerability.get("withdrawn"),
                    "vulnerabilities": normalized_vulnerabilities,
                    "osv": vulnerability,
                }
            )
        self.merge_github_advisories(advisories, source_name="osv")

    @staticmethod
    def _osv_ranges(ranges: list[dict[str, Any]]) -> list[tuple[str, str | None]]:
        normalized: list[tuple[str, str | None]] = []
        for range_item in ranges:
            if range_item.get("type") not in {"ECOSYSTEM", "SEMVER"}:
                continue
            introduced: str | None = None
            for event in range_item.get("events", []):
                if "introduced" in event:
                    introduced = event["introduced"]
                boundary = event.get("fixed") or event.get("last_affected")
                if not boundary:
                    continue
                clauses = [] if introduced in {None, "0"} else [f">={introduced}"]
                clauses.append(("<=" if "last_affected" in event else "<") + boundary)
                normalized.append((", ".join(clauses), event.get("fixed")))
                introduced = None
            if introduced is not None:
                normalized.append((f">={introduced}", None))
        return normalized

    def refresh_risk_scores(self) -> None:
        with self.connection() as connection, connection.cursor() as cursor:
            cursor.execute("CALL REFRESH_RISK_SCORES()")
            connection.commit()

    def refresh_dependency_exposures(self) -> int:
        dependency_sql = """
            SELECT REPO_NAME, PACKAGE_NAME, RESOLVED_VERSION, PURL
            FROM REPOSITORY_DEPENDENCIES
            QUALIFY ROW_NUMBER() OVER (
              PARTITION BY REPO_NAME, PURL, RESOLVED_VERSION ORDER BY OBSERVED_AT DESC
            )=1
        """
        advisory_sql = """
            SELECT p.SOURCE, p.ADVISORY_ID, p.ECOSYSTEM, p.PACKAGE_NAME,
                   p.VULNERABLE_RANGE, COALESCE(a.SEVERITY, 'unknown')
            FROM ADVISORY_AFFECTED_PACKAGES p
            LEFT JOIN SECURITY_ADVISORIES a
              ON a.SOURCE=p.SOURCE AND a.ADVISORY_ID=p.ADVISORY_ID
        """
        with self.connection() as connection, connection.cursor() as cursor:
            cursor.execute(dependency_sql)
            dependencies = cursor.fetchall()
            cursor.execute(advisory_sql)
            advisories = cursor.fetchall()
            rows: list[tuple[object, ...]] = []
            for repo, package_name, version, purl in dependencies:
                purl_ecosystem = ""
                if purl and str(purl).startswith("pkg:"):
                    purl_ecosystem = str(purl).split(":", 1)[1].split("/", 1)[0]
                for (
                    source,
                    advisory_id,
                    ecosystem,
                    affected_name,
                    affected_range,
                    severity,
                ) in advisories:
                    normalized_ecosystem = canonical_ecosystem(str(ecosystem or purl_ecosystem))
                    if (
                        purl_ecosystem
                        and canonical_ecosystem(purl_ecosystem) != normalized_ecosystem
                    ):
                        continue
                    if normalize_package_name(
                        normalized_ecosystem, str(package_name)
                    ) != normalize_package_name(normalized_ecosystem, str(affected_name)):
                        continue
                    match = version_is_affected(
                        normalized_ecosystem,
                        str(version) if version else None,
                        str(affected_range or ""),
                    )
                    if match.vulnerable:
                        rows.append(
                            (
                                repo,
                                package_name,
                                version,
                                normalized_ecosystem,
                                source,
                                advisory_id,
                                severity,
                                "confirmed_vulnerable",
                                match.reason,
                            )
                        )
            cursor.execute("TRUNCATE TABLE REPOSITORY_DEPENDENCY_EXPOSURES")
            if rows:
                cursor.executemany(
                    """
                    INSERT INTO REPOSITORY_DEPENDENCY_EXPOSURES (
                      REPO_NAME, PACKAGE_NAME, RESOLVED_VERSION, ECOSYSTEM,
                      ADVISORY_SOURCE, ADVISORY_ID, SEVERITY, MATCH_STATUS, MATCH_REASON
                    ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
                    """,
                    rows,
                )
            connection.commit()
        return len(rows)
