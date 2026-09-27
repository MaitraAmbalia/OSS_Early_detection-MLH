import json
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

import snowflake.connector
from cryptography.hazmat.primitives import serialization
from snowflake.connector.errors import ProgrammingError

from app.config import Settings
from app.domain.versions import canonical_ecosystem, normalize_package_name, version_is_affected
from app.models import (
    ContributorTrustPage,
    DashboardOverview,
    FindingsPage,
    Metric,
    PipelineSource,
    RepositoryAnalysis,
    RepositoryRisk,
    SbomPackage,
    SignalShare,
    TrendPoint,
)


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

    def healthcheck(self) -> None:
        with self.connection() as connection, connection.cursor() as cursor:
            cursor.execute("SELECT 1")
            cursor.fetchone()

    @staticmethod
    def _json(value: object) -> str:
        return json.dumps(value, default=str)

    @staticmethod
    def _decode_variant(value: object) -> dict[str, Any]:
        if isinstance(value, dict):
            return value
        if isinstance(value, str):
            return json.loads(value)
        raise ValueError("Snowflake procedure returned an unsupported payload")

    @staticmethod
    def _decode_timestamp(value: object) -> datetime:
        if isinstance(value, datetime):
            return value
        if isinstance(value, str):
            normalized = value.strip().replace("Z", "+00:00")
            date_time, separator, offset = normalized.rpartition(" ")
            if separator and offset[:1] in {"+", "-"}:
                normalized = date_time.replace(" ", "T", 1) + offset
            return datetime.fromisoformat(normalized)
        return datetime.now(UTC)

    def repository_risk(self, repo: str, start: datetime, end: datetime) -> RepositoryRisk:
        sql = "CALL CHECK_REPO_RISK(%s, %s, %s)"
        with self.connection() as connection, connection.cursor() as cursor:
            cursor.execute(sql, (repo, start.date().isoformat(), end.date().isoformat()))
            row = cursor.fetchone()
        if not row:
            raise LookupError(f"No risk result found for {repo}")
        payload = self._decode_variant(row[0])
        if not payload:
            raise LookupError(f"No risk result found for {repo}")

        # Normalize both the current API contract and the historical procedure
        # contract already deployed in the hackathon Snowflake account.
        metadata = payload.get("metadata") or {}
        blast_radius = payload.get("blast_radius") or {}
        if isinstance(blast_radius, dict):
            blast_radius = blast_radius.get("repos_touched_by_actor") or []
        payload["risk_level"] = str(payload.get("risk_level", "low")).lower()
        payload["window_start"] = payload.get("window_start") or start
        payload["window_end"] = payload.get("window_end") or end
        payload["computed_at"] = self._decode_timestamp(
            payload.get("computed_at") or metadata.get("computed_at")
        )
        payload["data_sources"] = payload.get("data_sources") or ["gharchive_hourly"]
        payload["blast_radius_repos"] = payload.get("blast_radius_repos") or blast_radius
        payload["dependency_exposures"] = payload.get("dependency_exposures") or []
        return RepositoryRisk.model_validate(payload)

    def overview(self, start: datetime, end: datetime) -> DashboardOverview:
        metrics_sql = """
            SELECT COUNT_IF(UPPER(RISK_LEVEL) = 'CRITICAL'),
                   COUNT(DISTINCT REPO_NAME), COUNT(DISTINCT ACTOR_LOGIN)
            FROM RISK_SCORES
            WHERE COMPUTED_AT BETWEEN %s AND %s
        """
        trend_sql = """
            SELECT DATE_TRUNC('hour', COMPUTED_AT), LEAST(100, MAX(COMPOSITE_SCORE))
            FROM RISK_SCORES
            WHERE COMPUTED_AT BETWEEN %s AND %s
            GROUP BY 1 ORDER BY 1
        """
        signals_sql = """
            SELECT f.value::STRING, COUNT(*)
            FROM RISK_SCORES r, LATERAL FLATTEN(INPUT => r.SIGNALS_FIRED) f
            WHERE r.COMPUTED_AT BETWEEN %s AND %s
            GROUP BY 1 ORDER BY 2 DESC
        """
        exposure_sql = """
            SELECT COUNT(*) FROM REPOSITORY_DEPENDENCY_EXPOSURES
            WHERE LOWER(MATCH_STATUS) = 'confirmed_vulnerable'
        """
        pipeline_sql = """
            SELECT SOURCE_KEY, MAX(COMPLETED_AT)
            FROM INGESTION_CHECKPOINTS
            WHERE STATUS = 'completed'
            GROUP BY SOURCE_KEY
        """
        with self.connection() as connection, connection.cursor() as cursor:
            critical, repositories, actors = cursor.execute(
                metrics_sql, (start, end)
            ).fetchone()
            trend_rows = cursor.execute(trend_sql, (start, end)).fetchall()
            signal_rows = cursor.execute(signals_sql, (start, end)).fetchall()
            exposed = cursor.execute(exposure_sql).fetchone()[0]
            try:
                checkpoint_rows = cursor.execute(pipeline_sql).fetchall()
            except ProgrammingError:
                # Historical deployments predate the checkpoint table. The
                # analytics remain usable while pipeline status stays unknown.
                checkpoint_rows = []

        signal_total = sum(int(row[1]) for row in signal_rows)
        checkpoints: dict[str, datetime] = {}
        for source_key, completed_at in checkpoint_rows:
            source = str(source_key).split(":", 1)[0]
            if source not in checkpoints or completed_at > checkpoints[source]:
                checkpoints[source] = completed_at

        now = datetime.now(UTC)
        pipeline_specs = (
            ("gharchive", "hourly"),
            ("github_advisories", "daily"),
            ("osv_queries", "daily"),
        )
        pipeline = []
        for source, cadence in pipeline_specs:
            last_success = checkpoints.get(source)
            max_age = 3 * 3600 if cadence == "hourly" else 36 * 3600
            if last_success is None:
                status = "unknown"
            else:
                if last_success.tzinfo is None:
                    last_success = last_success.replace(tzinfo=UTC)
                status = "healthy" if (now - last_success).total_seconds() <= max_age else "delayed"
            pipeline.append(
                PipelineSource(
                    source="osv" if source == "osv_queries" else source,
                    last_success_at=last_success,
                    cadence=cadence,
                    status=status,
                )
            )

        return DashboardOverview(
            metrics=[
                Metric(label="Critical findings", value=int(critical or 0), note="selected window"),
                Metric(label="Repos monitored", value=int(repositories or 0), note="selected window"),
                Metric(label="Exposed packages", value=int(exposed or 0), note="confirmed"),
                Metric(label="Active actors", value=int(actors or 0), note="flagged"),
            ],
            trend=[TrendPoint(timestamp=row[0], score=float(row[1])) for row in trend_rows],
            signal_distribution=[
                SignalShare(
                    signal=str(row[0]),
                    percentage=round(100 * int(row[1]) / signal_total, 1),
                )
                for row in signal_rows
            ] if signal_total else [],
            pipeline=pipeline,
            generated_at=now,
        )

    def findings(self, level: str | None, limit: int) -> FindingsPage:
        where = "WHERE RISK_LEVEL = %s" if level else ""
        params: tuple[object, ...] = (level.upper(), limit) if level else (limit,)
        sql = f"""
            SELECT RISK_ID, REPO_NAME, ACTOR_LOGIN, COMPOSITE_SCORE, LOWER(RISK_LEVEL),
                   SIGNALS_FIRED[0]::STRING, AI_EXPLANATION, SIGNALS_FIRED,
                   COMPUTED_AT, DATA_SOURCES
            FROM RISK_SCORES
            {where}
            ORDER BY COMPOSITE_SCORE DESC, COMPUTED_AT DESC
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

    def persist_repository_snapshot(
        self,
        repository: dict[str, Any],
        analysis: RepositoryAnalysis,
        packages: list[SbomPackage],
        alerts: list[dict[str, Any]],
    ) -> str:
        scan_id = str(uuid4())
        repo_name = analysis.repository
        repository_sql = """
            MERGE INTO GITHUB_REPOSITORIES target
            USING (SELECT %s REPO_NAME, %s DEFAULT_BRANCH, %s VISIBILITY,
                          PARSE_JSON(%s) RAW) source
              ON target.REPO_NAME=source.REPO_NAME
            WHEN MATCHED THEN UPDATE SET DEFAULT_BRANCH=source.DEFAULT_BRANCH,
                 VISIBILITY=source.VISIBILITY, RAW=source.RAW,
                 LAST_SEEN_AT=CURRENT_TIMESTAMP()
            WHEN NOT MATCHED THEN INSERT
                 (REPO_NAME, DEFAULT_BRANCH, VISIBILITY, RAW, FIRST_SEEN_AT, LAST_SEEN_AT)
                 VALUES (source.REPO_NAME, source.DEFAULT_BRANCH, source.VISIBILITY,
                         source.RAW, CURRENT_TIMESTAMP(), CURRENT_TIMESTAMP())
        """
        scan_sql = """
            INSERT INTO GITHUB_SCAN_RUNS (
              SCAN_ID, REPO_NAME, DEPENDENCY_SOURCE, DEPENDENCY_COUNT,
              VULNERABILITY_STATUS, OPEN_ALERT_COUNT, REPOSITORY_RISK_SCORE, RAW
            ) SELECT %s,%s,%s,%s,%s,%s,%s,PARSE_JSON(%s)
        """
        dependency_sql = """
            INSERT INTO GITHUB_DEPENDENCY_SNAPSHOTS (
              SCAN_ID, REPO_NAME, PACKAGE_NAME, RESOLVED_VERSION, PURL, SPDX_ID
            ) VALUES (%s,%s,%s,%s,%s,%s)
        """
        alert_sql = """
            INSERT INTO GITHUB_ALERT_SNAPSHOTS (
              SCAN_ID, REPO_NAME, ALERT_NUMBER, GHSA_ID, CLASSIFICATION,
              SEVERITY, PACKAGE_NAME, STATE, RAW
            ) SELECT %s,%s,%s,%s,%s,%s,%s,%s,PARSE_JSON(%s)
        """
        with self.connection() as connection, connection.cursor() as cursor:
            cursor.execute(
                repository_sql,
                (
                    repo_name,
                    analysis.default_branch,
                    analysis.visibility,
                    self._json(repository),
                ),
            )
            cursor.execute(
                scan_sql,
                (
                    scan_id,
                    repo_name,
                    analysis.dependency_source,
                    analysis.dependency_count,
                    analysis.vulnerability_status,
                    len(alerts),
                    analysis.risk.composite_score,
                    self._json(analysis.model_dump(mode="json")),
                ),
            )
            if packages:
                cursor.executemany(
                    dependency_sql,
                    [
                        (scan_id, repo_name, item.name, item.version, item.purl, item.spdx_id)
                        for item in packages
                    ],
                )
            for alert in alerts:
                advisory = alert.get("security_advisory") or {}
                dependency = alert.get("dependency") or {}
                package = dependency.get("package") if isinstance(dependency, dict) else {}
                if not isinstance(advisory, dict):
                    advisory = {}
                if not isinstance(package, dict):
                    package = {}
                cursor.execute(
                    alert_sql,
                    (
                        scan_id,
                        repo_name,
                        alert.get("number"),
                        advisory.get("ghsa_id"),
                        advisory.get("classification") or "general",
                        advisory.get("severity"),
                        package.get("name"),
                        alert.get("state"),
                        self._json(alert),
                    ),
                )
            connection.commit()
        return scan_id

    @staticmethod
    def _event_row(
        repo_name: str,
        event: dict[str, Any],
        source: str,
    ) -> tuple[object, ...] | None:
        actor = event.get("actor") or event.get("sender") or {}
        payload = event.get("payload") if isinstance(event.get("payload"), dict) else event
        member = payload.get("member") or {}
        created_at = (
            event.get("created_at")
            or (payload.get("head_commit") or {}).get("timestamp")
            or datetime.now(UTC)
        )
        event_id = event.get("id") or event.get("delivery_id")
        event_type = event.get("type") or event.get("event_type")
        if not event_id or not event_type:
            return None
        return (
            str(event_id),
            repo_name,
            str(event_type),
            actor.get("login") if isinstance(actor, dict) else None,
            payload.get("action"),
            member.get("login") if isinstance(member, dict) else None,
            created_at,
            source,
            SnowflakeRepository._json(payload),
        )

    @staticmethod
    def _merge_events(cursor: Any, rows: list[tuple[object, ...]]) -> None:
        sql = """
            MERGE INTO GITHUB_REPOSITORY_EVENTS target
            USING (SELECT %s EVENT_ID,%s REPO_NAME,%s EVENT_TYPE,%s ACTOR_LOGIN,
                          %s ACTION,%s MEMBER_LOGIN,%s EVENT_CREATED_AT,%s SOURCE,
                          PARSE_JSON(%s) PAYLOAD) source
              ON target.EVENT_ID=source.EVENT_ID AND target.REPO_NAME=source.REPO_NAME
            WHEN MATCHED THEN UPDATE SET PAYLOAD=source.PAYLOAD,
                 INGESTED_AT=CURRENT_TIMESTAMP()
            WHEN NOT MATCHED THEN INSERT
                 (EVENT_ID,REPO_NAME,EVENT_TYPE,ACTOR_LOGIN,ACTION,MEMBER_LOGIN,
                  EVENT_CREATED_AT,SOURCE,PAYLOAD)
                 VALUES (source.EVENT_ID,source.REPO_NAME,source.EVENT_TYPE,
                         source.ACTOR_LOGIN,source.ACTION,source.MEMBER_LOGIN,
                         source.EVENT_CREATED_AT,source.SOURCE,source.PAYLOAD)
        """
        for row in rows:
            cursor.execute(sql, row)

    def persist_contributor_snapshot(
        self,
        repo_name: str,
        events: list[dict[str, Any]],
        page: ContributorTrustPage,
    ) -> str:
        score_id = str(uuid4())
        rows = [
            row
            for event in events
            if (row := self._event_row(repo_name, event, "github_repository_events"))
        ]
        score_sql = """
            INSERT INTO GITHUB_CONTRIBUTOR_TRUST_SNAPSHOTS (
              SCORE_ID,REPO_NAME,ACTOR_LOGIN,CONTRIBUTIONS,OBSERVED_EVENTS,
              RISK_SCORE,TRUST_SCORE,RISK_LEVEL,SIGNALS,WINDOW_START,WINDOW_END,SOURCE
            ) SELECT %s,%s,%s,%s,%s,%s,%s,%s,PARSE_JSON(%s),%s,%s,%s
        """
        with self.connection() as connection, connection.cursor() as cursor:
            self._merge_events(cursor, rows)
            for item in page.items:
                cursor.execute(
                    score_sql,
                    (
                        score_id,
                        repo_name,
                        item.login,
                        item.contributions,
                        item.observed_events,
                        item.risk_score,
                        item.trust_score,
                        item.risk_level,
                        self._json([signal.model_dump(mode="json") for signal in item.signals]),
                        page.computed_at - timedelta(days=page.window_days),
                        page.computed_at,
                        page.source,
                    ),
                )
            connection.commit()
        return score_id

    def persist_webhook_delivery(
        self,
        delivery_id: str,
        event_type: str,
        payload: dict[str, Any],
    ) -> None:
        repository = payload.get("repository") or {}
        repo_name = str(repository.get("full_name") or "")
        delivery_sql = """
            MERGE INTO GITHUB_WEBHOOK_DELIVERIES target
            USING (SELECT %s DELIVERY_ID,%s EVENT_TYPE,%s REPO_NAME,
                          PARSE_JSON(%s) PAYLOAD) source
              ON target.DELIVERY_ID=source.DELIVERY_ID
            WHEN NOT MATCHED THEN INSERT (DELIVERY_ID,EVENT_TYPE,REPO_NAME,PAYLOAD)
                 VALUES (source.DELIVERY_ID,source.EVENT_TYPE,source.REPO_NAME,source.PAYLOAD)
        """
        github_type = {
            "push": "PushEvent",
            "member": "MemberEvent",
        }.get(event_type, event_type)
        event = {
            "delivery_id": delivery_id,
            "event_type": github_type,
            "sender": payload.get("sender") or {},
            **payload,
        }
        row = self._event_row(repo_name, event, "github_webhook") if repo_name else None
        with self.connection() as connection, connection.cursor() as cursor:
            cursor.execute(
                delivery_sql,
                (delivery_id, event_type, repo_name or None, self._json(payload)),
            )
            if row:
                self._merge_events(cursor, [row])
                cursor.execute("CALL REFRESH_GITHUB_CONTRIBUTOR_TRUST()")
            connection.commit()
