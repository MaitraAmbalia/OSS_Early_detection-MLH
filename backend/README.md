# Sentinel OSS API

FastAPI service for the analytics dashboard. It keeps browser clients away from Snowflake credentials and uses GitHub tokens only for the lifetime of one request.

## Local development

```powershell
cd backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e ".[dev]"
Copy-Item .env.example .env
uvicorn app.main:app --reload --port 8000
```

The default `DATA_MODE=mock` serves stable dashboard data without external credentials. Set `DATA_MODE=snowflake` after configuring the read-only Snowflake role and private key.

## API

- `GET /health`
- `GET /api/v1/dashboard/overview`
- `GET /api/v1/findings?severity=critical&limit=50`
- `GET /api/v1/repositories/{owner}/{repo}/risk`
- `POST /api/v1/github/validate`
- `POST /api/v1/repositories/{owner}/{repo}/analyze`

Send an optional fine-grained GitHub token in `X-GitHub-Token`. The service does not persist or log the header.

## Snowflake contract

The backend currently expects:

- `CHECK_REPO_RISK(repo, start, end)` returning the agreed VARIANT contract.
- `RISK_SCORES` for the investigation queue.
- `GET_DASHBOARD_OVERVIEW(start, end)` returning the `DashboardOverview` JSON shape. This procedure still needs to be finalized with CoCo.

## Snowflake setup and ingestion

Run `sql/001_schema.sql`, `sql/002_detection.sql`, and `sql/003_access.sql` in order.
The checkpointed ingestion CLI is:

```powershell
python -m app.cli ingest --sources all --lookback-hours 3
```

GitHub Actions runs GH Archive hourly and refreshes advisories/OSV daily. Required
repository secrets are documented in `.github/workflows/ingest.yml`.
