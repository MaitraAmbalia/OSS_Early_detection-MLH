# Sentinel OSS API

FastAPI service for GitHub repository onboarding, Dependency Graph/SBOM retrieval, and Dependabot vulnerability alerts.

## Local development

```powershell
cd backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
Copy-Item .env.example .env
python -m uvicorn app.main:app --reload --port 8000
```

The default `DATA_MODE=github` serves no generated findings. Send a fine-grained credential in `X-GitHub-Token`, or set `GITHUB_TOKEN` in the ignored local `.env` file.

Required fine-grained repository permissions are Metadata read, Contents read, and Dependabot alerts read.

## Active endpoints

- `GET /health`
- `POST /api/v1/github/validate`
- `GET /api/v1/github/repositories`
- `POST /api/v1/repositories/{owner}/{repo}/analyze`
- `GET /api/v1/repositories/{owner}/{repo}/contributors/trust`
- `GET /api/v1/warehouse/status`
- `POST /api/v1/github/webhooks`

Contributor scoring uses authenticated GitHub contributor and repository-event data with the
same behavioral formulas mirrored by `sql/002_detection.sql`. The response labels the algorithm
and coverage window. It is an on-demand repository assessment, not a global judgment about a user.

The service logs only request method, route, and response status. It does not log headers or bodies.

When `DATA_MODE=snowflake`, the stored analytics endpoints and SQL contracts in `sql/` are also available for hosted historical monitoring.

## Snowflake warehouse persistence

Run the four SQL files in `sql/` in numeric order, then configure the ignored `.env`:

Register the matching RSA public key on the generated `INGESTION_SVC` Snowflake user and keep the
private `.p8` file outside this repository. The API uses key-pair authentication; no Snowflake
password is read or stored.

```dotenv
SNOWFLAKE_PERSISTENCE_ENABLED=true
SNOWFLAKE_ACCOUNT=your_org-your_account
SNOWFLAKE_USER=INGESTION_SVC
SNOWFLAKE_ROLE=INGESTION_ROLE
SNOWFLAKE_WAREHOUSE=INGEST_WH
SNOWFLAKE_PRIVATE_KEY_FILE=/absolute/path/to/key.p8
GITHUB_WEBHOOK_SECRET=replace_with_a_random_deployment_secret
```

No real values belong in `.env.example` or Git. `DATA_MODE=github` can remain unchanged;
warehouse persistence is independently controlled by `SNOWFLAKE_PERSISTENCE_ENABLED`.

`GET /api/v1/warehouse/status` checks configuration and connectivity. Repository analysis stores
metadata, the full dependency inventory, and raw Dependabot alerts. Contributor analysis stores
the recent repository-event window and contributor score snapshots. `POST /api/v1/github/webhooks`
verifies GitHub's SHA-256 signature, deduplicates deliveries and events, and refreshes contributor
scoring in Snowflake.
