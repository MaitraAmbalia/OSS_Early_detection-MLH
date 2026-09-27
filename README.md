# Sentinel OSS

Sentinel OSS is a GitHub-first dependency security monitor. A user connects a fine-grained, read-only GitHub token, selects a repository they can access, and receives its current dependency inventory and open Dependabot vulnerability alerts.

The active application does not generate mock findings and does not use GH Archive or OSV. Repository access, dependency data, and vulnerability results come directly from GitHub.

The current version performs on-demand snapshots when a user selects or rescans a repository. It does not claim to provide continuous background monitoring; that requires a hosted GitHub App, webhooks, scheduled rescans, and persistent storage.

Contributor trust is repository-scoped. A score of `100` means none of the configured behavioral
risk signals appeared in GitHub's available recent event window; it is not identity verification,
a global reputation score, or proof that a person is safe. Snowflake is not presented as the live
source until a deployment configures persistence and event ingestion.

## Genuine data flow

1. The backend validates the credential with GitHub.
2. GitHub returns repositories that the authenticated user can access.
3. The selected repository's Dependency Graph is exported as an SPDX SBOM. If the SBOM is
   unavailable, Sentinel reads supported committed lockfiles and manifests through GitHub's
   Contents API and labels the fallback in the dashboard.
4. Open Dependabot alerts provide affected packages, severity, vulnerable ranges, and GHSA identifiers.
5. Sentinel assigns a transparent display score based on the highest open alert severity. It does not claim that this score is a statistical probability.
6. The contributor view reads GitHub's recent repository events and applies the matching
   behavioral formulas represented in the Snowflake SQL: fast activity after collaborator access
   and suspicious commit metadata. Cross-repository burst detection is reserved for a deployment
   with persisted events from multiple connected repositories.

If Dependency Graph, Dependabot alerts, or the required permission is unavailable, the dashboard shows that limitation. It never substitutes representative vulnerabilities.

## Technology

- **Frontend:** React 19, TypeScript, Vinext/Vite, Tailwind CSS, and shadcn/ui.
- **Backend:** Python 3.11+, FastAPI, Pydantic, HTTPX, and Uvicorn.
- **GitHub:** authenticated repository listing, Dependency Graph/SBOM, and Dependabot alerts.
- **Optional warehouse:** Snowflake stores scan runs, dependency and alert snapshots, normalized
  GitHub events, contributor scores, and signed webhook deliveries. Idempotent `MERGE` operations,
  `VARIANT`, clustered event storage, views, and stored procedures support historical scoring.

## Run locally

### Requirements

- Node.js 22.13 or newer
- npm
- Python 3.11 or newer
- A fine-grained GitHub personal access token

### 1. Clone and install the frontend

```powershell
git clone https://github.com/MaitraAmbalia/OSS_Early_detection-MLH.git
cd OSS_Early_detection-MLH
npm ci
Copy-Item .env.example .env.local
```

### 2. Install and start the backend

In the first PowerShell terminal:

```powershell
cd backend
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
Copy-Item .env.example .env
python -m uvicorn app.main:app --reload --port 8000
```

### 3. Start the frontend

In a second PowerShell terminal, from the repository root:

```powershell
npm run dev
```

Open `http://localhost:5173` and complete the GitHub onboarding screen.

On macOS or Linux, use `python3 -m venv .venv`, `source .venv/bin/activate`, and `cp` in place of the PowerShell-specific commands.

## GitHub credential setup

Create a fine-grained token at `https://github.com/settings/personal-access-tokens/new` and grant access only to repositories you want Sentinel to monitor.

Required repository permissions:

- **Metadata:** read
- **Contents:** read
- **Dependabot alerts:** read

The onboarding credential is kept only in the current browser tab's memory. The frontend sends it to the local FastAPI service in the `X-GitHub-Token` request header. The backend does not persist or log request headers or bodies.

For unattended local use, `GITHUB_TOKEN` can instead be set in the ignored `backend/.env` file. Never place a real token in `.env.example` or commit it.

## Environment variables

### Frontend (`.env.local`)

| Variable | Default | Purpose |
| --- | --- | --- |
| `NEXT_PUBLIC_API_BASE_URL` | `http://127.0.0.1:8000` | Local FastAPI URL. |

### Backend (`backend/.env`)

| Variable | Default | Purpose |
| --- | --- | --- |
| `APP_ENV` | `development` | Runtime environment label. |
| `DATA_MODE` | `github` | Use `github` for onboarding and live scans; `snowflake` enables stored analytics endpoints. |
| `CORS_ORIGINS` | `http://localhost:5173` | Comma-separated frontend origins. |
| `GITHUB_TOKEN` | empty | Optional server-side GitHub credential fallback. |
| `GITHUB_WEBHOOK_SECRET` | empty | Secret used to validate `X-Hub-Signature-256` webhook signatures. |
| `SNOWFLAKE_PERSISTENCE_ENABLED` | `false` | Store scans and events in Snowflake when enabled. |
| `SNOWFLAKE_*` | placeholders | Snowflake account, key-pair, role, warehouse, database, and schema. |

## Enable Snowflake persistence

Persistence is off by default, so local development never pretends data was stored.

1. Run `backend/sql/001_schema.sql`, `002_detection.sql`, `003_access.sql`, and
   `004_github_warehouse.sql` in order.
2. Register the matching RSA public key on `INGESTION_SVC` in Snowflake; keep the private `.p8`
   file outside the repository.
3. Create an ignored `backend/.env`; set `SNOWFLAKE_PERSISTENCE_ENABLED=true` and the real
   `SNOWFLAKE_*` key-pair values locally or through deployment secrets.
4. Restart the backend and confirm `GET /api/v1/warehouse/status` returns `ready`.
5. For continuous collection, configure a GitHub App or repository webhook to send at least
   `push` and `member` events to `POST /api/v1/github/webhooks`. Set the same random secret as
   `GITHUB_WEBHOOK_SECRET` in both GitHub and the backend.

On-demand scans persist complete dependency inventories, alert payloads, repository metadata, and
contributor snapshots. Webhook delivery IDs and GitHub event IDs are merged idempotently so retries
do not create duplicate events. Webhook ingestion refreshes the Snowflake contributor scoring
procedure, including cross-repository burst detection once multiple connected repositories supply
events.

## API

- `GET /health`
- `POST /api/v1/github/validate`
- `GET /api/v1/github/repositories`
- `POST /api/v1/repositories/{owner}/{repo}/analyze`
- `GET /api/v1/repositories/{owner}/{repo}/contributors/trust`
- `GET /api/v1/warehouse/status`
- `POST /api/v1/github/webhooks`

The GitHub endpoints require `X-GitHub-Token` unless `GITHUB_TOKEN` is configured locally.

## Validate changes

```powershell
npm run lint
.\node_modules\.bin\tsc.cmd --noEmit
npm run build

cd backend
python -m pytest
python -m ruff check .
```

## Production authentication

Fine-grained token onboarding makes the project easy to run locally. A hosted multi-user deployment should use a GitHub App installation flow so users can select repositories and revoke access without pasting a personal token into the application.
