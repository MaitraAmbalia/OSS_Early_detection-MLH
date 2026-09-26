# Sentinel OSS

Sentinel OSS is a GitHub-first dependency security monitor. A user connects a fine-grained, read-only GitHub token, selects a repository they can access, and receives its current dependency inventory and open Dependabot vulnerability alerts.

The active application does not generate mock findings and does not use GH Archive or OSV. Repository access, dependency data, and vulnerability results come directly from GitHub.

The current version performs on-demand snapshots when a user selects or rescans a repository. It does not claim to provide continuous background monitoring; that requires a hosted GitHub App, webhooks, scheduled rescans, and persistent storage.

## Genuine data flow

1. The backend validates the credential with GitHub.
2. GitHub returns repositories that the authenticated user can access.
3. The selected repository's Dependency Graph is exported as an SPDX SBOM.
4. Open Dependabot alerts provide affected packages, severity, vulnerable ranges, and GHSA identifiers.
5. Sentinel assigns a transparent display score based on the highest open alert severity. It does not claim that this score is a statistical probability.

If Dependency Graph, Dependabot alerts, or the required permission is unavailable, the dashboard shows that limitation. It never substitutes representative vulnerabilities.

## Technology

- **Frontend:** React 19, TypeScript, Vinext/Vite, Tailwind CSS, and shadcn/ui.
- **Backend:** Python 3.11+, FastAPI, Pydantic, HTTPX, and Uvicorn.
- **GitHub:** authenticated repository listing, Dependency Graph/SBOM, and Dependabot alerts.
- **Optional storage:** Snowflake tables, roles, warehouses, `VARIANT`, `MERGE`, views, and stored procedures remain available for a hosted deployment that needs historical snapshots.

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
| `SNOWFLAKE_*` | placeholders | Optional hosted-storage configuration. |

## API

- `GET /health`
- `POST /api/v1/github/validate`
- `GET /api/v1/github/repositories`
- `POST /api/v1/repositories/{owner}/{repo}/analyze`

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
