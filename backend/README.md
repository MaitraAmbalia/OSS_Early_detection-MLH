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

The service logs only request method, route, and response status. It does not log headers or bodies.

When `DATA_MODE=snowflake`, the stored analytics endpoints and SQL contracts in `sql/` are also available for hosted historical monitoring.
