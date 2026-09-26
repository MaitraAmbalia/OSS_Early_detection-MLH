from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_health() -> None:
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["data_mode"] == "github"


def test_aggregate_overview_requires_snowflake() -> None:
    response = client.get("/api/v1/dashboard/overview")
    assert response.status_code == 409


def test_overview_accepts_naive_datetime() -> None:
    response = client.get("/api/v1/dashboard/overview?start=2026-01-01T00:00:00")
    assert response.status_code == 409


def test_overview_rejects_reversed_window() -> None:
    response = client.get(
        "/api/v1/dashboard/overview"
        "?start=2026-02-01T00:00:00Z&end=2026-01-01T00:00:00Z"
    )
    assert response.status_code == 422
    assert response.json()["detail"] == "start must be before end"


def test_findings_require_snowflake() -> None:
    response = client.get("/api/v1/findings?severity=critical")
    assert response.status_code == 409


def test_stored_repository_risk_requires_snowflake() -> None:
    response = client.get("/api/v1/repositories/acme/checkout-sdk/risk")
    assert response.status_code == 409


def test_github_onboarding_requires_token() -> None:
    assert client.post("/api/v1/github/validate").status_code == 401
    assert client.get("/api/v1/github/repositories").status_code == 401
    assert client.post("/api/v1/repositories/acme/example/analyze").status_code == 401
