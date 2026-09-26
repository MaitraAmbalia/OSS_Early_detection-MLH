from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_health() -> None:
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["data_mode"] == "mock"


def test_overview() -> None:
    response = client.get("/api/v1/dashboard/overview")
    assert response.status_code == 200
    assert len(response.json()["metrics"]) == 4


def test_overview_accepts_naive_datetime() -> None:
    response = client.get("/api/v1/dashboard/overview?start=2026-01-01T00:00:00")
    assert response.status_code == 200


def test_overview_rejects_reversed_window() -> None:
    response = client.get(
        "/api/v1/dashboard/overview"
        "?start=2026-02-01T00:00:00Z&end=2026-01-01T00:00:00Z"
    )
    assert response.status_code == 422
    assert response.json()["detail"] == "start must be before end"


def test_findings_filter() -> None:
    response = client.get("/api/v1/findings?severity=critical")
    assert response.status_code == 200
    assert all(item["risk_level"] == "critical" for item in response.json()["items"])


def test_repository_risk() -> None:
    response = client.get("/api/v1/repositories/acme/checkout-sdk/risk")
    assert response.status_code == 200
    assert response.json()["repo"] == "acme/checkout-sdk"
