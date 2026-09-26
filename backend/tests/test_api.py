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


def test_findings_filter() -> None:
    response = client.get("/api/v1/findings?severity=critical")
    assert response.status_code == 200
    assert all(item["risk_level"] == "critical" for item in response.json()["items"])


def test_repository_risk() -> None:
    response = client.get("/api/v1/repositories/acme/checkout-sdk/risk")
    assert response.status_code == 200
    assert response.json()["repo"] == "acme/checkout-sdk"
