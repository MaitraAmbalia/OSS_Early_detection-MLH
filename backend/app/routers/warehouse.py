import hashlib
import hmac
import json
from typing import Annotated

from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from starlette.concurrency import run_in_threadpool

from app.config import Settings
from app.dependencies import settings_dependency
from app.models import WarehouseHealth
from app.services.snowflake import SnowflakeRepository

router = APIRouter(prefix="/api/v1", tags=["warehouse"])
SettingsDep = Annotated[Settings, Depends(settings_dependency)]


def valid_webhook_signature(body: bytes, signature: str | None, secret: str) -> bool:
    if not signature or not signature.startswith("sha256="):
        return False
    expected = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)


@router.get("/warehouse/status", response_model=WarehouseHealth)
async def warehouse_status(settings: SettingsDep) -> WarehouseHealth:
    if not settings.snowflake_persistence_enabled:
        return WarehouseHealth(
            status="disabled",
            configured=settings.snowflake_configured,
            persistence_enabled=False,
            message="Snowflake persistence is disabled",
        )
    if not settings.snowflake_configured:
        return WarehouseHealth(
            status="failed",
            configured=False,
            persistence_enabled=True,
            message="Snowflake persistence is enabled but required credentials are missing",
        )
    try:
        await run_in_threadpool(SnowflakeRepository(settings).healthcheck)
    except Exception:  # noqa: BLE001 - status must collapse connector/key failures safely
        return WarehouseHealth(
            status="failed",
            configured=True,
            persistence_enabled=True,
            message="Snowflake connection failed",
        )
    return WarehouseHealth(
        status="ready",
        configured=True,
        persistence_enabled=True,
        message="Snowflake is ready to persist scans and events",
    )


@router.post("/github/webhooks", status_code=status.HTTP_202_ACCEPTED)
async def github_webhook(
    request: Request,
    settings: SettingsDep,
    x_hub_signature_256: Annotated[str | None, Header()] = None,
    x_github_event: Annotated[str | None, Header()] = None,
    x_github_delivery: Annotated[str | None, Header()] = None,
) -> dict[str, str]:
    if not settings.snowflake_persistence_enabled:
        raise HTTPException(status_code=503, detail="Snowflake persistence is disabled")
    if not settings.github_webhook_secret:
        raise HTTPException(status_code=503, detail="GitHub webhook secret is not configured")
    body = await request.body()
    if not valid_webhook_signature(body, x_hub_signature_256, settings.github_webhook_secret):
        raise HTTPException(status_code=401, detail="Invalid GitHub webhook signature")
    if not x_github_event or not x_github_delivery:
        raise HTTPException(status_code=400, detail="Missing GitHub webhook headers")
    try:
        payload = json.loads(body)
    except json.JSONDecodeError as error:
        raise HTTPException(status_code=400, detail="Invalid webhook JSON") from error
    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="Webhook payload must be an object")
    try:
        await run_in_threadpool(
            SnowflakeRepository(settings).persist_webhook_delivery,
            x_github_delivery,
            x_github_event,
            payload,
        )
    except Exception as error:
        raise HTTPException(status_code=502, detail="Snowflake webhook write failed") from error
    return {"status": "stored", "delivery_id": x_github_delivery}
