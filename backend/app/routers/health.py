from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends

from app.config import Settings
from app.dependencies import settings_dependency
from app.models import HealthResponse

router = APIRouter(tags=["health"])
SettingsDep = Annotated[Settings, Depends(settings_dependency)]


@router.get("/health", response_model=HealthResponse)
def health(settings: SettingsDep) -> HealthResponse:
    return HealthResponse(data_mode=settings.data_mode, timestamp=datetime.now(UTC))
