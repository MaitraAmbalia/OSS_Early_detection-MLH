import logging

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware

from app.config import get_settings
from app.routers import dashboard, github, health, warehouse

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
logger = logging.getLogger("sentinel-oss-api")
settings = get_settings()

app = FastAPI(
    title="Sentinel OSS API",
    version="0.1.0",
    description="GitHub repository dependency and vulnerability monitoring API.",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type", "X-GitHub-Token"],
)


@app.middleware("http")
async def request_logging(request: Request, call_next):
    # Log only request metadata. Headers and bodies may contain GitHub credentials.
    response = await call_next(request)
    logger.info("%s %s %s", request.method, request.url.path, response.status_code)
    return response


app.include_router(health.router)
app.include_router(dashboard.router)
app.include_router(github.router)
app.include_router(warehouse.router)
