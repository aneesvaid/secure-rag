from datetime import datetime, timezone
from fastapi import APIRouter
from app.core.config import settings
from app.database.session import check_db_connectivity
from app.schemas.health import HealthResponse

router = APIRouter(tags=["Health"])


@router.get("/health", response_model=HealthResponse, summary="Service Health Check")
async def health_check() -> HealthResponse:
    """Check the health and operational status of the service."""
    db_ok, _ = check_db_connectivity()
    return HealthResponse(
        status="healthy",
        app_name=settings.APP_NAME,
        environment=settings.APP_ENV,
        version=settings.APP_VERSION,
        timestamp=datetime.now(timezone.utc),
        database="connected" if db_ok else "unavailable",
    )

