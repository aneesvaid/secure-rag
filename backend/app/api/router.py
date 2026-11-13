from fastapi import APIRouter
from app.api.routes.health import router as health_router

api_router = APIRouter()

# Include modular route collections
api_router.include_router(health_router, prefix="", tags=["Health"])

