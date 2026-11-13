from contextlib import asynccontextmanager
from typing import AsyncGenerator
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from app.api.router import api_router
from app.api.routes.health import router as health_router
from app.core.config import get_settings
from app.core.logging import logger, setup_logging


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application lifespan context manager for startup and shutdown events."""
    current_settings = get_settings()
    setup_logging()
    logger.info(
        "Starting %s v%s in %s mode",
        current_settings.APP_NAME,
        current_settings.APP_VERSION,
        current_settings.APP_ENV.value,
    )
    yield
    logger.info("Shutting down %s", current_settings.APP_NAME)


def create_application() -> FastAPI:
    """Create and configure the FastAPI application instance."""
    current_settings = get_settings()

    # Expose interactive docs unless explicitly disabled in production
    docs_enabled = current_settings.DEBUG or not current_settings.is_production

    app = FastAPI(
        title=current_settings.APP_NAME,
        version=current_settings.APP_VERSION,
        debug=current_settings.DEBUG,
        lifespan=lifespan,
        docs_url="/docs" if docs_enabled else None,
        redoc_url="/redoc" if docs_enabled else None,
        openapi_url="/openapi.json" if docs_enabled else None,
    )

    # Enforce TrustedHostMiddleware in production when trusted hosts are specified
    if current_settings.is_production and current_settings.TRUSTED_HOSTS:
        allowed_hosts = (
            current_settings.TRUSTED_HOSTS
            if isinstance(current_settings.TRUSTED_HOSTS, list)
            else [current_settings.TRUSTED_HOSTS]
        )
        app.add_middleware(TrustedHostMiddleware, allowed_hosts=allowed_hosts)

    # Configure CORS middleware
    cors_origins = (
        current_settings.CORS_ORIGINS
        if isinstance(current_settings.CORS_ORIGINS, list)
        else [current_settings.CORS_ORIGINS]
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=cors_origins,
        allow_credentials=current_settings.CORS_ALLOW_CREDENTIALS,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Root-level health check endpoint
    app.include_router(health_router, prefix="", tags=["Health"])

    # Modular versioned API routes
    app.include_router(api_router, prefix=current_settings.API_V1_PREFIX)

    @app.get("/", tags=["Root"])
    async def root():
        """Root endpoint returning basic service information."""
        return {
            "name": current_settings.APP_NAME,
            "version": current_settings.APP_VERSION,
            "environment": current_settings.APP_ENV.value,
            "docs": "/docs" if docs_enabled else "disabled",
            "health": "/health",
        }

    return app


app = create_application()
