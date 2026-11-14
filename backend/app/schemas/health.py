from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field


class HealthResponse(BaseModel):
    """Schema for application health check response."""

    status: str = Field(default="healthy", description="Current service health status")
    app_name: str = Field(..., description="Name of the application")
    environment: str = Field(..., description="Operating environment")
    version: str = Field(..., description="Application version")
    timestamp: datetime = Field(..., description="UTC timestamp of the health check")
    database: Optional[str] = Field(default=None, description="Database connectivity status")

