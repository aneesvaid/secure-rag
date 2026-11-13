"""Pytest configuration, fixtures, and settings cache isolation."""

import sys
from pathlib import Path
import pytest

# Ensure backend root is on sys.path for test discovery
backend_dir = Path(__file__).resolve().parent.parent
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

from app.core.config import reset_settings


@pytest.fixture(autouse=True)
def isolate_settings_cache():
    """Ensure settings cache is isolated and reset before and after each test."""
    reset_settings()
    yield
    reset_settings()

