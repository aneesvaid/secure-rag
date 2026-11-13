"""Development server runner script."""

import sys
from pathlib import Path
import uvicorn

# Ensure the backend root directory is on Python's path
backend_dir = Path(__file__).resolve().parent.parent
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

from app.core.config import get_settings
from app.core.logging import ensure_log_dir

if __name__ == "__main__":
    settings = get_settings()
    # Ensure backend/logs exists using project-root-independent path
    ensure_log_dir()

    uvicorn.run(
        "app.main:app",
        host=settings.HOST,
        port=settings.PORT,
        reload=settings.DEBUG,
    )
