"""Database session management and connectivity verification.

Provides SQLAlchemy 2.x engine initialization using psycopg 3 driver,
scoped session factories, FastAPI dependency injection, and health verification.
"""

from typing import Generator, Optional, Tuple
import logging

from sqlalchemy import Engine, create_engine, text
from sqlalchemy.exc import OperationalError, SQLAlchemyError
from sqlalchemy.orm import Session, declarative_base, sessionmaker

from app.core.config import get_settings

logger = logging.getLogger("secure_rag.database")

# Declarative base for SQLAlchemy models
Base = declarative_base()


def create_db_engine(
    database_url: Optional[str] = None,
    echo: Optional[bool] = None,
) -> Engine:
    """Create a new SQLAlchemy Engine instance with connection pooling.

    Uses psycopg 3 driver and connection pool parameters from Settings.
    """
    settings = get_settings()
    url = database_url or settings.DATABASE_URL.get_secret_value()
    is_echo = echo if echo is not None else (settings.DB_ECHO and settings.DEBUG)

    # SQLite compatibility for isolated unit tests
    if url.startswith("sqlite"):
        return create_engine(
            url,
            echo=is_echo,
            connect_args={"check_same_thread": False},
        )

    return create_engine(
        url,
        echo=is_echo,
        pool_size=settings.DB_POOL_SIZE,
        max_overflow=settings.DB_MAX_OVERFLOW,
        pool_timeout=settings.DB_POOL_TIMEOUT,
        pool_recycle=settings.DB_POOL_RECYCLE,
        pool_pre_ping=True,  # Test connection liveness before vending from pool
    )


# Application-level engine singleton
engine: Engine = create_db_engine()

# Application-level session factory
SessionLocal: sessionmaker[Session] = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine,
    expire_on_commit=False,
)


def reset_db_engine(database_url: Optional[str] = None) -> Engine:
    """Recreate engine and rebind SessionLocal. Useful during tests or environment updates."""
    global engine, SessionLocal
    if engine:
        engine.dispose()
    engine = create_db_engine(database_url=database_url)
    SessionLocal.configure(bind=engine)
    return engine


def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency yielding a scoped database session.

    Guarantees session cleanup and rollback on unhandled exceptions.
    """
    session = SessionLocal()
    try:
        yield session
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def check_db_connectivity(target_engine: Optional[Engine] = None) -> Tuple[bool, Optional[str]]:
    """Verify database connectivity by executing a lightweight ping query ('SELECT 1').

    Returns:
        Tuple[bool, Optional[str]]: (is_healthy, error_message_or_none)
    """
    eng = target_engine or engine
    try:
        with eng.connect() as conn:
            conn.execute(text("SELECT 1"))
        return True, None
    except (OperationalError, SQLAlchemyError, Exception) as exc:
        # Sanitize exception message so credentials are never logged
        logger.warning("Database connectivity check failed: %s", str(exc))
        return False, "Database connection unavailable"
