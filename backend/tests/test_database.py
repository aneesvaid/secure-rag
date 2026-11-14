"""Comprehensive unit and integration tests for database session and connectivity."""

import pytest
from sqlalchemy import text
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session

from app.core.config import Settings, reset_settings
from app.database.session import (
    Base,
    SessionLocal,
    check_db_connectivity,
    create_db_engine,
    get_db,
    reset_db_engine,
)


def test_declarative_base_instantiation():
    """Verify that Base is a valid SQLAlchemy DeclarativeBase."""
    assert Base is not None
    assert hasattr(Base, "metadata")


def test_create_db_engine_sqlite():
    """Verify engine creation with SQLite for isolated testing."""
    sqlite_url = "sqlite+pysqlite:///:memory:"
    engine = create_db_engine(database_url=sqlite_url, echo=False)
    assert engine is not None
    assert engine.dialect.name == "sqlite"

    with engine.connect() as conn:
        result = conn.execute(text("SELECT 42")).scalar()
        assert result == 42
    engine.dispose()


def test_create_db_engine_postgresql_settings(monkeypatch):
    """Verify PostgreSQL engine instantiation with psycopg 3 driver and pool config."""
    monkeypatch.setenv("DATABASE_URL", "postgresql+psycopg://test_user:test_pass@localhost:5432/test_db")
    monkeypatch.setenv("DB_POOL_SIZE", "5")
    monkeypatch.setenv("DB_MAX_OVERFLOW", "10")
    monkeypatch.setenv("DB_POOL_TIMEOUT", "15.0")
    reset_settings()

    engine = create_db_engine()
    assert engine.dialect.name == "postgresql"
    assert engine.dialect.driver == "psycopg"
    assert engine.pool.size() == 5
    engine.dispose()


def test_reset_db_engine():
    """Verify that reset_db_engine disposes existing engine and rebinds SessionLocal."""
    sqlite_url = "sqlite+pysqlite:///:memory:"
    new_engine = reset_db_engine(database_url=sqlite_url)

    assert new_engine.dialect.name == "sqlite"
    # SessionLocal is bound to new engine
    session = SessionLocal()
    assert isinstance(session, Session)
    result = session.execute(text("SELECT 'rebound'")).scalar()
    assert result == "rebound"
    session.close()

    # Reset back to default settings
    reset_settings()
    reset_db_engine()


def test_session_local_and_transaction():
    """Verify that SessionLocal can perform transactional operations in an isolated test database."""
    sqlite_url = "sqlite+pysqlite:///:memory:"
    engine = create_db_engine(database_url=sqlite_url)
    session = Session(bind=engine)

    try:
        session.execute(text("CREATE TABLE test_items (id INTEGER PRIMARY KEY, name TEXT)"))
        session.execute(text("INSERT INTO test_items (id, name) VALUES (1, 'secure_rag')"))
        session.commit()

        row = session.execute(text("SELECT name FROM test_items WHERE id = 1")).scalar()
        assert row == "secure_rag"
    finally:
        session.close()
        engine.dispose()


def test_get_db_yields_and_closes(monkeypatch):
    """Verify that get_db dependency yields a valid session and closes it."""
    sqlite_url = "sqlite+pysqlite:///:memory:"
    reset_db_engine(database_url=sqlite_url)

    db_gen = get_db()
    session = next(db_gen)

    assert isinstance(session, Session)
    assert session.is_active is True

    result = session.execute(text("SELECT 100")).scalar()
    assert result == 100

    # Exhaust generator to trigger finally block
    with pytest.raises(StopIteration):
        next(db_gen)

    # Session should now be closed
    reset_settings()
    reset_db_engine()


def test_get_db_rollback_on_exception(monkeypatch):
    """Verify that get_db automatically rolls back transaction if an unhandled exception occurs."""
    sqlite_url = "sqlite+pysqlite:///:memory:"
    reset_db_engine(database_url=sqlite_url)

    # Create table
    init_session = SessionLocal()
    init_session.execute(text("CREATE TABLE rollback_test (val TEXT)"))
    init_session.commit()
    init_session.close()

    db_gen = get_db()
    session = next(db_gen)

    session.execute(text("INSERT INTO rollback_test (val) VALUES ('pending')"))

    # Simulate exception inside route handler
    with pytest.raises(RuntimeError) as exc_info:
        try:
            raise RuntimeError("Route processing failed")
        except Exception as exc:
            db_gen.throw(exc)

    assert "Route processing failed" in str(exc_info.value)

    # Verify that the value was rolled back and not committed
    verify_session = SessionLocal()
    count = verify_session.execute(text("SELECT count(*) FROM rollback_test")).scalar()
    assert count == 0
    verify_session.close()

    reset_settings()
    reset_db_engine()


def test_check_db_connectivity_success():
    """Verify check_db_connectivity returns True when connection succeeds."""
    sqlite_url = "sqlite+pysqlite:///:memory:"
    engine = create_db_engine(database_url=sqlite_url)

    is_ok, err = check_db_connectivity(target_engine=engine)
    assert is_ok is True
    assert err is None
    engine.dispose()


def test_check_db_connectivity_failure(monkeypatch, caplog):
    """Verify check_db_connectivity handles failure gracefully without exposing credentials."""
    # Use invalid host/port to guarantee connection failure
    unreachable_url = "postgresql+psycopg://test_user:super_secret_db_pass_12345@127.0.0.1:59999/non_existent_db"
    failing_engine = create_db_engine(database_url=unreachable_url)

    is_ok, err = check_db_connectivity(target_engine=failing_engine)

    assert is_ok is False
    assert err == "Database connection unavailable"

    # Verify that no password was leaked into the log output
    for record in caplog.records:
        assert "super_secret_db_pass_12345" not in record.message

    failing_engine.dispose()
