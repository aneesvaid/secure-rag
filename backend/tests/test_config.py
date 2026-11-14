"""Comprehensive tests for configuration, environment validation, and security policies."""

import logging
from pathlib import Path
import pytest
from pydantic import SecretStr, ValidationError
from starlette.testclient import TestClient

from app.core.config import (
    EnvironmentMode,
    Settings,
    get_settings,
    reset_settings,
)
from app.core.logging import (
    JSONLogFormatter,
    SensitiveDataFilter,
    StandardLogFormatter,
    ensure_log_dir,
    setup_logging,
)
from app.main import create_application


# ------------------------------------------------------------------------------
# 1. Default Development Configuration Tests
# ------------------------------------------------------------------------------
def test_default_development_configuration():
    """Verify default development configuration settings and types."""
    settings = Settings()

    assert settings.APP_NAME == "Secure RAG Backend"
    assert settings.APP_ENV == EnvironmentMode.DEVELOPMENT
    assert settings.is_development is True
    assert settings.is_production is False
    assert settings.is_testing is False
    assert settings.DEBUG is True
    assert settings.PORT == 8000
    assert settings.HOST == "0.0.0.0"
    assert settings.API_V1_PREFIX == "/api/v1"
    assert settings.LOG_LEVEL == "INFO"
    assert settings.JWT_ALGORITHM == "HS256"
    assert settings.ACCESS_TOKEN_EXPIRE_MINUTES == 60
    assert "postgresql+psycopg://" in settings.DATABASE_URL.get_secret_value()
    assert settings.DB_POOL_SIZE == 10
    assert settings.DB_MAX_OVERFLOW == 20
    assert settings.DB_POOL_TIMEOUT == 30.0
    assert settings.DB_POOL_RECYCLE == 1800
    assert settings.DB_ECHO is False
    assert settings.LLM_PROVIDER == "openai"
    assert settings.LLM_TEMPERATURE == 0.0
    assert settings.LLM_MAX_TOKENS == 1024


# ------------------------------------------------------------------------------
# 2. Environment Variable Loading Tests
# ------------------------------------------------------------------------------
def test_environment_variable_loading(monkeypatch):
    """Verify that environment variables properly override default values."""
    monkeypatch.setenv("APP_NAME", "Custom Secure RAG")
    monkeypatch.setenv("PORT", "9000")
    monkeypatch.setenv("LOG_LEVEL", "DEBUG")
    monkeypatch.setenv("LLM_MODEL", "gpt-4o")
    monkeypatch.setenv("DATABASE_URL", "postgresql+psycopg://custom_user:custom_pass@localhost:5432/custom_db")
    monkeypatch.setenv("DB_POOL_SIZE", "15")

    settings = Settings()

    assert settings.APP_NAME == "Custom Secure RAG"
    assert settings.PORT == 9000
    assert settings.LOG_LEVEL == "DEBUG"
    assert settings.LLM_MODEL == "gpt-4o"
    assert settings.DATABASE_URL.get_secret_value() == "postgresql+psycopg://custom_user:custom_pass@localhost:5432/custom_db"
    assert settings.DB_POOL_SIZE == 15


def test_environment_mode_normalization():
    """Verify normalization of environment string aliases."""
    assert Settings(APP_ENV="dev").APP_ENV == EnvironmentMode.DEVELOPMENT
    assert Settings(APP_ENV="development").APP_ENV == EnvironmentMode.DEVELOPMENT
    assert Settings(APP_ENV="test").APP_ENV == EnvironmentMode.TESTING
    assert Settings(APP_ENV="testing").APP_ENV == EnvironmentMode.TESTING


# ------------------------------------------------------------------------------
# 3. Invalid Configuration Rejection Tests
# ------------------------------------------------------------------------------
def test_invalid_port_rejection():
    """Verify that out-of-range port numbers raise a ValidationError."""
    with pytest.raises(ValidationError) as exc:
        Settings(PORT=70000)
    assert "PORT must be between 1 and 65535" in str(exc.value)

    with pytest.raises(ValidationError):
        Settings(PORT=0)


def test_invalid_log_level_rejection():
    """Verify that unsupported log levels raise a ValidationError."""
    with pytest.raises(ValidationError) as exc:
        Settings(LOG_LEVEL="VERBOSE")
    assert "Invalid LOG_LEVEL" in str(exc.value)


def test_invalid_jwt_algorithm_rejection():
    """Verify that unsupported JWT algorithms are rejected."""
    with pytest.raises(ValidationError) as exc:
        Settings(JWT_ALGORITHM="MD5")
    assert "JWT_ALGORITHM 'MD5' is not supported" in str(exc.value)


def test_invalid_providers_rejection():
    """Verify that unsupported LLM or Embedding providers are rejected."""
    with pytest.raises(ValidationError) as exc:
        Settings(LLM_PROVIDER="unknown_ai_provider")
    assert "LLM_PROVIDER 'unknown_ai_provider' is not supported" in str(exc.value)

    with pytest.raises(ValidationError) as exc:
        Settings(EMBEDDING_PROVIDER="unsupported_embedding")
    assert "EMBEDDING_PROVIDER 'unsupported_embedding' is not supported" in str(exc.value)


def test_invalid_password_hash_algorithm_rejection():
    """Verify that unsupported password hash algorithms are rejected."""
    with pytest.raises(ValidationError) as exc:
        Settings(PASSWORD_HASH_ALGORITHM="plain_md5")
    assert "PASSWORD_HASH_ALGORITHM 'plain_md5' is not supported" in str(exc.value)


def test_invalid_timeout_and_token_rejections():
    """Verify that negative or zero timeouts and work factors are rejected."""
    with pytest.raises(ValidationError):
        Settings(ACCESS_TOKEN_EXPIRE_MINUTES=0)

    with pytest.raises(ValidationError):
        Settings(REFRESH_TOKEN_EXPIRE_DAYS=-1)

    with pytest.raises(ValidationError):
        Settings(BCRYPT_ROUNDS=2)  # Below min 4

    with pytest.raises(ValidationError):
        Settings(BCRYPT_ROUNDS=35)  # Above max 31

    with pytest.raises(ValidationError):
        Settings(DB_POOL_TIMEOUT=0)

    with pytest.raises(ValidationError):
        Settings(DB_POOL_SIZE=-1)

    with pytest.raises(ValidationError):
        Settings(LLM_TIMEOUT=-5.0)

    with pytest.raises(ValidationError):
        Settings(LLM_TEMPERATURE=2.5)  # Max 2.0


# ------------------------------------------------------------------------------
# 4. Production Secret and Policy Validation Tests
# ------------------------------------------------------------------------------
def test_production_rejects_debug_mode():
    """Verify that production rejects DEBUG=True."""
    with pytest.raises(ValidationError) as exc:
        Settings(
            APP_ENV="production",
            DEBUG=True,
            SECRET_KEY="a" * 32,
            LLM_API_KEY="sk-valid-production-key-example",
        )
    assert "DEBUG mode cannot be enabled in production" in str(exc.value)


def test_production_rejects_default_or_short_secret_key():
    """Verify that production rejects default dummy secret keys and short keys."""
    # Dummy default key
    with pytest.raises(ValidationError) as exc:
        Settings(
            APP_ENV="production",
            DEBUG=False,
            SECRET_KEY="insecure-dev-secret-key-change-in-production-min-32-chars",
            LLM_API_KEY="sk-valid-key",
        )
    assert "Default or dummy SECRET_KEY is not allowed in production" in str(exc.value)

    # Whitespace or too short (< 32 chars)
    with pytest.raises(ValidationError) as exc:
        Settings(
            APP_ENV="production",
            DEBUG=False,
            SECRET_KEY="short-secret-key",
            LLM_API_KEY="sk-valid-key",
        )
    assert "Production SECRET_KEY must be at least 32 characters long" in str(exc.value)


def test_production_rejects_wildcard_cors_with_credentials():
    """Verify that production rejects wildcard CORS when credentials are enabled."""
    with pytest.raises(ValidationError) as exc:
        Settings(
            APP_ENV="production",
            DEBUG=False,
            SECRET_KEY="a" * 32,
            CORS_ORIGINS=["*"],
            CORS_ALLOW_CREDENTIALS=True,
            LLM_API_KEY="sk-valid-key",
        )
    assert "Wildcard '*' in CORS_ORIGINS is prohibited" in str(exc.value)


def test_production_rejects_dummy_database_password():
    """Verify that production rejects default dummy password in DATABASE_URL."""
    with pytest.raises(ValidationError) as exc:
        Settings(
            APP_ENV="production",
            DEBUG=False,
            SECRET_KEY="a" * 32,
            DATABASE_URL="postgresql+psycopg://secure_rag_app:password@localhost:5432/secure_rag",
            LLM_API_KEY="sk-valid-key",
        )
    assert "Default or dummy database password is not allowed in production" in str(exc.value)


def test_production_rejects_sqlite_database():
    """Verify that production rejects SQLite database."""
    with pytest.raises(ValidationError) as exc:
        Settings(
            APP_ENV="production",
            DEBUG=False,
            SECRET_KEY="a" * 32,
            DATABASE_URL="sqlite:///./prod.db",
            LLM_API_KEY="sk-valid-key",
        )
    assert "SQLite database is not permitted in production" in str(exc.value)


def test_production_rejects_db_echo():
    """Verify that production rejects DB_ECHO=True."""
    with pytest.raises(ValidationError) as exc:
        Settings(
            APP_ENV="production",
            DEBUG=False,
            SECRET_KEY="a" * 32,
            DATABASE_URL="postgresql+psycopg://secure_rag_app:strong_prod_pass_12345@localhost:5432/secure_rag",
            DB_ECHO=True,
            LLM_API_KEY="sk-valid-key",
        )
    assert "DB_ECHO cannot be enabled in production" in str(exc.value)


def test_production_requires_cloud_llm_api_key():
    """Verify that production requires LLM_API_KEY for cloud providers."""
    with pytest.raises(ValidationError) as exc:
        Settings(
            APP_ENV="production",
            DEBUG=False,
            SECRET_KEY="a" * 32,
            LLM_PROVIDER="openai",
            LLM_API_KEY=None,
        )
    assert "LLM_API_KEY is required in production when LLM_PROVIDER is 'openai'" in str(exc.value)


def test_production_requires_cloud_embedding_api_key():
    """Verify that production requires an API key for cloud embeddings."""
    with pytest.raises(ValidationError) as exc:
        Settings(
            APP_ENV="production",
            DEBUG=False,
            SECRET_KEY="a" * 32,
            LLM_PROVIDER="ollama",
            EMBEDDING_PROVIDER="openai",
            EMBEDDING_API_KEY=None,
            LLM_API_KEY=None,
        )
    assert "EMBEDDING_API_KEY (or LLM_API_KEY) is required in production" in str(exc.value)


def test_production_rejects_wildcard_trusted_hosts():
    """Verify that production rejects wildcard '*' in TRUSTED_HOSTS."""
    with pytest.raises(ValidationError) as exc:
        Settings(
            APP_ENV="production",
            DEBUG=False,
            SECRET_KEY="a" * 32,
            TRUSTED_HOSTS=["*"],
            LLM_API_KEY="sk-valid-key",
        )
    assert "TRUSTED_HOSTS cannot be empty or wildcard" in str(exc.value)


def test_production_valid_configuration():
    """Verify that valid production configuration succeeds."""
    settings = Settings(
        APP_ENV="production",
        DEBUG=False,
        SECRET_KEY="production-super-strong-secret-key-32chars",
        CORS_ORIGINS=["https://app.securerag.com"],
        CORS_ALLOW_CREDENTIALS=True,
        TRUSTED_HOSTS=["app.securerag.com", "localhost"],
        LLM_PROVIDER="openai",
        LLM_API_KEY="sk-production-test-key-valid",
        DATABASE_URL="postgresql+psycopg://secure_rag_app:strong_secure_prod_pass_99999@localhost:5432/secure_rag",
    )
    assert settings.is_production is True
    assert settings.DEBUG is False
    assert settings.use_json_logging is True


# ------------------------------------------------------------------------------
# 5. CORS Configuration Tests
# ------------------------------------------------------------------------------
def test_cors_string_and_list_parsing():
    """Verify parsing of comma-separated strings into lists of trimmed origins."""
    settings = Settings(CORS_ORIGINS="http://localhost:3000, http://localhost:8443 , http://example.com")
    assert settings.CORS_ORIGINS == [
        "http://localhost:3000",
        "http://localhost:8443",
        "http://example.com",
    ]


# ------------------------------------------------------------------------------
# 6. TrustedHost Middleware Behavior Tests
# ------------------------------------------------------------------------------
def test_trusted_host_middleware_blocks_untrusted_host(monkeypatch):
    """Verify that in production mode, requests with untrusted Host headers are rejected."""
    monkeypatch.setenv("APP_ENV", "production")
    monkeypatch.setenv("DEBUG", "false")
    monkeypatch.setenv("SECRET_KEY", "strong-production-secret-key-at-least-32chars")
    monkeypatch.setenv("LLM_API_KEY", "sk-valid-key-for-test-purposes")
    monkeypatch.setenv("TRUSTED_HOSTS", "allowed.domain.com,localhost")

    reset_settings()
    app = create_application()

    # Allowed host client
    allowed_client = TestClient(app, base_url="http://allowed.domain.com")
    allowed_resp = allowed_client.get("/health")
    assert allowed_resp.status_code == 200

    # Untrusted host client
    untrusted_client = TestClient(app, base_url="http://evil.attacker.com")
    blocked_resp = untrusted_client.get("/health")
    assert blocked_resp.status_code == 400


# ------------------------------------------------------------------------------
# 7. Database Settings Validation Tests
# ------------------------------------------------------------------------------
def test_database_configuration_defaults():
    """Verify default PostgreSQL database settings and driver."""
    settings = Settings()
    raw_url = settings.DATABASE_URL.get_secret_value()
    assert raw_url.startswith("postgresql+psycopg://")
    assert "secure_rag" in raw_url
    assert settings.DB_POOL_SIZE == 10
    assert settings.DB_MAX_OVERFLOW == 20
    assert settings.DB_POOL_TIMEOUT == 30.0
    assert settings.DB_POOL_RECYCLE == 1800
    assert settings.DB_ECHO is False


def test_database_url_validation():
    """Verify acceptance of valid PostgreSQL and SQLite URLs and rejection of unsupported schemes."""
    # Valid PostgreSQL URLs
    s1 = Settings(DATABASE_URL="postgresql+psycopg://user:pass@localhost:5432/db")
    assert s1.DATABASE_URL.get_secret_value() == "postgresql+psycopg://user:pass@localhost:5432/db"

    s2 = Settings(DATABASE_URL="postgresql://user:pass@localhost:5432/db")
    assert s2.DATABASE_URL.get_secret_value() == "postgresql://user:pass@localhost:5432/db"

    # Valid SQLite URL for testing
    s3 = Settings(DATABASE_URL="sqlite:///./test.db")
    assert s3.DATABASE_URL.get_secret_value() == "sqlite:///./test.db"

    # Invalid scheme rejection
    with pytest.raises(ValidationError) as exc1:
        Settings(DATABASE_URL="mysql://user:pass@localhost:3306/db")
    assert "DATABASE_URL must start with" in str(exc1.value)

    # Empty URL rejection
    with pytest.raises(ValidationError) as exc2:
        Settings(DATABASE_URL="")
    assert "DATABASE_URL cannot be empty" in str(exc2.value)


# ------------------------------------------------------------------------------
# 8. LLM Provider Settings Validation Tests
# ------------------------------------------------------------------------------
def test_llm_provider_configuration():
    """Verify LLM local vs cloud resolution and base URL handling."""
    cloud_settings = Settings(LLM_PROVIDER="openai", LLM_BASE_URL="https://custom.openai.proxy/v1")
    assert cloud_settings.is_local_llm is False
    assert cloud_settings.effective_llm_base_url == "https://custom.openai.proxy/v1"

    local_settings = Settings(LLM_PROVIDER="ollama")
    assert local_settings.is_local_llm is True
    assert local_settings.effective_llm_base_url == "http://localhost:11434/v1"


# ------------------------------------------------------------------------------
# 9. Sensitive Values Masking and Log Sanitization Tests
# ------------------------------------------------------------------------------
def test_secret_str_masking():
    """Verify that SecretStr masks the secret in string representation."""
    settings = Settings(SECRET_KEY="super-secret-passphrase-not-to-leak")
    assert "super-secret-passphrase" not in str(settings.SECRET_KEY)
    assert "super-secret-passphrase" not in repr(settings.SECRET_KEY)
    assert settings.SECRET_KEY.get_secret_value() == "super-secret-passphrase-not-to-leak"


def test_sensitive_data_log_filter_strings_and_structures():
    """Verify that SensitiveDataFilter redacts passwords, tokens, API keys in strings and nested structures."""
    filter_ = SensitiveDataFilter()

    # 1. Plain string message
    record1 = logging.LogRecord(
        name="test",
        level=logging.INFO,
        pathname="test.py",
        lineno=1,
        msg="Connecting with api_key=sk-12345678901234567890 and password='mysecretpassword'",
        args=(),
        exc_info=None,
    )
    filter_.filter(record1)
    assert "mysecretpassword" not in record1.msg
    assert "sk-12345678901234567890" not in record1.msg
    assert "********" in record1.msg

    # 2. JWT and Bearer token in message
    jwt_sample = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    record2 = logging.LogRecord(
        name="test",
        level=logging.INFO,
        pathname="test.py",
        lineno=2,
        msg=f"Auth: Bearer {jwt_sample}",
        args=(),
        exc_info=None,
    )
    filter_.filter(record2)
    assert jwt_sample not in record2.msg
    assert "********" in record2.msg

    # 3. Nested dictionary and list args
    record3 = logging.LogRecord(
        name="test",
        level=logging.INFO,
        pathname="test.py",
        lineno=3,
        msg="Payload",
        args=({"password": "secret_in_dict", "token": jwt_sample, "nested": ["sk-12345678901234567890"]},),
        exc_info=None,
    )
    filter_.filter(record3)
    arg_dict = record3.args if isinstance(record3.args, dict) else record3.args[0]
    assert arg_dict["password"] == "********"
    assert arg_dict["token"] == "********"
    assert arg_dict["nested"][0] == "********"


def test_sensitive_data_redaction_in_exception_traceback():
    """Verify that exception tracebacks containing secrets are redacted by formatters."""
    formatter_json = JSONLogFormatter()
    formatter_std = StandardLogFormatter()

    try:
        raise ValueError("Failed connecting with api_key=sk-12345678901234567890")
    except ValueError:
        import sys
        exc_info = sys.exc_info()

    record = logging.LogRecord(
        name="test",
        level=logging.ERROR,
        pathname="test.py",
        lineno=10,
        msg="Error occurred",
        args=(),
        exc_info=exc_info,
    )

    json_output = formatter_json.format(record)
    assert "sk-12345678901234567890" not in json_output
    assert "********" in json_output

    std_exception = formatter_std.formatException(exc_info)
    assert "sk-12345678901234567890" not in std_exception
    assert "********" in std_exception


def test_explicit_secret_str_access_cannot_bypass_logging_redaction(monkeypatch):
    """Verify that even when SecretStr values are explicitly unmasked via .get_secret_value(),
    they are intercepted and masked by the logging sanitization filter and formatters."""
    raw_secret_key = "my-high-entropy-production-secret-9876543210"
    raw_db_url = "postgresql+psycopg://app_user:db-secret-password-xyz-9876@localhost:5432/secure_rag"
    raw_llm_key = "custom-llm-cloud-token-topsecret-67890"

    monkeypatch.setenv("SECRET_KEY", raw_secret_key)
    monkeypatch.setenv("DATABASE_URL", raw_db_url)
    monkeypatch.setenv("LLM_API_KEY", raw_llm_key)
    reset_settings()

    filter_ = SensitiveDataFilter()
    formatter_json = JSONLogFormatter()
    formatter_std = StandardLogFormatter()

    # 1. Secret accessed via .get_secret_value() logged as plain text without "secret=" keyword
    unmasked_secret = get_settings().SECRET_KEY.get_secret_value()
    assert unmasked_secret == raw_secret_key

    record = logging.LogRecord(
        name="test",
        level=logging.INFO,
        pathname="test.py",
        lineno=1,
        msg=f"Initialized service instance with {unmasked_secret}",
        args=(),
        exc_info=None,
    )
    filter_.filter(record)
    assert raw_secret_key not in record.msg
    assert "********" in record.msg

    # 2. Raw Database password unmasked in positional args or URL
    unmasked_db = get_settings().DATABASE_URL.get_secret_value()
    record_args = logging.LogRecord(
        name="test",
        level=logging.INFO,
        pathname="test.py",
        lineno=2,
        msg="Connecting to database at URL",
        args=(unmasked_db,),
        exc_info=None,
    )
    filter_.filter(record_args)
    assert "db-secret-password-xyz-9876" not in record_args.args[0]
    assert "********" in record_args.args[0]

    # 3. Bare SecretStr object passed to log filter
    bare_secret = SecretStr("bare-secret-object-payload-999")
    sanitized_secret = filter_.sanitize_value(bare_secret)
    assert sanitized_secret == "********"

    # 4. Exception traceback containing explicitly unmasked secret
    try:
        raise ConnectionError(f"Handshake failed with provider key {get_settings().LLM_API_KEY.get_secret_value()}")
    except ConnectionError:
        import sys
        exc_info = sys.exc_info()

    err_record = logging.LogRecord(
        name="test",
        level=logging.ERROR,
        pathname="test.py",
        lineno=10,
        msg="External service failed",
        args=(),
        exc_info=exc_info,
    )
    json_out = formatter_json.format(err_record)
    assert raw_llm_key not in json_out
    assert "********" in json_out

    std_out = formatter_std.formatException(exc_info)
    assert raw_llm_key not in std_out
    assert "********" in std_out


# ------------------------------------------------------------------------------
# 10. JSON Logging Tests
# ------------------------------------------------------------------------------
def test_json_log_formatter():
    """Verify that JSONLogFormatter produces valid JSON with expected metadata."""
    formatter = JSONLogFormatter()
    record = logging.LogRecord(
        name="secure_rag.test",
        level=logging.WARNING,
        pathname="test.py",
        lineno=42,
        msg="Test warning message",
        args=(),
        exc_info=None,
    )

    formatted = formatter.format(record)
    assert '"level": "WARNING"' in formatted
    assert '"message": "Test warning message"' in formatted
    assert '"timestamp"' in formatted
    assert '"environment"' in formatted


# ------------------------------------------------------------------------------
# 11. Settings Cache Isolation Tests
# ------------------------------------------------------------------------------
def test_settings_cache_isolation(monkeypatch):
    """Verify that reset_settings clears the cache and get_settings uses the updated environment."""
    s1 = get_settings()
    assert s1.PORT == 8000

    monkeypatch.setenv("PORT", "8888")
    # Calling get_settings directly without reset would return cached s1
    assert get_settings().PORT == 8000

    # Calling reset_settings clears cache and returns updated instance
    s2 = reset_settings()
    assert s2.PORT == 8888
    assert get_settings().PORT == 8888


# ------------------------------------------------------------------------------
# 12. Log Directory Creation and File Logging Tests
# ------------------------------------------------------------------------------
def test_ensure_log_dir_creates_directory():
    """Verify that ensure_log_dir creates backend/logs using project-root-independent path."""
    log_dir = ensure_log_dir()
    assert log_dir.exists()
    assert log_dir.is_dir()
    assert log_dir.name == "logs"


def test_file_logging_configuration(monkeypatch, tmp_path):
    """Verify that LOG_TO_FILE attaches a file handler writing to backend/logs."""
    monkeypatch.setenv("LOG_TO_FILE", "true")
    monkeypatch.setenv("LOG_FILE_NAME", "test_run.log")

    reset_settings()
    setup_logging()

    test_logger = logging.getLogger("secure_rag.file_test")
    test_logger.info("Test log entry to file with password=secret123")

    log_file = get_settings().LOGS_DIR / "test_run.log"
    assert log_file.exists()
    content = log_file.read_text(encoding="utf-8")
    assert "Test log entry to file" in content
    assert "secret123" not in content  # SensitiveDataFilter masked it
