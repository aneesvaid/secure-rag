"""Centralized structured logging with sensitive data sanitization.

Provides production-ready logging with environment-specific formatters,
automatic redaction of sensitive credentials, tokens, and keys, and
project-root-independent log directory management.
"""

import json
import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path
import re
import sys
from datetime import datetime, timezone
from typing import Any, Dict, Set

from pydantic import SecretStr

from app.core.config import get_settings

# Regular expressions matching sensitive key-value pairs and token patterns
SENSITIVE_PATTERNS = [
    # Key-value pairs: password="...", api_key='...', secret=..., token=...
    re.compile(
        r"(?i)\b(password|secret_key|secret|api_key|apikey|access_token|refresh_token|auth_token|authorization|bearer|private_key)\b\s*[:=]\s*['\"]?([^'\",\s]+)['\"]?"
    ),
    # OpenAI / Anthropic API keys (sk-..., ant-...)
    re.compile(r"\b(sk-[a-zA-Z0-9_\-]{20,})\b"),
    re.compile(r"\b(ant-[a-zA-Z0-9_\-]{20,})\b"),
    # JWT tokens: eyJ...
    re.compile(r"\b(eyJ[a-zA-Z0-9_\-]{10,}\.eyJ[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]+)\b"),
    # Bearer tokens in headers: Bearer <token>
    re.compile(r"(?i)\bBearer\s+([a-zA-Z0-9_\-\.]{20,})\b"),
    # Database connection URLs with embedded passwords: postgresql+psycopg://user:pass@host...
    re.compile(r"(?i)\b((?:postgresql(?:\+psycopg)?|sqlite|mysql|mongodb)://[^:]+:)([^@]+)(@)"),
]

# Keys whose contents should be masked or truncated if passed in structured data
SENSITIVE_KEYS = {
    "password",
    "db_password",
    "database_url",
    "secret",
    "secret_key",
    "api_key",
    "apikey",
    "access_token",
    "refresh_token",
    "auth_token",
    "authorization",
    "token",
    "private_key",
}

DOCUMENT_CONTENT_KEYS = {
    "document_content",
    "chunk_content",
    "raw_text",
    "file_bytes",
}


def ensure_log_dir() -> Path:
    """Ensure the backend/logs directory exists using project-root-independent path."""
    settings = get_settings()
    log_dir = settings.LOGS_DIR
    log_dir.mkdir(parents=True, exist_ok=True)
    return log_dir


class SensitiveDataFilter(logging.Filter):
    """Logging filter that sanitizes and masks sensitive data in log records."""

    def filter(self, record: logging.LogRecord) -> bool:
        record.msg = self.sanitize_value(record.msg)

        if record.args:
            record.args = self.sanitize_value(record.args)

        # Also sanitize any custom extra attributes attached to the LogRecord
        for key in list(record.__dict__.keys()):
            if key in SENSITIVE_KEYS:
                record.__dict__[key] = "********"
            elif key in DOCUMENT_CONTENT_KEYS and isinstance(record.__dict__[key], str):
                # Avoid logging full raw document chunks
                record.__dict__[key] = f"[PROTECTED_DOCUMENT_DATA length={len(record.__dict__[key])}]"

        return True

    @classmethod
    def get_configured_secret_values(cls) -> Set[str]:
        """Collect active configured raw secrets to prevent unmasked leaks."""
        secrets: Set[str] = set()
        try:
            settings = get_settings()

            # If DATABASE_URL contains user:password@host, extract password component
            db_raw = settings.DATABASE_URL.get_secret_value().strip()
            if "@" in db_raw and "://" in db_raw:
                try:
                    auth_part = db_raw.split("://", 1)[1].split("@", 1)[0]
                    if ":" in auth_part:
                        db_pass = auth_part.split(":", 1)[1].strip()
                        if len(db_pass) >= 4 and db_pass.lower() not in {"password", "secret"}:
                            secrets.add(db_pass)
                except Exception:
                    pass

            for secret_obj in (
                settings.SECRET_KEY,
                settings.DATABASE_URL,
                settings.LLM_API_KEY,
                settings.EMBEDDING_API_KEY,
            ):
                if secret_obj:
                    val = (
                        secret_obj.get_secret_value()
                        if hasattr(secret_obj, "get_secret_value")
                        else str(secret_obj)
                    )
                    val = val.strip()
                    # Only register secrets of sufficient length to avoid false-positive collisions
                    if len(val) >= 6 and val.lower() not in {
                        "secret",
                        "changeme",
                        "admin",
                        "password",
                        "none",
                        "true",
                        "false",
                    }:
                        secrets.add(val)
        except Exception:
            pass
        return secrets

    @classmethod
    def sanitize_string(cls, text: str) -> str:
        """Replace sensitive credential patterns and known active secrets with masked placeholders."""
        if not text:
            return text
        sanitized = text
        for pattern in SENSITIVE_PATTERNS:
            def _replace(m):
                groups = m.groups()
                if len(groups) == 3:
                    # Database URL pattern: prefix, password, suffix
                    return f"{groups[0]}********{groups[2]}"
                elif len(groups) >= 2:
                    return f"{groups[0]}=********"
                return "********"

            sanitized = pattern.sub(_replace, sanitized)
        # Redact any configured active secrets that were accessed or unmasked directly
        for secret_val in cls.get_configured_secret_values():
            if secret_val in sanitized:
                sanitized = sanitized.replace(secret_val, "********")
        return sanitized

    @classmethod
    def sanitize_value(cls, value: Any) -> Any:
        """Recursively sanitize strings, SecretStr, models, dictionaries, lists, and tuples."""
        if isinstance(value, SecretStr):
            return "********"
        if isinstance(value, str):
            return cls.sanitize_string(value)
        if hasattr(value, "model_dump") and callable(value.model_dump):
            try:
                return cls.sanitize_value(value.model_dump())
            except Exception:
                return cls.sanitize_string(str(value))
        if isinstance(value, dict):
            sanitized_dict: Dict[str, Any] = {}
            for k, v in value.items():
                k_str = str(k).lower()
                if k_str in SENSITIVE_KEYS:
                    sanitized_dict[k] = "********"
                elif k_str in DOCUMENT_CONTENT_KEYS and isinstance(v, str):
                    sanitized_dict[k] = f"[PROTECTED_DOCUMENT_DATA length={len(v)}]"
                else:
                    sanitized_dict[k] = cls.sanitize_value(v)
            return sanitized_dict
        if isinstance(value, list):
            return [cls.sanitize_value(item) for item in value]
        if isinstance(value, tuple):
            return tuple(cls.sanitize_value(item) for item in value)
        return value


class StandardLogFormatter(logging.Formatter):
    """Human-readable console formatter with exception traceback sanitization."""

    def formatException(self, ei) -> str:
        formatted = super().formatException(ei)
        return SensitiveDataFilter.sanitize_string(formatted)


class JSONLogFormatter(logging.Formatter):
    """Structured JSON formatter for production environments with traceback sanitization."""

    def formatException(self, ei) -> str:
        formatted = super().formatException(ei)
        return SensitiveDataFilter.sanitize_string(formatted)

    def format(self, record: logging.LogRecord) -> str:
        settings = get_settings()
        log_data: Dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": SensitiveDataFilter.sanitize_string(record.getMessage()),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
            "environment": settings.APP_ENV.value,
        }

        if record.exc_info:
            log_data["exception"] = self.formatException(record.exc_info)

        return json.dumps(log_data, default=str)


def setup_logging() -> None:
    """Configure structured logging based on current environment settings."""
    settings = get_settings()
    log_level = getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO)

    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)

    # Remove existing handlers to prevent duplicate log entries
    for handler in list(root_logger.handlers):
        root_logger.removeHandler(handler)

    sensitive_filter = SensitiveDataFilter()

    # 1. Console Handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(log_level)
    console_handler.addFilter(sensitive_filter)

    if settings.use_json_logging:
        console_handler.setFormatter(JSONLogFormatter())
    else:
        log_format = settings.LOG_FORMAT or (
            "%(asctime)s | %(levelname)-8s | %(name)s:%(funcName)s:%(lineno)d - %(message)s"
        )
        console_handler.setFormatter(StandardLogFormatter(log_format))

    root_logger.addHandler(console_handler)

    # 2. File Handler (Optional / Configurable)
    if settings.LOG_TO_FILE:
        log_dir = ensure_log_dir()
        log_file_path = log_dir / settings.LOG_FILE_NAME
        file_handler = RotatingFileHandler(
            filename=str(log_file_path),
            maxBytes=10 * 1024 * 1024,  # 10 MB per file
            backupCount=5,
            encoding="utf-8",
        )
        file_handler.setLevel(log_level)
        file_handler.addFilter(sensitive_filter)
        if settings.use_json_logging:
            file_handler.setFormatter(JSONLogFormatter())
        else:
            file_handler.setFormatter(StandardLogFormatter(log_format))
        root_logger.addHandler(file_handler)

    # Align standard Uvicorn loggers with application configuration
    for logger_name in ("uvicorn", "uvicorn.access", "uvicorn.error", "fastapi"):
        uv_logger = logging.getLogger(logger_name)
        uv_logger.handlers = [console_handler]
        uv_logger.setLevel(log_level)
        uv_logger.propagate = False


logger = logging.getLogger("secure_rag")
