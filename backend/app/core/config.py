"""Centralized application configuration and environment management.

Uses Pydantic Settings for strictly typed validation, environment separation,
and production safety guarantees.
"""

from enum import Enum
from functools import lru_cache
from pathlib import Path
from typing import Any, List, Optional, Set, Union

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# Base paths (project-root-independent)
BACKEND_DIR: Path = Path(__file__).resolve().parent.parent.parent
LOGS_DIR: Path = BACKEND_DIR / "logs"


class EnvironmentMode(str, Enum):
    """Supported operating environment modes."""

    DEVELOPMENT = "development"
    TESTING = "testing"
    PRODUCTION = "production"


INSECURE_SECRET_KEYS: Set[str] = {
    "insecure-dev-secret-key-change-in-production-min-32-chars",
    "insecure-dev-secret-key-change-in-production",
    "change-this-in-production-use-a-secure-random-key",
    "change-this-in-production-use-a-secure-random-key-min-32-chars",
    "secret",
    "changeme",
    "test",
    "admin",
    "password",
    "12345678",
    "defaultsecretkeyforlocaldevelopmentonly",
}

ALLOWED_JWT_ALGORITHMS: Set[str] = {
    "HS256",
    "HS384",
    "HS512",
    "RS256",
    "RS384",
    "RS512",
    "ES256",
    "ES384",
    "ES512",
}

SUPPORTED_LLM_PROVIDERS: Set[str] = {
    "openai",
    "anthropic",
    "ollama",
    "vllm",
    "local",
    "azure_openai",
    "custom",
    "lmstudio",
}

CLOUD_LLM_PROVIDERS: Set[str] = {
    "openai",
    "anthropic",
    "azure_openai",
}

LOCAL_LLM_PROVIDERS: Set[str] = {
    "ollama",
    "vllm",
    "local",
    "lmstudio",
}

SUPPORTED_EMBEDDING_PROVIDERS: Set[str] = {
    "openai",
    "local",
    "custom",
    "azure_openai",
    "ollama",
}

SUPPORTED_HASH_ALGORITHMS: Set[str] = {
    "bcrypt",
    "argon2",
}


class Settings(BaseSettings):
    """Centralized application settings with environment validation."""

    model_config = SettingsConfigDict(
        env_file=(str(BACKEND_DIR / ".env"), ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    # --------------------------------------------------------------------------
    # 1. Application Configuration
    # --------------------------------------------------------------------------
    APP_NAME: str = Field(default="Secure RAG Backend", description="Application name")
    APP_ENV: EnvironmentMode = Field(
        default=EnvironmentMode.DEVELOPMENT,
        description="Operating environment (development, testing, production)",
    )
    APP_VERSION: str = Field(default="0.1.0", description="Semantic application version")
    DEBUG: bool = Field(default=True, description="Enable debug mode")
    HOST: str = Field(default="0.0.0.0", description="Binding host for the server")
    PORT: int = Field(default=8000, description="Listening port for the server")
    API_V1_PREFIX: str = Field(default="/api/v1", description="Prefix for version 1 API endpoints")

    @field_validator("APP_ENV", mode="before")
    @classmethod
    def normalize_app_env(cls, v: Any) -> Any:
        if isinstance(v, str):
            v_lower = v.lower().strip()
            if v_lower in ("dev", "devel", "development"):
                return EnvironmentMode.DEVELOPMENT
            if v_lower in ("test", "tests", "testing"):
                return EnvironmentMode.TESTING
            if v_lower in ("prod", "prodn", "production"):
                return EnvironmentMode.PRODUCTION
        return v

    @field_validator("PORT")
    @classmethod
    def validate_port(cls, v: int) -> int:
        if not (1 <= v <= 65535):
            raise ValueError(f"PORT must be between 1 and 65535, got {v}")
        return v

    # --------------------------------------------------------------------------
    # 2. CORS and Network Security Configuration
    # --------------------------------------------------------------------------
    CORS_ORIGINS: Union[str, List[str]] = Field(
        default=[
            "http://localhost:8443",
            "http://localhost:5173",
            "http://127.0.0.1:8443",
            "http://127.0.0.1:5173",
        ],
        description="Allowed CORS origins as list or comma-separated string",
    )
    CORS_ALLOW_CREDENTIALS: bool = Field(default=True, description="Allow credentials in CORS")
    TRUSTED_HOSTS: Union[str, List[str]] = Field(
        default=["localhost", "127.0.0.1", "0.0.0.0", "testserver"],
        description="Allowed host headers for TrustedHostMiddleware",
    )

    @field_validator("CORS_ORIGINS", "TRUSTED_HOSTS", mode="before")
    @classmethod
    def assemble_string_or_list(cls, v: Union[str, List[str]]) -> List[str]:
        if isinstance(v, str):
            return [item.strip() for item in v.split(",") if item.strip()]
        if isinstance(v, (list, tuple, set)):
            return [str(item).strip() for item in v if str(item).strip()]
        return v

    # --------------------------------------------------------------------------
    # 3. Security and Authentication Configuration
    # --------------------------------------------------------------------------
    SECRET_KEY: SecretStr = Field(
        default=SecretStr("insecure-dev-secret-key-change-in-production-min-32-chars"),
        description="Master secret key for application cryptography",
    )
    JWT_ALGORITHM: str = Field(default="HS256", description="JWT cryptographic signing algorithm")
    ACCESS_TOKEN_EXPIRE_MINUTES: int = Field(default=60, description="Access token expiration in minutes")
    REFRESH_TOKEN_EXPIRE_DAYS: int = Field(default=7, description="Refresh token expiration in days")
    PASSWORD_HASH_ALGORITHM: str = Field(default="bcrypt", description="Password hashing algorithm")
    BCRYPT_ROUNDS: int = Field(default=12, description="Bcrypt computational work factor")

    @field_validator("JWT_ALGORITHM")
    @classmethod
    def validate_jwt_algorithm(cls, v: str) -> str:
        upper = v.upper()
        if upper not in ALLOWED_JWT_ALGORITHMS:
            raise ValueError(f"JWT_ALGORITHM '{v}' is not supported. Allowed: {sorted(ALLOWED_JWT_ALGORITHMS)}")
        return upper

    @field_validator("PASSWORD_HASH_ALGORITHM")
    @classmethod
    def validate_hash_algorithm(cls, v: str) -> str:
        lower = v.lower().strip()
        if lower not in SUPPORTED_HASH_ALGORITHMS:
            raise ValueError(f"PASSWORD_HASH_ALGORITHM '{v}' is not supported. Allowed: {sorted(SUPPORTED_HASH_ALGORITHMS)}")
        return lower

    @field_validator("ACCESS_TOKEN_EXPIRE_MINUTES", "REFRESH_TOKEN_EXPIRE_DAYS")
    @classmethod
    def validate_token_expiration(cls, v: int) -> int:
        if v <= 0:
            raise ValueError("Token expiration durations must be strictly positive")
        return v

    @field_validator("BCRYPT_ROUNDS")
    @classmethod
    def validate_bcrypt_rounds(cls, v: int) -> int:
        if not (4 <= v <= 31):
            raise ValueError("BCRYPT_ROUNDS must be between 4 and 31")
        return v

    # --------------------------------------------------------------------------
    # 4. Database (PostgreSQL) Configuration
    # --------------------------------------------------------------------------
    DATABASE_URL: SecretStr = Field(
        default=SecretStr("postgresql+psycopg://secure_rag_app:password@localhost:5432/secure_rag"),
        description="PostgreSQL database connection URL (using psycopg 3 driver)",
    )
    DB_POOL_SIZE: int = Field(default=10, description="Database connection pool size")
    DB_MAX_OVERFLOW: int = Field(default=20, description="Database connection pool max overflow")
    DB_POOL_TIMEOUT: float = Field(default=30.0, description="Database connection pool timeout in seconds")
    DB_POOL_RECYCLE: int = Field(default=1800, description="Database connection pool recycle time in seconds")
    DB_ECHO: bool = Field(default=False, description="Enable SQLAlchemy engine SQL statement logging")

    @field_validator("DATABASE_URL", mode="before")
    @classmethod
    def validate_database_url_format(cls, v: Any) -> Any:
        raw_url = v.get_secret_value() if hasattr(v, "get_secret_value") else str(v)
        raw_url = raw_url.strip()
        if not raw_url:
            raise ValueError("DATABASE_URL cannot be empty")
        valid_prefixes = ("postgresql+psycopg://", "postgresql://", "sqlite://", "sqlite+pysqlite://")
        if not any(raw_url.startswith(prefix) for prefix in valid_prefixes):
            raise ValueError(
                f"DATABASE_URL must start with 'postgresql+psycopg://' or 'postgresql://' (got '{raw_url.split('://')[0]}://...')"
            )
        return SecretStr(raw_url) if not isinstance(v, SecretStr) else v

    @field_validator("DB_POOL_SIZE", "DB_MAX_OVERFLOW", "DB_POOL_RECYCLE")
    @classmethod
    def validate_positive_pool_ints(cls, v: int) -> int:
        if v < 0:
            raise ValueError("Database pool parameters cannot be negative")
        return v

    @field_validator("DB_POOL_TIMEOUT")
    @classmethod
    def validate_positive_pool_timeout(cls, v: float) -> float:
        if v <= 0:
            raise ValueError("DB_POOL_TIMEOUT must be positive")
        return v

    # --------------------------------------------------------------------------
    # 5. LLM and Embedding Configuration
    # --------------------------------------------------------------------------
    LLM_PROVIDER: str = Field(
        default="openai",
        description="LLM provider: openai, anthropic, ollama, vllm, local, custom",
    )
    LLM_MODEL: str = Field(default="gpt-4o-mini", description="Model identifier")
    LLM_API_KEY: Optional[SecretStr] = Field(default=None, description="API key for cloud LLM provider")
    LLM_BASE_URL: Optional[str] = Field(default=None, description="Custom base URL for LLM provider")
    LOCAL_LLM_BASE_URL: str = Field(
        default="http://localhost:11434/v1",
        description="Default base URL for locally hosted LLM engines (Ollama, vLLM, LM Studio)",
    )
    LLM_TIMEOUT: float = Field(default=60.0, description="LLM request timeout in seconds")
    LLM_MAX_RETRIES: int = Field(default=3, description="Maximum number of retries for LLM calls")
    LLM_TEMPERATURE: float = Field(default=0.0, description="Sampling temperature (0.0 to 2.0)")
    LLM_MAX_TOKENS: int = Field(default=1024, description="Maximum response tokens")

    EMBEDDING_PROVIDER: str = Field(default="openai", description="Embedding provider: openai, local, etc.")
    EMBEDDING_MODEL: str = Field(default="text-embedding-3-small", description="Embedding model name")
    EMBEDDING_DIMENSION: int = Field(default=1536, description="Vector dimension size")
    EMBEDDING_API_KEY: Optional[SecretStr] = Field(default=None, description="API key for embedding service")
    LOCAL_EMBEDDING_BASE_URL: str = Field(
        default="http://localhost:11434/v1",
        description="Base URL for local embedding models",
    )
    EMBEDDING_TIMEOUT: float = Field(default=30.0, description="Embedding request timeout in seconds")

    @field_validator("LLM_PROVIDER")
    @classmethod
    def validate_llm_provider(cls, v: str) -> str:
        lower = v.lower().strip()
        if lower not in SUPPORTED_LLM_PROVIDERS:
            raise ValueError(f"LLM_PROVIDER '{v}' is not supported. Allowed: {sorted(SUPPORTED_LLM_PROVIDERS)}")
        return lower

    @field_validator("EMBEDDING_PROVIDER")
    @classmethod
    def validate_embedding_provider(cls, v: str) -> str:
        lower = v.lower().strip()
        if lower not in SUPPORTED_EMBEDDING_PROVIDERS:
            raise ValueError(f"EMBEDDING_PROVIDER '{v}' is not supported. Allowed: {sorted(SUPPORTED_EMBEDDING_PROVIDERS)}")
        return lower

    @field_validator("LLM_TIMEOUT", "EMBEDDING_TIMEOUT")
    @classmethod
    def validate_positive_timeout(cls, v: float) -> float:
        if v <= 0:
            raise ValueError("Timeout must be strictly positive")
        return v

    @field_validator("LLM_TEMPERATURE")
    @classmethod
    def validate_temperature(cls, v: float) -> float:
        if not (0.0 <= v <= 2.0):
            raise ValueError("LLM_TEMPERATURE must be between 0.0 and 2.0")
        return v

    @field_validator("LLM_MAX_TOKENS", "EMBEDDING_DIMENSION")
    @classmethod
    def validate_positive_dimensions(cls, v: int) -> int:
        if v <= 0:
            raise ValueError("Token counts and dimensions must be strictly positive")
        return v

    @field_validator("LLM_MAX_RETRIES")
    @classmethod
    def validate_max_retries(cls, v: int) -> int:
        if v < 0:
            raise ValueError("LLM_MAX_RETRIES cannot be negative")
        return v

    @property
    def is_local_llm(self) -> bool:
        """Check if selected LLM provider is a local runtime."""
        return self.LLM_PROVIDER.lower() in LOCAL_LLM_PROVIDERS

    @property
    def effective_llm_base_url(self) -> Optional[str]:
        """Resolve effective LLM base URL depending on provider."""
        if self.LLM_BASE_URL:
            return self.LLM_BASE_URL
        if self.is_local_llm:
            return self.LOCAL_LLM_BASE_URL
        return None

    # --------------------------------------------------------------------------
    # 6. Logging Configuration & Storage
    # --------------------------------------------------------------------------
    LOG_LEVEL: str = Field(default="INFO", description="Log level: DEBUG, INFO, WARNING, ERROR, CRITICAL")
    LOG_FORMAT: Optional[str] = Field(default=None, description="Custom log format string")
    LOG_JSON: Optional[bool] = Field(
        default=None,
        description="Whether to emit structured JSON logs. Defaults to True in production.",
    )
    LOG_TO_FILE: bool = Field(default=False, description="Whether to write logs to file in backend/logs")
    LOG_FILE_NAME: str = Field(default="app.log", description="Log filename when LOG_TO_FILE is True")

    @property
    def LOGS_DIR(self) -> Path:
        """Return project-root-independent path to backend/logs directory."""
        return LOGS_DIR

    @field_validator("LOG_LEVEL")
    @classmethod
    def validate_log_level(cls, v: str) -> str:
        valid_levels = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        upper = v.upper()
        if upper not in valid_levels:
            raise ValueError(f"Invalid LOG_LEVEL '{v}'. Allowed: {sorted(valid_levels)}")
        return upper

    # --------------------------------------------------------------------------
    # 7. Helper Environment Properties
    # --------------------------------------------------------------------------
    @property
    def is_production(self) -> bool:
        """Check if the active environment is production."""
        return self.APP_ENV == EnvironmentMode.PRODUCTION

    @property
    def is_development(self) -> bool:
        """Check if the active environment is development."""
        return self.APP_ENV == EnvironmentMode.DEVELOPMENT

    @property
    def is_testing(self) -> bool:
        """Check if the active environment is testing."""
        return self.APP_ENV == EnvironmentMode.TESTING

    @property
    def use_json_logging(self) -> bool:
        """Determine whether to use JSON logging format."""
        if self.LOG_JSON is not None:
            return self.LOG_JSON
        return self.is_production

    # --------------------------------------------------------------------------
    # 8. Cross-Field Production Safety Validations
    # --------------------------------------------------------------------------
    @model_validator(mode="after")
    def validate_production_safety(self) -> "Settings":
        """Strictly enforce security policies and reject insecure defaults in production."""
        if self.APP_ENV == EnvironmentMode.PRODUCTION:
            # 1. Debug mode must never be active in production
            if self.DEBUG:
                raise ValueError("Unsafe configuration: DEBUG mode cannot be enabled in production environment.")

            # 2. Secret key must not be a known insecure development default
            secret_val = self.SECRET_KEY.get_secret_value().strip()
            if not secret_val or secret_val.lower() in INSECURE_SECRET_KEYS:
                raise ValueError(
                    "Unsafe configuration: Default or dummy SECRET_KEY is not allowed in production. "
                    "Set a secure, random SECRET_KEY (min 32 characters) in production environment."
                )
            if len(secret_val) < 32:
                raise ValueError(
                    f"Unsafe configuration: Production SECRET_KEY must be at least 32 characters long (got {len(secret_val)})."
                )

            # 3. CORS origins must not permit wildcards when credentials are enabled
            origins = self.CORS_ORIGINS if isinstance(self.CORS_ORIGINS, list) else [self.CORS_ORIGINS]
            if "*" in origins and self.CORS_ALLOW_CREDENTIALS:
                raise ValueError(
                    "Unsafe configuration: Wildcard '*' in CORS_ORIGINS is prohibited when CORS_ALLOW_CREDENTIALS is True in production."
                )

            # 4. Cloud LLM provider requires an API key in production
            if self.LLM_PROVIDER.lower() in CLOUD_LLM_PROVIDERS:
                if not self.LLM_API_KEY or not self.LLM_API_KEY.get_secret_value().strip():
                    raise ValueError(
                        f"Unsafe configuration: LLM_API_KEY is required in production when LLM_PROVIDER is '{self.LLM_PROVIDER}'."
                    )

            # 5. Cloud Embedding provider requires an API key in production
            if self.EMBEDDING_PROVIDER.lower() in ("openai", "azure_openai"):
                has_emb_key = self.EMBEDDING_API_KEY and self.EMBEDDING_API_KEY.get_secret_value().strip()
                has_llm_key = self.LLM_API_KEY and self.LLM_API_KEY.get_secret_value().strip()
                if not (has_emb_key or has_llm_key):
                    raise ValueError(
                        f"Unsafe configuration: EMBEDDING_API_KEY (or LLM_API_KEY) is required in production when EMBEDDING_PROVIDER is '{self.EMBEDDING_PROVIDER}'."
                    )

            # 6. Trusted hosts must not be empty or wildcard in production
            hosts = self.TRUSTED_HOSTS if isinstance(self.TRUSTED_HOSTS, list) else [self.TRUSTED_HOSTS]
            if not hosts or "*" in hosts:
                raise ValueError("Unsafe configuration: TRUSTED_HOSTS cannot be empty or wildcard '*' in production.")

            # 7. Database configuration check in production
            db_url = self.DATABASE_URL.get_secret_value().strip()
            if "password@" in db_url or "your_password_here" in db_url:
                raise ValueError(
                    "Unsafe configuration: Default or dummy database password is not allowed in production. "
                    "Configure a secure DATABASE_URL in production environment."
                )
            if db_url.startswith("sqlite"):
                raise ValueError("Unsafe configuration: SQLite database is not permitted in production.")
            if self.DB_ECHO:
                raise ValueError("Unsafe configuration: DB_ECHO cannot be enabled in production.")

        return self


@lru_cache()
def get_settings() -> Settings:
    """Return a cached singleton instance of application settings."""
    return Settings()


def reset_settings() -> Settings:
    """Clear the cached settings singleton and return a fresh Settings instance."""
    get_settings.cache_clear()
    return get_settings()


# Export standard settings instance for direct import
settings: Settings = get_settings()
