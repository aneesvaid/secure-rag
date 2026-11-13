# Secure RAG - Backend

FastAPI backend service for the **Secure RAG (Retrieval-Augmented Generation) System**.

This service provides a modular, production-ready foundation designed to support permission-aware retrieval, Qdrant vector database indexing, and flexible LLM providers (both cloud APIs and self-hosted models).

---

## 1. Directory Structure

```text
backend/
├── app/
│   ├── api/                  # API routers and versioned endpoints
│   │   ├── routes/           # Modular route controllers
│   │   │   ├── __init__.py
│   │   │   └── health.py     # Health check endpoint (/health)
│   │   ├── __init__.py
│   │   └── router.py         # Versioned API router aggregation
│   ├── core/                 # Application configuration & logging
│   │   ├── __init__.py
│   │   ├── config.py         # Pydantic BaseSettings environment config & validation
│   │   └── logging.py        # Centralized structured logger & sensitive data filter
│   ├── database/             # Database & Qdrant vector store connectors
│   │   └── __init__.py
│   ├── llm/                  # Cloud & local LLM provider adapters
│   │   └── __init__.py
│   ├── models/               # Domain & database data models
│   │   └── __init__.py
│   ├── rag/                  # Chunking, indexing, and retrieval pipeline
│   │   └── __init__.py
│   ├── schemas/              # Pydantic request and response schemas
│   │   ├── __init__.py
│   │   └── health.py         # HealthResponse schema
│   ├── security/             # Authentication, RBAC & document permissions
│   │   └── __init__.py
│   ├── services/             # Business logic service layer
│   │   └── __init__.py
│   ├── utils/                # Helper utilities
│   │   └── __init__.py
│   ├── __init__.py
│   └── main.py               # FastAPI application entry point
├── scripts/                  # Utility and execution scripts
│   └── run_dev.py            # Local development server runner
├── tests/                    # Automated test suite
│   ├── __init__.py
│   ├── test_config.py        # Centralized config, security & validation tests
│   └── test_health.py        # Health and CORS test cases
├── .env.example              # Environment variables template
├── .gitignore                # Python and environment ignore rules
├── README.md                 # Backend documentation
└── requirements.txt          # Initial project dependencies
```

---

## 2. Prerequisites & Python Compatibility

* **Testing Environment:** Python 3.15 (Windows CPython)
* **Supported Production Runtimes:** Python 3.11, 3.12, 3.13, 3.14, 3.15
* **Dependency Compatibility:** All dependencies (`fastapi`, `uvicorn`, `pydantic`, `pydantic-settings`, `python-dotenv`, `httpx`, `pytest`) are verified compatible across modern CPython releases ($\ge 3.11$).
* **Virtual Environment:** Dedicated `.venv` created and activated.

---

## 3. Installation

1. Navigate to the project root or backend folder:
   ```bash
   cd backend
   ```

2. Activate the virtual environment:
   * **Windows PowerShell:**
     ```powershell
     ..\.venv\Scripts\Activate.ps1
     ```
   * **Windows Command Prompt:**
     ```cmd
     ..\.venv\Scripts\activate.bat
     ```
   * **Linux / macOS:**
     ```bash
     source ../.venv/bin/activate
     ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

---

## 4. Centralized Configuration & Environment Management

Configuration is handled by `app.core.config.Settings` using **Pydantic Settings**.

Copy `.env.example` to `.env` in the `backend/` directory:

```bash
cp .env.example .env
```

### Supported Environments (`APP_ENV`)
* **`development`**: Permissive defaults for rapid local development.
* **`testing`**: Optimized for isolated automated unit/integration tests.
* **`production`**: Strict security enforcement:
  * Rejects `DEBUG=True`.
  * Rejects default dummy secret keys and requires `SECRET_KEY` with $\ge 32$ characters.
  * Rejects wildcard `*` in `CORS_ORIGINS` when credentials are permitted.
  * Requires `QDRANT_API_KEY` for remote/cloud Qdrant clusters.
  * Requires `LLM_API_KEY` for cloud LLM providers (`openai`, `anthropic`, `azure_openai`).
  * Emits structured JSON logs.

### Key Environment Variables
* `APP_ENV`: `development` | `testing` | `production`
* `SECRET_KEY`: Cryptographic signing secret (wrapped in `SecretStr` to avoid accidental exposure).
* `CORS_ORIGINS`: Comma-separated list or JSON list of permitted frontend origins.
* `TRUSTED_HOSTS`: Allowed HTTP Host headers.
* `QDRANT_URL`: URL for local (`http://localhost:6333`) or cloud Qdrant.
* `LLM_PROVIDER`: `openai` | `anthropic` | `ollama` | `vllm` | `local` | `custom`.
* `LOCAL_LLM_BASE_URL`: Endpoint for local LLM inference (e.g. `http://localhost:11434/v1`).
* `LOG_LEVEL`: `DEBUG` | `INFO` | `WARNING` | `ERROR` | `CRITICAL`.
* `LOG_JSON`: `true` | `false` (defaults to `true` in production).

---

## 5. Running the Application

### Option A: Using Uvicorn directly
From the `backend/` directory:
```bash
uvicorn app.main:app --reload --port 8000 --host 0.0.0.0
```

### Option B: Using the runner script
From the `backend/` directory:
```bash
python scripts/run_dev.py
```

The service endpoints:
* **Interactive OpenAPI Docs:** [http://localhost:8000/docs](http://localhost:8000/docs) (disabled in production if debug is off)
* **ReDoc Documentation:** [http://localhost:8000/redoc](http://localhost:8000/redoc)
* **Health Check Endpoint:** [http://localhost:8000/health](http://localhost:8000/health)
* **Versioned Health Endpoint:** [http://localhost:8000/api/v1/health](http://localhost:8000/api/v1/health)

---

## 6. Running Tests

Execute pytest from the project root or `backend/` directory:

```bash
pytest backend/tests -v
```

---

## 7. Production Deployment Security & Architecture Boundaries

> [!IMPORTANT]
> **Current Application Status:** The centralized configuration and logging security foundation (Step 2) is verified and hardened. However, the complete Secure RAG application is in active modular development and is **not yet fully production-ready**. Subsequent backend steps will implement database persistence, vector indexing, document ingestion, authentication, and RAG pipelines.

### Implemented Protections (Application / Configuration Layer)
The backend enforces these safeguards at runtime:
* **Fail-Closed Production Validation:** At startup, `validate_production_safety` halts execution if `DEBUG=True`, if `SECRET_KEY` is a default/short value ($< 32$ chars), if wildcard CORS origins are paired with credentials, if trusted hosts are wildcards, or if remote Qdrant / cloud LLM providers lack credentials.
* **Universal Secret Redaction:** `SensitiveDataFilter` masks known active secret keys (`SECRET_KEY`, `QDRANT_API_KEY`, `LLM_API_KEY`, `EMBEDDING_API_KEY`) even when explicitly accessed or unmasked via `.get_secret_value()`, along with tokens (`sk-...`, `ant-...`, `eyJ...`, `Bearer ...`).
* **Traceback Sanitization:** Exception messages and stack traces scrub sensitive credentials in console and JSON loggers.
* **Host Header Defense:** `TrustedHostMiddleware` rejects untrusted HTTP Host headers in production.
* **Documentation Lockdown:** Interactive Swagger UI (`/docs`), ReDoc (`/redoc`), and OpenAPI schema (`/openapi.json`) are automatically disabled in production.
* **Project-Root Log Isolation:** Logs write exclusively to `backend/logs/` using root-independent paths, keeping the project root clean and git history untainted.

### Deployment Responsibilities (Infrastructure / Ops Layer)
Production operations must ensure the following external security controls:
1. **TLS / HTTPS Termination:** Uvicorn does not manage SSL/TLS certificates directly. An edge reverse proxy or ingress controller (e.g., Nginx, Caddy, Cloudflare, AWS ALB) must terminate HTTPS, enforce HTTP Strict Transport Security (HSTS), and redirect HTTP to HTTPS.
2. **Secure Secret Injection:** Secrets (`SECRET_KEY`, `QDRANT_API_KEY`, `LLM_API_KEY`, `EMBEDDING_API_KEY`) must never be written to files on disk in production. Use managed secrets storage (e.g., AWS Secrets Manager, HashiCorp Vault, Kubernetes Secrets) injected as environment variables into the container runtime.
3. **Network Isolation & Firewalls:**
   * Vector database ports (Qdrant `6333`/`6334`) and local LLM ports (Ollama `11434`) must never be exposed to the public internet. They must reside in isolated private VPC subnets.
   * Firewall rules should restrict ingress to backend port `8000` exclusively from the trusted reverse proxy / load balancer.
4. **Access Control & RBAC Policies:** User authentication (JWT issuance/validation), tenant isolation, and document-level permission checks are application-level logic scheduled for subsequent backend implementation steps.
5. **WAF & Rate Limiting:** External endpoints should be protected by a Web Application Firewall (WAF) with rate limiting and DDoS mitigation.
