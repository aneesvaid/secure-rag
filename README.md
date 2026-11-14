
# SecureRAG

A secure multi-tenant Retrieval-Augmented Generation (RAG) system with role-based document access control.

## Project Overview

SecureRAG is an enterprise knowledge assistant designed to ensure that users can only retrieve documents they are authorized to access.

## Core Features

- Multi-tenant architecture
- Role-based access control (RBAC)
- Permission-aware document retrieval
- Secure document ingestion
- AI-powered question answering
- Audit logging
- Security testing

## Technology Stack

- **Backend:** Python (FastAPI, Pydantic Settings, Uvicorn)
- **Database:** PostgreSQL (SQLAlchemy 2.x, psycopg 3 driver)
- **LLM Support:** Dual cloud API providers (OpenAI, Anthropic) and local inference engines (Ollama, vLLM)
- **Frontend:** React, Vite, Tailwind CSS (Emerald Slate theme)
- **Testing:** Pytest

## Supported Python Runtimes

- **Testing Environment:** Python 3.15 (Windows CPython)
- **Supported Deployment Versions:** Python 3.11, 3.12, 3.13, 3.14, 3.15

## Project Status

Modular development in progress.
- **Frontend:** Completed prototype UI.
- **Backend Step 1:** Backend directory structure and baseline FastAPI initialization completed.
- **Backend Step 2:** Centralized configuration, environment management, and logging security completed and verified.
- **Backend Step 3.1:** PostgreSQL server installation and database setup completed.
- **Backend Step 3.2:** SQLAlchemy 2.x engine, connection pool, session factory, FastAPI dependency, and connectivity verification completed.
- **Remaining Steps:** Authentication/RBAC, User & Document models, ingestion/chunking, retrieval pipelines, and security testing.

> [!NOTE]
> The backend configuration and logging foundation is verified and hardened. However, the complete Secure RAG application is in active development and is **not yet fully production-ready**.

## Security Principle

Document permissions must be enforced before retrieved content is passed to the language model.
