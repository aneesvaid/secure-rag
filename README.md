
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

## Planned Technology Stack

- Python
- FastAPI
- PostgreSQL
- pgvector
- Sentence Transformers
- LLM integration
- Pytest

## Project Status

Early development — environment setup completed.

## Security Principle

Document permissions must be enforced before retrieved content is passed to the language model.
