# Agentic AI-Based Proactive Scam Detection and Prevention System

A VTU final-year project for investigating suspicious messages, URLs, conversations, and pre-transaction descriptions. The system is advisory: it does not initiate payments or verify a recipient's identity.

## Project status

Architecture and foundation are being established. See [CHECKLIST.md](CHECKLIST.md) for implementation and verification status. Features are only marked verified after they have been run.

## Planned stack

- React, TypeScript, Vite, Tailwind CSS
- Python, FastAPI, Pydantic, SQLAlchemy, Alembic
- PostgreSQL for application data
- LangGraph orchestration with a deterministic router and scorer
- Optional Ollama local explanation provider behind a provider interface

## Local development

Prerequisites: Python 3.12+, Node.js 24+, npm 11+, and Docker Compose for the PostgreSQL-backed full stack.

Copy `.env.example` to `.env`, set a strong `APP_SECRET_KEY`, then start services with:

```powershell
docker compose up --build
```

The API is intended at `http://localhost:8000`; OpenAPI docs at `/docs`; the web UI at `http://localhost:5173`.

Without Docker, install the backend dependencies in a virtual environment and run the API from `backend/`. Install frontend dependencies in `frontend/` and run `npm run dev`. Exact commands will be updated as the foundation lands.

## Configuration

Secrets belong in environment variables and must never be committed. External threat-intel providers are optional; unconfigured or failed providers must appear as unavailable in reports. The initial LLM default is Ollama local, and LLM explanations are never treated as evidence.

## Verification

No application build or tests have been run yet. The current workspace lacks Python and Docker. These constraints will be recorded in the checklist and final verification report.

