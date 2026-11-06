# Agentic AI-Based Proactive Scam Detection and Prevention System

A VTU final-year project for investigating suspicious messages, URLs, conversations, and pre-transaction descriptions. The system is advisory: it does not initiate payments or verify a recipient's identity.

## Project status

Architecture and the first foundation implementation are in place. See [CHECKLIST.md](CHECKLIST.md) for implementation and verification status. Features are only marked verified after they have been run.

## Planned stack

- React, TypeScript, Vite, Tailwind CSS
- Python, FastAPI, Pydantic, SQLAlchemy, Alembic
- PostgreSQL for application data
- LangGraph orchestration with a deterministic router and scorer
- Optional OpenAI explanation provider behind a provider interface

## Local development

Prerequisites: Python 3.12 or 3.13, Node.js 24+, npm 11+, and Docker Compose for the PostgreSQL-backed full stack.

Copy `.env.example` to `.env`, replace all placeholder secrets (especially `APP_SECRET_KEY` and `POSTGRES_PASSWORD`), then start services with:

```powershell
docker compose up --build
```

The API is served at `http://localhost:8000`; OpenAPI docs at `/docs`; the web UI at `http://localhost:5173`.

Without Docker, from the repository root run `python -m venv backend/.venv`, activate it, then `pip install -e "backend[dev]"`. Set the values from `.env` in your shell. Change into `backend/`, run `alembic upgrade head`, then `uvicorn app.main:app --reload`. In another terminal, change into `frontend/` and run `npm ci` and `npm run dev`.

## Configuration

Secrets belong in environment variables and must never be committed. External threat-intel providers are optional; unconfigured or failed providers must appear as unavailable in reports. The selected provider is OpenAI. LLM explanation calls remain disabled until `OPENAI_API_KEY` is supplied; LLM text is never treated as evidence.

## Verification

Verification completed on 2026-11-06: all 13 backend tests and the frontend test pass, and the production build succeeds with a bundle-size warning. Docker/PostgreSQL startup and migrations remain unverified because Docker is unavailable. See [the test report](docs/testing/test-report.md) for exact coverage and limitations.

