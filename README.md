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

Prerequisites: Python 3.12 or 3.13, Node.js 24+, and npm 11+. Local development uses SQLite and does not require Docker or a PostgreSQL server. From the repository root:

```powershell
Copy-Item .env.example .env
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

Copy the generated value into `APP_SECRET_KEY` in `.env` (it must be at least 32 characters). Set `DATABASE_URL=sqlite:///./local.db`; keep `COOKIE_SECURE=false` for localhost. The SQLite file is created in `backend/` when the migration runs. The essential local settings are:

```dotenv
APP_ENV=development
APP_SECRET_KEY=<paste-the-generated-random-value-here>
COOKIE_SECURE=false
DATABASE_URL=sqlite:///./local.db
FRONTEND_ORIGIN=http://localhost:5173
URL_SCANNER_URL=http://localhost:8001
```

Install and start the backend; the same Alembic migrations are used with SQLite and PostgreSQL:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e "backend[dev]"
Set-Location backend
alembic upgrade head
python -m app.db.seed
uvicorn app.main:app --reload
```

In another terminal start the frontend: `Set-Location frontend`, `npm ci`, then `npm run dev`. The API is at `http://localhost:8000`, OpenAPI docs at `/docs`, and the UI at `http://localhost:5173`.

For PostgreSQL through Docker Compose, set `POSTGRES_DB`, `POSTGRES_USER`, and a strong `POSTGRES_PASSWORD` in `.env`; Compose overrides `DATABASE_URL` with its PostgreSQL service URL. Start it with `docker compose up --build`. Production must also set `APP_SECRET_KEY` and an explicit PostgreSQL `DATABASE_URL`; do not use the local SQLite URL in production. PostgreSQL connection attempts time out after three seconds and return HTTP 503 with `Database unavailable` if the server cannot be reached.

For URL scanning outside Compose, also run `pip install -r url_scanner/requirements.txt` and start `uvicorn url_scanner.main:app --host 127.0.0.1 --port 8001` from the repository root. Set `URL_SCANNER_URL=http://localhost:8001` for the backend. Compose starts the scanner on its private service network without publishing port 8001 to the host.

## Configuration

Secrets belong in environment variables and must never be committed. `APP_SECRET_KEY` is required for authentication and must contain at least 32 characters; generate one with the command above and keep it private. External threat-intel providers are optional; unconfigured or failed providers must appear as unavailable in reports. The selected provider is OpenAI. LLM explanation calls remain disabled until `OPENAI_API_KEY` is supplied; LLM text is never treated as evidence.

## Verification

Run backend checks from `backend/` with `..\.venv\Scripts\python.exe -m pytest`. The test report records the latest verification counts and marks live PostgreSQL/Docker behavior as not verified when unavailable. See [the test report](docs/testing/test-report.md) for coverage and limitations.

