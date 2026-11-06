# Requirements and verification checklist

Statuses: `done` means the artifact exists; `not verified` means it has not been run; `blocked` means a missing external dependency or credential prevents implementation or verification.

| Requirement | Status | Evidence |
|---|---|---|
| Architecture, risk register, schema, phase plan | done | `docs/architecture/` |
| Git baseline and develop branch | done | `main` and `develop` local branches; initial commit |
| FastAPI foundation | implemented; partially verified | `backend/app/`; SQLite API tests pass, PostgreSQL startup is not verified |
| Authentication and persistence | implemented; partially verified | Argon2/JWT cookies/CSRF and CRUD paths; SQLite tests pass, PostgreSQL migration not run |
| React shell | implemented; verified | `frontend/`; build and Vitest pass |
| Deterministic detection and risk scoring | implemented; partially verified | seeded phrase rules and weighted score; tests pass; no calibrated ML model |
| LangGraph stages and audit trail | implemented; partially verified | deterministic router; per-stage status tests pass; provider failures not exercised |
| Threat-intel integrations | implemented; not verified | Safe Browsing and VirusTotal adapters; no API keys configured, so no external calls made |
| OpenAI explanation provider | implemented; not verified | Responses API adapter; `OPENAI_API_KEY` is not configured, so no call made |
| SSRF-protected URL fetch service | not implemented | URL fetching and redirect following are disabled; structure and reputation adapters only |
| Evaluation harness | implemented; measured on authored set | `ml/evaluate.py`; 32 hand-labelled examples, 20/6/6 split; see `docs/testing/evaluation-report.md`; LLM-only skipped without key |
| OCR, PDF export, admin replay | planned | Tier 2 work |
| Backend and evaluation tests | verified | `19 passed` with portable Python 3.13.17; see `docs/testing/test-report.md` |
| Frontend tests/build | verified | `1 passed`; production build succeeded with a bundle-size warning |
| Docker/PostgreSQL deployment | not verified | Docker is unavailable; PostgreSQL service/migrations not run |
| GitHub remote/push | blocked | repository URL not provided |
