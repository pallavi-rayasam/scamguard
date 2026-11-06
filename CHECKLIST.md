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
| Threat-intel integrations | implemented; mocked tests pass; live calls not verified | URL scanner provider clients cache, timeout, retry 429 once, and return explicit `unavailable`; no provider keys configured |
| OpenAI explanation provider | implemented; not verified | Responses API adapter; `OPENAI_API_KEY` is not configured, so no call made |
| SSRF guard transport | Pass | `url_scanner/ssrf_guard.py`; tests cover non-public IP ranges, mixed DNS, pinning, redirects, methods, size, TLS hostname validation, and unavailable DNS |
| URL scanner service, analysis, provider clients | Pass (unit/integration tests) | `url_scanner/`; internal API is wired into backend workflow and Compose; live provider calls are not verified |
| URL scanner Docker Compose runtime | Not verified | Docker is unavailable; scanner container and PostgreSQL-backed stack have not been started |
| Evaluation harness | implemented; measured on authored set | `ml/evaluate.py`; 32 hand-labelled examples, 20/6/6 split; see `docs/testing/evaluation-report.md`; LLM-only skipped without key |
| OCR, PDF export, admin replay | planned | Tier 2 work |
| Backend, evaluation, and URL scanner tests | Pass | `69 passed` with portable Python 3.13.17; includes auth, rate limits, prompt injection, agent failures/timeouts, redaction, scanner providers, and SSRF cases; see `docs/testing/test-report.md` |
| Frontend tests/build | verified | `1 passed`; production build succeeded with a bundle-size warning |
| Docker/PostgreSQL deployment | not verified | Docker is unavailable; PostgreSQL service/migrations not run |
| GitHub remote/push | blocked | repository URL not provided |
| `feature/evaluation` | Pass | Commit `fa938c3` was merged into `develop` |
| `feature/url-scanner` commit | Not verified | The commit request for the staged SSRF guard was rejected with “rejected by user”; scanner service work remains uncommitted on this branch |
