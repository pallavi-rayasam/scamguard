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
| LangGraph stages and audit trail | Pass | Seven requested agents are separate graph nodes; four-state run contract, provider outcomes, deterministic routing, redaction, and failure fallback are covered by workflow tests |
| `feature/agents-audit` | Pass | Focused workflow/scanner/API suite: 38 passed; full backend suite: 86 passed; legacy unavailable rows migrate to failed on SQLite |
| Threat-intel integrations | implemented; mocked tests pass; live calls not verified | URL scanner provider clients cache, timeout, retry 429 once, and return explicit `unavailable`; no provider keys configured |
| OpenAI explanation provider | implemented; not verified | Responses API adapter; `OPENAI_API_KEY` is not configured, so no call made |
| SSRF guard transport | Pass | `url_scanner/ssrf_guard.py`; 37 focused tests pass, including IPv6 loopback/mapped/link-local, metadata, legacy numeric IPv4, userinfo, schemes/ports, mixed DNS, redirect revalidation/cap, pinning, and request limits |
| `feature/ssrf-hardening` | Pass | Full backend suite: 79 passed; three new legacy numeric-IP tests exposed a real DNS-resolution gap, fixed by rejecting ambiguous numeric hosts before resolution |
| URL scanner service, analysis, provider clients | Pass (unit/integration tests) | `url_scanner/`; internal API is wired into backend workflow and Compose; live provider calls are not verified |
| URL scanner Docker Compose runtime | Not verified | Docker is unavailable; scanner container and PostgreSQL-backed stack have not been started |
| Evaluation harness | Pass | Loader requires text/label/category/source/author/split; exact and near-duplicate test/train leakage checks; 2,000 bootstrap 95% CIs; stratified 5-fold CV on train+validation; current data size 32; see `docs/testing/evaluation-report.md`. |
| OCR, PDF export, admin replay | planned | Tier 2 work |
| Backend, evaluation, and URL scanner tests | Pass | `154 passed in 12.11s` with the project `.venv` Python 3.12.0; see `docs/testing/test-report.md`. |
| Frontend tests/build | Pass | `12 passed` across 3 Vitest files; production build succeeded with the existing >500 kB chunk warning. Includes URL-provider and auth validation, timeout, and loading-reset cases. |
| Docker/PostgreSQL deployment | not verified | Docker is unavailable; PostgreSQL service/migrations not run |
| GitHub remote/push | blocked | repository URL not provided |
| `feature/evaluation` | Pass | Commit `fa938c3` was merged into `develop` |
| `feature/url-scanner` | Pass | Merge commit `1e282e4` is present on `develop`; the Step 0 worktree was clean |
| `feature/transaction-conversation` | Pass | Focused transaction/conversation suite: 62 passed (15 scam + 15 legitimate transaction examples; 15 scam + 17 legitimate conversation examples). Full backend suite: 148 passed in 10.16s using `.venv` Python 3.12. Frontend suite: 1 passed; production build succeeded. Includes genuine bill reminder false-positive checks. |
| `feature/evaluation-v2` | Pass | Focused evaluation suite: 12 passed; full backend suite: 154 passed. Seed-42 test messages unchanged; dataset remains 32 rows. Evaluation report contains held-out metrics with 95% bootstrap CIs and 5-fold train+validation CV; LLM-only skipped because no key is configured. `backend/pyproject.toml` declares `langgraph` and `scikit-learn`. |
| `feature/frontend-url-results` | Pass | Vitest: 6 passed across 2 files; production build succeeded (634.96 kB JS chunk, size warning). Report renders provider statuses, verified/heuristic badges, and `no known threat found; not verified safe` for checked clean results. |
| `feature/auth-error-messages` | Pass | TestClient reproduction returned 422 for the browser-accepted address `member@localhost`; `loc=[body,email]`. Form payload keys match the backend. Vitest: 12 passed across 3 files; includes readable 422 errors, 15-second abort, client rules, and finally-reset loading behavior. |
