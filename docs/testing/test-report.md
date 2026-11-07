# Verification report

Date: 2026-11-07

## Results

| Area | Result | Evidence |
|---|---|---|
| Backend, evaluation, and URL scanner tests | Pass | `158 passed in 7.50s` using the project `.venv` Python 3.12.0; in-memory SQLite plus a real SQLite-file migration smoke check |
| Frontend tests | Pass | `14 passed` across 3 Vitest files in 5.94s, including URL provider states, auth validation/error rendering, request timeout, busy-state reset, and database outage rendering |
| Frontend production build | Pass with warning | Vite 8.3.6 build succeeded; minified JS chunk is 637.91 kB (188.29 kB gzip) |
| Local SQLite setup | Pass | `.env` uses `sqlite:///./local.db`; all Alembic revisions completed on a temporary SQLite file at `0003_agent_status_contract` and created 13 application tables. SQLite runtime enables foreign-key enforcement. |
| PostgreSQL connection failure handling | Pass (bounded local reproduction); live PostgreSQL not verified | PostgreSQL engine is configured with `connect_timeout=3`; an auth registration against unreachable localhost PostgreSQL returns HTTP 503 `Database unavailable` in 3.12 seconds. Docker and a live PostgreSQL server are unavailable. |
| Browser visual smoke check | Not verified | No targetable browser window was available through Windows UI automation |
| Evaluation run | Pass on demonstration data | 32 hand-labelled examples, seed 42; see `evaluation-report.md`; LLM-only skipped because no key is configured |
| SSRF guard tests | Pass | `37 passed` with public DNS/socket operations replaced by deterministic test doubles |
| npm dependency audit | Pass | `0 vulnerabilities` after upgrading Vite, Vitest, React, Recharts, and related pins |
| Agent status migration | Pass | Alembic upgrade and legacy unavailable-row conversion passed against a temporary SQLite database; PostgreSQL migration/startup is not verified |
| PostgreSQL migration/startup | Not verified | Docker and PostgreSQL are unavailable in the environment |
| Google Safe Browsing / VirusTotal | Not verified | No API keys configured; adapters return explicit `unavailable` status |
| OpenAI Responses API | Not verified | No `OPENAI_API_KEY` configured; no request sent |
| URL scanner container runtime | Not verified | Docker is unavailable; container networking and runtime isolation have not been exercised |
| OCR/PDF/E2E/Playwright | Not verified | Tier 2 and wider E2E are not implemented |

## Backend test coverage

Database-specific verification: registration against the configured unreachable PostgreSQL service initially had no response within an 8-second bound. With the new engine settings, the same endpoint returns HTTP 503 `Database unavailable` in 3.12 seconds. The PostgreSQL engine uses a three-second connect timeout; the development-only `localhost` case pins one loopback address so dual-stack retries do not multiply that wait. Alembic revisions 0001–0003 were run on a temporary file-backed SQLite database and created all 13 application tables. Live PostgreSQL and Docker startup remain not verified.

The first full backend test run in this checkout yielded 155 passed and 3 failed because three workflow tests followed `.env`'s configured but stopped URL scanner. The tests now disable live scanner access by default; tests using scanner behavior supply fakes explicitly. The final backend suite passed all 158 tests.

Tests cover redaction of OTP/credentials before an LLM request, URL origin extraction, seeded category detection, weighted score thresholds, HTTPS and shortener/typosquatting heuristics, deterministic LangGraph completion/skips, registration/login/session, unauthorized access, CSRF rejection, backend and scanner rate limits, request validation, report persistence, redacted stored content, threat-intel timeout/failure handling, provider throttling and unavailable results, conflicting provider results, prompt-injection isolation, agent failure and timeout paths, seven separate agent graph nodes, separate /analyze and /reputation calls, four-state status contract, LLM provider-setup failure fallback, deterministic train/validation/test splitting, metric calculations, baseline fit, local full-pipeline evaluation, SSRF range blocking (including metadata and IPv4-mapped IPv6), legacy decimal/hex/octal IP rejection before DNS, userinfo and scheme/port rejection, mixed DNS answers, pinned-IP connections, private redirects and per-hop revalidation, redirect caps, HEAD and bounded text-only GET behavior, and request/response caps. The migration was exercised against an in-memory SQLite database.  The pre-transaction and conversation tests add 62 cases: 15 scam and 15 legitimate transaction examples, plus 15 scam and 17 legitimate conversation examples. They cover UPI collect requests, advance-fee job fraud, digital arrest, credential requests, pressure escalation, identity changes, genuine bank/OTP notices, ordinary chats, and benign bill reminders.Frontend URL report tests cover unavailable, checked, rate-limited, flagged, and clean provider states, including verification badges and the not-verified-safe wording. Auth UI/service tests cover FastAPI validation detail formatting, the 15-second request timeout, client/backend field validation, and loading reset after timeout/error. Evaluation-v2 adds required author metadata, test/train exact and near-duplicate leakage checks, 2,000 stratified paired bootstrap percentile replicates for 95% CIs, and five-fold cross-validation over train+validation only; it includes a regression test that preserves the exact seed-42 test rows and the 32-row dataset. They do not cover PostgreSQL behavior, real external provider calls, container networking at runtime, or cross-user deletion/access against a live PostgreSQL server.

## Limitations

Passing tests show only the listed cases. They do not establish production security or safety of unknown URLs. The authored evaluation set is small and illustrative; its held-out test split has only three examples per class, so its metrics are not reliable estimates of real-world performance. External LLM/provider calls were not made because credentials are not configured.
