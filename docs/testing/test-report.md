# Verification report

Date: 2026-11-07

## Results

| Area | Result | Evidence |
|---|---|---|
| Backend, evaluation, and URL scanner tests | Pass | `86 passed in 9.46s` using portable Python 3.13.17; SQLite in-memory DB |
| Frontend tests | Pass | `1 passed` with Vitest 5.1.0 and Testing Library |
| Frontend production build | Pass with warning | Vite 8.3.6 build succeeded; minified JS chunk is 630.44 kB (186.12 kB gzip) |
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

Tests cover redaction of OTP/credentials before an LLM request, URL origin extraction, seeded category detection, weighted score thresholds, HTTPS and shortener/typosquatting heuristics, deterministic LangGraph completion/skips, registration/login/session, unauthorized access, CSRF rejection, backend and scanner rate limits, request validation, report persistence, redacted stored content, threat-intel timeout/failure handling, provider throttling and unavailable results, conflicting provider results, prompt-injection isolation, agent failure and timeout paths, seven separate agent graph nodes, separate /analyze and /reputation calls, four-state status contract, LLM provider-setup failure fallback, deterministic train/validation/test splitting, metric calculations, baseline fit, local full-pipeline evaluation, SSRF range blocking (including metadata and IPv4-mapped IPv6), legacy decimal/hex/octal IP rejection before DNS, userinfo and scheme/port rejection, mixed DNS answers, pinned-IP connections, private redirects and per-hop revalidation, redirect caps, HEAD and bounded text-only GET behavior, and request/response caps. The migration was exercised against an in-memory SQLite database. They do not cover PostgreSQL behavior, real external provider calls, container networking at runtime, or cross-user deletion/access against a live PostgreSQL server.

## Limitations

Passing tests show only the listed cases. They do not establish production security or safety of unknown URLs. The authored evaluation set is small and illustrative; its held-out test split has only three examples per class, so its metrics are not reliable estimates of real-world performance. External LLM/provider calls were not made because credentials are not configured.
