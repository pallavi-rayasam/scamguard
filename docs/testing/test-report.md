# Verification report

Date: 2026-11-06

## Results

| Area | Result | Evidence |
|---|---|---|
| Backend and evaluation tests | Pass | `19 passed in 6.24s` using portable Python 3.13.17; SQLite in-memory DB |
| Frontend tests | Pass | `1 passed` with Vitest 5.1.0 and Testing Library |
| Frontend production build | Pass with warning | Vite 8.3.6 build succeeded; minified JS chunk is 630.44 kB (186.12 kB gzip) |
| Browser visual smoke check | Not verified | No targetable browser window was available through Windows UI automation |
| Evaluation run | Pass on demonstration data | 32 hand-labelled examples, seed 42; see `evaluation-report.md`; LLM-only skipped because no key is configured |
| npm dependency audit | Pass | `0 vulnerabilities` after upgrading Vite, Vitest, React, Recharts, and related pins |
| PostgreSQL migration/startup | Not verified | Docker and PostgreSQL are unavailable in the environment |
| Google Safe Browsing / VirusTotal | Not verified | No API keys configured; adapters return explicit skipped status |
| OpenAI Responses API | Not verified | No `OPENAI_API_KEY` configured; no request sent |
| URL isolation, SSRF, redirect handling | Not implemented | No URL fetcher or outbound URL resolution in this phase |
| OCR/PDF/E2E/Playwright | Not verified | Tier 2 and wider E2E are not implemented |

## Backend test coverage

Tests cover redaction of OTP/credentials before an LLM request, URL origin extraction, seeded category detection, weighted score thresholds, HTTPS heuristic, deterministic LangGraph completion/skips, registration/login/session, CSRF rejection, request validation, report persistence, redacted stored content, threat-intel timeout/failure handling, conflicting provider results, prompt-injection isolation, deterministic train/validation/test splitting, metric calculations, baseline fit, and local full-pipeline evaluation. They do not cover PostgreSQL behavior, real external provider calls, rate-limit behavior, database migration execution, or cross-user deletion/access in a live server.

## Limitations

Passing tests show only the listed cases. They do not establish detection accuracy, provider availability, production security, or safety of unknown URLs. No labelled held-out dataset or calibrated classifier has been used, so no performance metric is claimed.
