# API contract

Base path: `/api`. Interactive OpenAPI docs are served at `/docs` when the FastAPI app is running. Mutations require the double-submit CSRF token returned by `GET /api/auth/csrf` in the `X-CSRF-Token` header. Authenticated routes use the `scamguard_session` httpOnly cookie. JSON errors use FastAPI validation/status responses.

## Implemented routes

| Method and path | Auth | Status/result |
|---|---|---|
| `GET /health` | no | `200` service status |
| `GET /api/auth/csrf` | no | `200` token and CSRF cookie |
| `POST /api/auth/register` | CSRF | `201` user and session cookie; `409` duplicate email |
| `POST /api/auth/login` | CSRF | `200` user and session cookie; `401` invalid credentials |
| `POST /api/auth/logout` | CSRF | `204`, clears cookies |
| `GET /api/auth/me` | user | `200` current user |
| `POST /api/investigations/text` | user + CSRF | `201` synchronous report; body has `text` and `input_type` |
| POST /api/investigations/image | user + CSRF | 201 stored screenshot report; JPEG/PNG magic bytes, 5 MB cap; OCR unavailable/timeout returned clearly; extracted links are not fetched or reputation-queried |
| `GET /api/investigations` | user | `200` own reports; accepts `q`, `risk_level`, `limit`, `offset` |
| `GET /api/investigations/{id}` | owner | `200` report and redacted content; `404` when absent/not owned |
| `GET /api/investigations/{id}/report` | owner | `200` report |
| GET /api/investigations/{id}/report.pdf | owner/admin | 200 stored report as PDF attachment; optional IANA time_zone query for local timestamps; 404 absent/not authorized |
| `GET /api/investigations/{id}/status` | owner | `200`, currently synchronous and always complete |
| `DELETE /api/investigations/{id}` | owner + CSRF | `204` hard deletes one investigation |
| `DELETE /api/me/data` | user + CSRF | `204` deletes account and owned data |
| `POST /api/feedback` | user + CSRF | `201`; rating is `correct`, `incorrect`, or `uncertain` |
| `GET /api/dashboard/statistics` | user | `200` counts from persisted records only |
| `GET /api/scam-categories` | no | `200` versioned English seed categories |
| `GET /api/scam-awareness` | no | `200` English advisory items |
| `GET /api/admin/analytics` | admin | `200` current aggregate counts |
| `GET /api/admin/system-health` | admin | `200` configuration availability (database not probed) |

Investigation input types currently accepted: text, sms, whatsapp, url, email, conversation, payment_request, transaction, and screenshot. Screenshots use input_type=screenshot through the multipart image endpoint. The scanner uses the single /text endpoint for the other text-based input types.

## Report shape

Reports include nullable `category`, deterministic `risk_score`, `risk_level`, `score_is_probability: false`, `model_confidence`, `evidence_strength`, `data_availability`, `findings`, `evidence`, `agents`, `urls`, `url_scans`, `threat_intel_results`, `redactions`, `recommendations`, `explanation`, and `limitations`. When no seeded scam category matches, `category` is null and the UI says “No scam pattern detected.” Evidence-strength labels are Strong (a verified finding), Limited (heuristic findings only), and Weak (no verified or heuristic findings); LLM-inferred findings do not count. Agent status is one of `completed`, `skipped`, `failed`, or `timed_out`. Provider results may separately be `unavailable`. Every agent record includes `duration_ms`, `tools_used`, and `error`. Evidence carries a source, UTC timestamp, detail, and verification level. API `created_at` timestamps include UTC offset; clients render them in local time.

The internal URL scanner service exposes `GET /health` and `POST /scan` on port 8001 within the Compose network. It is not published to the host. `POST /scan` accepts one HTTP(S) URL, validates public DNS answers and pins the connection before a HEAD request. A capped GET is used only when HEAD is unsupported and the declared content type is text. It does not return page content or execute scripts. Provider lookups receive only the validated origin and return `unavailable` when unconfigured, timed out, failed, or rate-limited.

The score thresholds are Low `0–24`, Moderate `25–49`, High `50–74`, Critical `75–100`. A provider's negative or missing match is never presented as proof of safety.

`GET /api/dashboard/statistics` includes `category_distribution` from persisted rows with a matched scam category. Null categories and the legacy `other_suspicious` placeholder are excluded.

## Not implemented yet

Dedicated public /url, /email, /conversation, and /transaction paths; dashboard trends; admin redacted replay; WebSocket/SSE status; pagination totals; and formal request/response models for every route.
