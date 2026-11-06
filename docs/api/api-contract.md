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
| `GET /api/investigations` | user | `200` own reports; accepts `q`, `risk_level`, `limit`, `offset` |
| `GET /api/investigations/{id}` | owner | `200` report and redacted content; `404` when absent/not owned |
| `GET /api/investigations/{id}/report` | owner | `200` report |
| `GET /api/investigations/{id}/status` | owner | `200`, currently synchronous and always complete |
| `DELETE /api/investigations/{id}` | owner + CSRF | `204` hard deletes one investigation |
| `DELETE /api/me/data` | user + CSRF | `204` deletes account and owned data |
| `POST /api/feedback` | user + CSRF | `201`; rating is `correct`, `incorrect`, or `uncertain` |
| `GET /api/dashboard/statistics` | user | `200` counts from persisted records only |
| `GET /api/scam-categories` | no | `200` versioned English seed categories |
| `GET /api/scam-awareness` | no | `200` English advisory items |
| `GET /api/admin/analytics` | admin | `200` current aggregate counts |
| `GET /api/admin/system-health` | admin | `200` configuration availability (database not probed) |

Investigation input types currently accepted: `text`, `sms`, `whatsapp`, `url`, `email`, `conversation`, `payment_request`, and `transaction`. The scanner uses the single `/text` endpoint with the selected `input_type`.

## Report shape

Reports include `category`, deterministic `risk_score`, `risk_level`, `score_is_probability: false`, `model_confidence`, `evidence_strength`, `data_availability`, `findings`, `evidence`, `agents`, `urls`, `threat_intel_results`, `redactions`, `recommendations`, `explanation`, and `limitations`. Agent status is one of `completed`, `skipped`, `failed`, or `timed_out`. Evidence carries a source, timestamp, detail, and verification level.

The score thresholds are Low `0–24`, Moderate `25–49`, High `50–74`, Critical `75–100`. A provider's negative or missing match is never presented as proof of safety.

## Not implemented yet

Dedicated `/url`, `/screenshot`, `/email`, `/conversation`, and `/transaction` paths; upload validation/OCR; `/report.pdf`; dashboard trends; admin redacted replay; evaluation execution; WebSocket/SSE status; pagination totals; and formal request/response models for every route.
