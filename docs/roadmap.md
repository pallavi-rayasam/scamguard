# Roadmap

## Tier 1 — MVP

- [x] Account registration/login foundation, Argon2, cookie JWT, CSRF token, ownership checks
- [x] Text/SMS/WhatsApp/URL/email/conversation/payment/transaction input modes through a common scanner endpoint
- [x] English seeded Indian scam categories and pattern-based classification
- [x] Deterministic LangGraph stages, explicit run statuses, evidence provenance, and weighted score
- [x] Recommendations, report history, feedback, dashboard counts, privacy deletion endpoint
- [x] Local URL structure checks and reputation-provider adapters with explicit unavailability
- [ ] Separate URL fetch worker with SSRF-safe DNS pinning and redirect limits
- [ ] Search/filter/delete interactions in history UI and dedicated pre-transaction fields
- [ ] PostgreSQL-backed integration run and complete endpoint contract suite

## Tier 2 — Should complete

- [ ] Screenshot OCR with magic-byte, size, and content validation; embedded links remain unopened
- [ ] PDF report export
- [ ] Admin analytics/replay UI and failure/processing-time metrics
- [ ] Held-out labelled evaluation set and baseline/LLM-only/multi-agent comparison
- [ ] E2E Playwright tests, including PDF download

## Tier 3 — If time allows

- [ ] Hindi/Kannada UI and pattern catalog after translation and evaluation work
- [ ] Verified-source notifications
- [ ] Deeper email-header checks and wider browser coverage
