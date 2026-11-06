# Known limitations

- The current detector uses phrase patterns and transparent rules. There is no trained or calibrated text classifier, so model confidence is `not_available` and the score is not a probability.
- URL checks inspect the origin, HTTPS scheme, shortener membership, domain depth, Punycode, and seeded lookalikes. The application does not fetch URLs, follow redirects, inspect page content, or safely determine a final destination.
- Reputation adapters are implemented but unverified because no Google Safe Browsing or VirusTotal key is configured. Unconfigured providers are marked skipped; no mock result is returned.
- OpenAI is behind an explanation provider interface, but its Responses API call is unverified because no API key is configured. The explanation cannot change score or evidence.
- The pattern/trusted-domain catalog is English only. Hindi/Kannada, OCR, screenshot ingestion, PDF reports, email headers, admin replay, model evaluation, and notification alerts are not implemented.
- PostgreSQL migrations and Docker Compose are authored but not run. Backend tests use SQLite in-memory only.
- The API is synchronous for investigations; status polling currently reports `completed`. There is no durable job queue.
- The history UI can list and reopen reports. Search/filter and single-report delete UI are not complete, although the API supports query filters and delete.
- The dashboard chart and icon imports create one larger production JavaScript bundle; Vite warns at 500 kB.
- Local rate limiting is in-process only. A deployed service needs gateway limits, secure cookie settings, TLS, secrets management, and operational review.
