# Known limitations

- The current detector uses phrase patterns and transparent rules. There is no trained or calibrated text classifier, so model confidence is `not_available` and the score is not a probability.
- URL checks inspect HTTPS, shorteners, domain depth, Punycode, and lookalikes against the small seeded organization-domain list. The separate scanner uses pinned public-IP connections, manually revalidates redirects, and only performs HEAD or a capped GET for text content when HEAD is unsupported. It does not execute scripts or retain/return response bodies.
- The scanner service is integrated through an internal Compose URL and is not host-published. Docker startup and live external provider calls remain unverified in this environment. Reputation lookups disclose only the URL origin and return `unavailable` when no key or provider response is available.
- Reputation adapters are implemented but unverified because no Google Safe Browsing or VirusTotal key is configured. Unconfigured providers are marked skipped; no mock result is returned.
- OpenAI is behind an explanation provider interface, but its Responses API call is unverified because no API key is configured. The explanation cannot change score or evidence.
- The pattern/trusted-domain catalog is English only. Hindi/Kannada, OCR, screenshot ingestion, PDF reports, email headers, admin replay, and notification alerts are not implemented. The new evaluation harness uses only a tiny synthetic authored dataset and does not establish generalization.
- PostgreSQL migrations and Docker Compose are authored but not run. Backend tests use SQLite in-memory only.
- The API is synchronous for investigations; status polling currently reports `completed`. There is no durable job queue.
- The history UI can list and reopen reports. Search/filter and single-report delete UI are not complete, although the API supports query filters and delete.
- The dashboard chart and icon imports create one larger production JavaScript bundle; Vite warns at 500 kB.
- Local rate limiting is in-process only. A deployed service needs gateway limits, secure cookie settings, TLS, secrets management, and operational review.
