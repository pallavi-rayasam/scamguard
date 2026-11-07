# Evidence strength

Evidence strength describes corroboration for the report's findings. It is separate from the deterministic risk score and does not describe probability.

| Label | Rule |
|---|---|
| **Strong** | At least one finding is marked `verified`. This is reserved for corroboration such as a provider confirming a known-threat match or a deterministic check that confirms a finding. |
| **Limited** | There is at least one `heuristic` finding and no verified finding. Heuristics may help identify risk, but their count never upgrades evidence strength. |
| **Weak** | There are no verified or heuristic findings. LLM-inferred findings alone remain Weak. |

Provider status is reported independently. An unavailable, skipped, failed, or clean provider lookup does not itself corroborate a scam finding. A clean result remains visible in provider results but does not become a verified finding. LLM-inferred content is never included in evidence-strength calculation.

Reports with no matched seeded scam category store `category = NULL`. The UI displays “No scam pattern detected,” and category distribution excludes null and legacy `other_suspicious` placeholders. This label is not a guarantee that content is safe.
