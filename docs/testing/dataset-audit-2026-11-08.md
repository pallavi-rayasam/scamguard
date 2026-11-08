# Sourced candidate dataset audit — 8 November 2026

## Scope

Audited `ml/data/sourced_scam_candidates.csv` in the uploaded ScamShield source archive. This is a structural and provenance audit, not independent adjudication of every message.

## Structural results

| Check | Result |
|---|---:|
| Candidate rows | 300 |
| Empty message fields | 0 |
| Missing values in required six-column schema | 0 |
| Exact raw-string duplicates | 0 |
| Pairwise exact matches after NFKC/casefold/punctuation normalization | 9 |
| Pairwise near-duplicate matches | 266 |
| Total pairwise exact/near matches | 275 |
| Connected similarity clusters | 189 |
| Singleton clusters | 146 |
| Multi-row clusters | 43 |
| Redundant rows beyond one representative per cluster | 111 |
| Literal `http://`, `https://`, or `www.` strings | 0 |
| Rows containing redaction placeholders | 229 |

Similarity detection uses the same practical thresholds as the project's evaluation harness: normalized sequence similarity >= 0.92, or token Jaccard >= 0.85 when the smaller message has at least five tokens. Clusters are connected components, so two members of a cluster need not each directly match every other member.

## Source-label provenance

The embedded `original_label` metadata resolves to:

| Original source label | Rows | Treatment |
|---|---:|---|
| Hugging Face original label `1 (scam)` | 46 | Scam-labelled candidate |
| Mendeley `Smishing` | 253 | Smishing/scam candidate |
| Mendeley `spam` | 1 | Hold for manual adjudication; spam is not automatically synonymous with fraud |

The Hugging Face dataset card declares CC BY 4.0 and describes a mixture of English/Hinglish financial scam examples. The Mendeley dataset page declares CC BY 4.0 and describes 5,971 messages with 4,844 Ham, 489 Spam, and 638 Smishing labels. Its source labels should not be collapsed without preserving provenance.

Sources:
- Hugging Face dataset card: https://huggingface.co/datasets/bolewara/hinglish-scam-text-dataset
- Mendeley Data record: https://data.mendeley.com/datasets/f45bkkt8pr/1

## Category distribution

The supplied category field is provisional metadata, not independently reviewed ground truth. It is heavily skewed:

| category               |   count |   percentage |
|:-----------------------|--------:|-------------:|
| lottery_prize          |     187 |        62.33 |
| banking_phishing       |      39 |        13    |
| phishing_or_prize_bait |      31 |        10.33 |
| government_phishing    |      11 |         3.67 |
| upi_fraud              |       9 |         3    |
| reward_phishing        |       8 |         2.67 |
| otp_theft              |       5 |         1.67 |
| utility_notice         |       3 |         1    |
| callback_bait          |       3 |         1    |
| loan_fraud             |       2 |         0.67 |
| investment_fraud       |       1 |         0.33 |
| inheritance_scam       |       1 |         0.33 |

`lottery_prize` represents 62.33% of the candidate rows. Some records have a category that does not obviously match their content; for example, a prize-winnings message is labelled `loan_fraud`. Do not use these categories as reliable supervised category labels without manual review.

## Decision

**Do not merge all 300 rows into the approved evaluation dataset yet.** The candidate file is useful and its sources are openly licensed, but:
1. near-duplicate repetition is material (275 pairwise matches across 189 clusters);
2. one row is labelled only as generic spam;
3. category metadata is provisional and imbalanced;
4. URL values have been redacted, so this file cannot validate URL extraction/reputation features;
5. it contains no genuine-message class.

A review CSV is generated at `ml/reports/sourced_candidate_duplicate_clusters.csv`. It marks one longest-text representative per similarity cluster for review but does not delete source rows or declare representatives approved. Pair details are in `ml/reports/sourced_candidate_near_duplicate_pairs.csv`.

## Next curation steps

1. Have two reviewers inspect the 188 non-spam cluster representatives and confirm scam/label/category.
2. Keep the raw 300-row source file immutable.
3. Keep all accepted sourced candidates in `train` only; do not modify the frozen 32-row validation/test split.
4. Add a similarly sourced and reviewed legitimate/Ham corpus, with source attribution and license preserved.
5. Deduplicate across both classes and sources before any split.
6. Re-run `python ml/evaluate.py` and compare TF-IDF baseline, rules, and full pipeline. The six-row held-out test in the current 32-row demo dataset is too small for strong conclusions.

## Reproduction

Run from repository root:

```powershell
python ml/audit_sourced_candidates.py
```

This writes the duplicate-cluster and pairwise-match CSVs under `ml/reports/`.
