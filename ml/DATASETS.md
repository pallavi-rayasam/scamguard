# Evaluation datasets

## `ml/data/indian_scam_examples.csv`

- **Current size:** 32 labelled examples: 16 `scam` and 16 `legitimate`. No rows were generated or added for this evaluation-v2 work.
- **Source:** Original, short illustrative Indian-context SMS/chat examples written for this project. They contain no user submissions, scraped text, real phone numbers, URLs, names, or financial identifiers.
- **Licence:** CC BY 4.0 for this project-authored example file.
- **Author field:** The initial examples predate contributor-level attribution. They use `legacy_author_unrecorded`, which denotes missing historical metadata and is not a contributor identity. New submissions must use a stable, non-identifying contributor slug.
- **Labels:** Binary `scam`/`legitimate` plus a descriptive category. These are author judgements for a demonstration set, not adjudicated ground truth.
- **Preprocessing:** UTF-8 CSV; sample text is passed to models as written. There is no stemming, translation, deduplication, or content augmentation. The baseline applies scikit-learn word TF-IDF with unigrams/bigrams and logistic regression. Only LLM requests (when explicitly enabled) redact detected secrets and replace extracted URLs before transmission.
- **Splitting:** The current 32 `auto` rows retain their seed-42 assignment: 20 train, 6 validation, and 6 test. The six test messages are covered by a regression test. To add rows without reshuffling those rows, assign additions `split=train`; mixed auto/explicit splitting keeps the original auto group together and appends explicit training rows. Do not edit existing test rows or use them to tune thresholds or rules.
- **Leakage checks:** Before evaluation, test rows are compared against train rows after Unicode NFKC/casefold/punctuation normalization. Exact matches fail. Near duplicates fail at normalized character similarity >=0.92 or token Jaccard >=0.85 with at least five tokens in the smaller sample. The same check runs across each train/held-out fold in cross-validation.
- **Limitations:** This tiny, English-only, project-authored collection is not representative of scam prevalence, dialects, multilingual India, evolving tactics, or legitimate-message diversity. Its examples are not independently adjudicated. The held-out test set has only three examples per class, so intervals are highly uncertain and results do not establish generalization, production accuracy, or safety. Expand only with independently authored, licensed, privacy-reviewed, adjudicated data.

Run the evaluation from the repository root:

```powershell
python ml/evaluate.py
```

The script writes no report file unless `--output` is supplied. LLM evaluation is skipped by default; `--include-llm` sends redacted validation, test, and train+validation CV samples to OpenAI if a key is configured. The full pipeline keeps external providers disabled unless `--allow-external` is passed. Five-fold stratified CV uses only train+validation; the test split is excluded. Reported intervals use 2,000 stratified paired percentile bootstrap replicates, preserving class counts.


## `ml/data/sourced_scam_candidates.csv` — raw candidate-only corpus

- **Current size:** 300 scam-labelled candidate rows; all marked `train` in the raw candidate file.
- **Provenance:** 46 rows from the Hugging Face `bolewara/hinglish-scam-text-dataset` (CC BY 4.0; source label `1 (scam)`) and 254 rows from the Mendeley SMS Phishing dataset (CC BY 4.0; 253 source-labelled `Smishing`, one source-labelled `spam`).
- **Important label distinction:** Smishing is a phishing/fraud category. Generic `spam` is not automatically equivalent to scam; the one `spam`-labelled row is held for manual adjudication.
- **Quality status:** Candidate-only, not yet approved for model training. A structural audit found 9 normalized-exact pairs and 266 near-duplicate pairs, forming 189 connected similarity clusters. The category field is provisional and highly imbalanced; `lottery_prize` is 62.33% of rows. URL/phone redactions mean this corpus is not suitable for direct URL-feature evaluation.
- **Use:** Preserve the raw file. Review one representative per similarity cluster, then adjudicate labels and categories with two reviewers. Accepted rows may be added to `indian_scam_examples.csv` as `split=train` only. Do not modify the frozen validation/test rows.
- **Audit outputs:** `docs/testing/dataset-audit-2026-11-08.md` and `ml/reports/sourced_candidate_*.csv`.
- **Re-run audit:** `python ml/audit_sourced_candidates.py`.

## `ml/data/synthetic_stress_test_320.csv` — synthetic regression corpus only

- **Current size:** 320 synthetic examples, balanced 160 scam / 160 legitimate.
- **Purpose:** Development-time stress testing of the deterministic rule engine and regression triage only.
- **Not for:** Training, claims of real-world accuracy, or independent benchmark reporting. It contains repeated template variants (116 connected similarity clusters).
- **Current rules-only result:** 80.00% accuracy, 95.24% scam precision, 62.50% scam recall, 5 false positives, and 60 false negatives. See `docs/testing/synthetic-stress-test-2026-11-08.md`.
- **Re-run:** `python ml/evaluate_rules_stress.py`.
