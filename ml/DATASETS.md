# Evaluation datasets

## Baseline: `ml/data/indian_scam_examples.csv`

- **Size:** 32 original project-authored examples: 16 `scam` and 16 `legitimate`.
- **Schema:** `text,label,category,source,author,split`.
- **Split:** All 32 source rows remain marked `auto`; seed 42 produces 20 train, 6 validation, and 6 test rows (10/10, 3/3, and 3/3 by class). The source file is preserved unchanged. The v2 dataset retains these rows and assignments, adding only explicit training rows.
- **Source/licence:** Original illustrative Indian-context SMS/chat examples; CC BY 4.0. These are author judgements, not independently adjudicated ground truth.
- **Preprocessing:** UTF-8 CSV; source text is preserved as written. Before TF-IDF fit/inference, the shared pipeline normalizes whitespace/zero-width characters, redacts sensitive OTP/credential/card-like values, and masks URL content. It applies word TF-IDF unigrams/bigrams and logistic regression; there is no stemming, translation, or augmentation. Optional LLM evaluation separately uses redaction and URL replacement before transmission.
- **Limitations:** This is a tiny, project-authored set, not representative of prevalence, evolving tactics, dialects, multilingual India, or the diversity of legitimate messages. The six-row test has only three rows per class; it cannot establish production performance or generalization.

## Versioned review integration: `ml/data/indian_scam_examples_v2.csv`

Rebuild from the immutable reviewed source and the unchanged baseline with:

```powershell
.\.venv\Scripts\python.exe ml\adapt_incoming_reviews.py
```

- **Source input:** `ml/data/incoming/scamshieldcsv.csv`, 188 reviewed records. Its declared source licence is CC BY 4.0. Every row has a source citation. All rows exactly overlap the raw sourced-candidate corpus; this is an adjudication layer over that source, not an independent 188-message corpus.
- **Review decisions:** 155 `verified_label=scam`; 33 `uncertain`. The adapter never uses `proposed_label`; it admits only verified scam rows explicitly marked `keep_for_training=YES` and `message_quality=good`.
- **Privacy exclusions:** 38 unique rows excluded: all 33 uncertain rows plus 5 otherwise eligible scam rows with privacy risk. The five privacy exclusions comprise one row marked `contains_personal_data=yes` and four rows detected by possible Aadhaar (1), UPI-like (2), or card-like (1) patterns. The two explicit personal-data flags and three unusable quality flags overlap the uncertain group in part. Per-reason counts overlap and are recorded in `ml/reports/incoming_review_adapter_summary.json`; record-level reasons without message text are in `ml/reports/incoming_review_exclusions.csv`.
- **Accepted additions:** 150 scam rows, all assigned `train`. Reviewer notes and IDs are not copied or used as features. The `author` field is `source_author_unrecorded`; reviewer identity is never treated as message authorship. The `source` field retains source label, citation, licence, source record ID, and dataset attribution.
- **Final dataset:** 182 rows: 166 scam, 16 legitimate. Split with seed 42: 170 train (160 scam, 10 legitimate), 6 validation (3/3), and 6 test (3/3). The original 32 records remain first in the CSV with their values and `auto` split declarations unchanged. Exact and near-duplicate checks across all resulting partitions found zero cross-split pairs.
- **Imbalance and coverage:** The 150 additions are scam-only; there are no new genuine/legitimate records. `lottery_prize` is 95/150 added examples (63.3%). Overall v2 is 166/182 scam (91.2%); training is 160/170 scam (94.1%). Class weighting in logistic regression does not make the evaluation data representative.
- **Privacy and licence limitations:** Pattern detection is conservative and can flag non-sensitive text; it is not proof that a value is personal data. The incoming file itself includes reviewer notes and two declared personal-data rows, so it must remain access-controlled and must not be sent to an LLM. Keep CC BY 4.0 attribution intact and verify source-specific attribution requirements before redistribution. The source author is not recorded; the adapter records that explicitly rather than substituting a reviewer.
- **Evaluation limits:** The frozen test still has only six examples, three per class. It is unchanged and was not used to tune rules or thresholds. See `docs/testing/evaluation-report-v2.md` for the measured offline results and confidence intervals. These are still small-sample estimates, not production accuracy or a safety guarantee.

## `ml/data/sourced_scam_candidates.csv` — raw candidate-only corpus

- **Size:** 300 scam-labelled candidate rows; the source file marks all `train`.
- **Provenance:** 46 rows from the Hugging Face `bolewara/hinglish-scam-text-dataset` (CC BY 4.0; source label `1 (scam)`) and 254 rows from the Mendeley SMS Phishing dataset (CC BY 4.0; 253 source-labelled `Smishing`, one source-labelled `spam`).
- **Label distinction:** Generic `spam` is not automatically a scam. The raw file's flattened `scam` label is not approval to train every row.
- **Quality:** Candidate-only; do not load as a training source alongside the reviewed subset. A structural audit found 9 normalized-exact pairs and 266 near-duplicate pairs in 189 connected clusters. Categories are provisional and highly imbalanced (`lottery_prize` 62.33%). URL and phone redactions make this unsuitable for direct URL-feature evaluation. The reviewed incoming file overlaps this corpus exactly.
- **Audit:** `docs/testing/dataset-audit-2026-11-08.md` and `ml/reports/sourced_candidate_*.csv`.

## `ml/data/synthetic_stress_test_320.csv` — synthetic regression corpus only

- **Size/schema:** 320 synthetic examples, 160 scam and 160 legitimate; columns are `message_id,message,label,category,sender_or_channel,rationale,source_type`.
- **Use:** Development regression tests only. It has repeated template variants (116 connected similarity clusters) and is not an independent benchmark or a model training corpus.
- **Recorded rules-only result:** The post-remediation corpus pass is documented in `docs/testing/synthetic-stress-test-2026-11-08.md`; because the examples guided rule changes, do not treat it as independent performance evidence.

## Evaluation harness

Run from the repository root:

```powershell
.\.venv\Scripts\python.exe ml\evaluate.py ml\data\indian_scam_examples_v2.csv
```

`ml/evaluate.py` compares TF-IDF plus logistic regression, current deterministic rule scoring, and the full deterministic investigation pipeline. It reports accuracy, precision, recall, F1, confusion matrix, false-positive rate, false-negative rate, stratified paired bootstrap 95% intervals, and five-fold CV on train+validation. The frozen test rows are excluded from CV and threshold/rule tuning. External lookups are disabled unless `--allow-external` is explicitly passed. LLM-only evaluation is a separate optional OpenAI-only path (`--include-llm`); it is not connected to the configured live provider abstraction.

The versioned `message-text-v1` TF-IDF + Logistic Regression classifier is now persisted under `ml/artifacts/message-text-v1/` and exposed to live single-message investigations as an experimental advisory. It is not a source of findings, verification, evidence strength, recommendations, or risk score. See `ml/MODEL_CARD.md` for training and deployment details. Its six-row frozen test set does not establish generalization.
