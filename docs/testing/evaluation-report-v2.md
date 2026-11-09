# Offline evaluation — `indian_scam_examples_v2.csv`

- **Dataset:** 182 rows; 166 scam and 16 legitimate.
- **Seed-42 split:** 170 train (160 scam, 10 legitimate), 6 validation (3/3), 6 test (3/3). The original 32 rows and their `auto` split declarations are unchanged; the 150 accepted reviewed rows are train-only.
- **Leakage:** The adapter found zero exact or near-duplicate pairs across train, validation, and test using the evaluation harness thresholds. The evaluator also completed its train/test and fold leakage checks.
- **Execution:** `.venv\Scripts\python.exe ml\evaluate.py ml\data\indian_scam_examples_v2.csv --output docs\testing\evaluation-report-v2.json`. External lookups were disabled; LLM-only was skipped because it was not requested. No live provider was called.
- **Method:** TF-IDF + logistic regression, current deterministic rules/scoring, and full deterministic pipeline. Baseline threshold is selected on validation; rule/pipeline threshold remains 25. Five-fold CV uses train+validation only (176 rows). Bootstrap uses 2,000 stratified paired replicates.

## Frozen six-row test results

Confusion matrices use `[[TN, FP], [FN, TP]]`, label order `legitimate`, `scam`.

| Model | n | Accuracy | Precision (scam) | Recall (scam) | F1 (scam) | FPR | FNR | Confusion matrix |
|---|---:|---:|---:|---:|---:|---:|---:|---|
| TF-IDF + logistic regression | 6 | 1.000 | 1.000 | 1.000 | 1.000 | 0.000 | 0.000 | `[[3, 0], [0, 3]]` |
| Current rules + scoring | 6 | 1.000 | 1.000 | 1.000 | 1.000 | 0.000 | 0.000 | `[[3, 0], [0, 3]]` |
| Full deterministic pipeline | 6 | 1.000 | 1.000 | 1.000 | 1.000 | 0.000 | 0.000 | `[[3, 0], [0, 3]]` |

The report's stratified bootstrap intervals are degenerate at these observed values because all six examples were classified correctly and each class has only three rows. This does not measure uncertainty over future data. The test set is too small for reliable generalization claims; the results are not production accuracy or a safety guarantee.

## Five-fold train+validation cross-validation

| Model | n | Accuracy | Precision (scam) | Recall (scam) | F1 (scam) | FPR | FNR | Confusion matrix |
|---|---:|---:|---:|---:|---:|---:|---:|---|
| TF-IDF + logistic regression | 176 | 0.9545 | 0.9586 | 0.9939 | 0.9759 | 0.5385 | 0.0061 | `[[6, 7], [1, 162]]` |
| Current rules + scoring | 176 | 0.2386 | 1.0000 | 0.1779 | 0.3021 | 0.0000 | 0.8221 | `[[13, 0], [134, 29]]` |
| Full deterministic pipeline | 176 | 0.2500 | 1.0000 | 0.1902 | 0.3196 | 0.0000 | 0.8098 | `[[13, 0], [132, 31]]` |

Cross-validation highlights the severe class imbalance: only 13 legitimate examples are in train+validation, compared with 163 scam examples. The TF-IDF model has a high false-positive rate in CV; the rule-based systems have very high false-negative rates. These estimates also come from one reviewed source family and should not be generalized.

## Scope limits

The incoming review set contributes 150 scam-only training records and no genuine examples. Its texts overlap the existing raw sourced-candidate file, which was not added again. Synthetic stress-test results are not used as independent benchmark evidence. The versioned TF-IDF artifact is also exposed as a separate experimental live advisory, but it does not influence findings or scoring. This integration does not strengthen the evaluation evidence: the frozen test still has only six rows, and the model is not calibrated. The full machine-readable metrics are in [`evaluation-report-v2.json`](evaluation-report-v2.json).
