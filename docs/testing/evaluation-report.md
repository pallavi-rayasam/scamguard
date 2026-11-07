# Evaluation report

- Date: 2026-11-07
- Command: `python ml/evaluate.py --include-llm`
- Dataset: `ml/data/indian_scam_examples.csv`
- Seed: `42`
- Bootstrap: 2,000 95% stratified paired percentile replicates; class counts preserved.

## Dataset and split

The current dataset has **32 original hand-labelled examples**: 16 scam and 16 legitimate. No examples were added for this evaluation. The existing seed-42 split remains 20 train, 6 validation, and 6 test rows; a regression test locks the exact existing test messages. Exact and near-duplicate train/test leakage checks passed.

## Held-out test results

Each metric is followed by its bootstrap 95% confidence interval. Confusion matrices use `[[TN, FP], [FN, TP]]`, label order `legitimate`, `scam`.

| Model | n | Accuracy [95% CI] | Precision [95% CI] | Recall [95% CI] | F1 [95% CI] | FPR [95% CI] | FNR [95% CI] | Confusion matrix |
|---|---:|---:|---:|---:|---:|---:|---:|---|
| TF-IDF + logistic regression | 6 | 0.667 [0.333, 1.000] | 0.667 [0.000, 1.000] | 0.667 [0.000, 1.000] | 0.667 [0.000, 1.000] | 0.333 [0.000, 1.000] | 0.333 [0.000, 1.000] | `[[2, 1], [1, 2]]` |
| Current rules + scoring | 6 | 0.833 [0.500, 1.000] | 1.000 [0.000, 1.000] | 0.667 [0.000, 1.000] | 0.800 [0.000, 1.000] | 0.000 [0.000, 0.000] | 0.333 [0.000, 1.000] | `[[3, 0], [1, 2]]` |
| Full deterministic pipeline | 6 | 0.833 [0.500, 1.000] | 1.000 [0.000, 1.000] | 0.667 [0.000, 1.000] | 0.800 [0.000, 1.000] | 0.000 [0.000, 0.000] | 0.333 [0.000, 1.000] | `[[3, 0], [1, 2]]` |
| LLM-only | — | — | — | — | — | — | — | Skipped: `OPENAI_API_KEY` is not configured; no request was sent. |

The logistic-regression threshold was selected on validation data. Rules and pipeline used the fixed score threshold of 25; no rules or thresholds were tuned on the held-out test set. External lookups were disabled.

## Five-fold cross-validation

Stratified 5-fold CV used the 26 train+validation rows only; the held-out test set was excluded. The logistic-regression CV threshold was fixed at 0.5 (no fold holdout used for tuning). Values below are pooled out-of-fold metrics with stratified paired bootstrap 95% CIs.

| Model | n | Accuracy [95% CI] | Precision [95% CI] | Recall [95% CI] | F1 [95% CI] | FPR [95% CI] | FNR [95% CI] | Confusion matrix |
|---|---:|---:|---:|---:|---:|---:|---:|---|
| TF-IDF + logistic regression | 26 | 0.692 [0.500, 0.846] | 0.692 [0.500, 0.909] | 0.692 [0.462, 0.923] | 0.692 [0.476, 0.867] | 0.308 [0.077, 0.538] | 0.308 [0.077, 0.538] | `[[9, 4], [4, 9]]` |
| Current rules + scoring | 26 | 0.731 [0.577, 0.846] | 1.000 [1.000, 1.000] | 0.462 [0.154, 0.692] | 0.632 [0.267, 0.818] | 0.000 [0.000, 0.000] | 0.538 [0.308, 0.846] | `[[13, 0], [7, 6]]` |
| Full deterministic pipeline | 26 | 0.731 [0.577, 0.846] | 1.000 [1.000, 1.000] | 0.462 [0.154, 0.692] | 0.632 [0.267, 0.818] | 0.000 [0.000, 0.000] | 0.538 [0.308, 0.846] | `[[13, 0], [7, 6]]` |

LLM-only cross-validation was skipped because `OPENAI_API_KEY` is not configured.

## Interpretation limits

These measurements use a tiny, project-authored illustrative set, not independently adjudicated or representative data. The held-out test set contains only three examples per class; accordingly, most intervals are very wide. Cross-validation is also based on only 26 rows and does not establish generalization. Do not present these values as production accuracy, calibrated confidence, or a safety guarantee. Dataset provenance and contribution guidance are in [`ml/DATASETS.md`](../../ml/DATASETS.md) and [`ml/COLLECTING_DATA.md`](../../ml/COLLECTING_DATA.md).
