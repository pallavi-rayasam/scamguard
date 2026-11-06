# Evaluation report

- Date: 2026-11-06
- Command: `python ml/evaluate.py --include-llm`
- Dataset: `ml/data/indian_scam_examples.csv`
- Seed: `42`

## Dataset and split

The hand-labelled file contains **32 original examples**: 16 scam and 16 legitimate. The deterministic stratified split produced 20 train rows (10 per label), 6 validation rows (3 per label), and 6 test rows (3 per label). The baseline threshold was selected on validation data; reported test metrics were computed once on the held-out test rows.

## Held-out test results

The confusion matrix uses `[[TN, FP], [FN, TP]]` with label order `legitimate`, `scam`.

| Model | Status | Accuracy | Precision (scam) | Recall (scam) | F1 (scam) | FPR | FNR | Confusion matrix |
|---|---|---:|---:|---:|---:|---:|---:|---|
| TF-IDF + logistic regression | Pass | 0.667 | 0.667 | 0.667 | 0.667 | 0.333 | 0.333 | `[[2,1],[1,2]]` |
| Current rules + scoring | Pass | 0.833 | 1.000 | 0.667 | 0.800 | 0.000 | 0.333 | `[[3,0],[1,2]]` |
| LLM-only | Skipped | — | — | — | — | — | — | `OPENAI_API_KEY` not configured; no request sent |
| Full deterministic pipeline | Pass | 0.833 | 1.000 | 0.667 | 0.800 | 0.000 | 0.333 | `[[3,0],[1,2]]` |

The threshold for rules and the full pipeline is a risk score of 25 (`Moderate` or higher). The TF-IDF threshold was 0.5, selected by validation F1. External provider lookups were disabled for this local run. The full pipeline therefore exercises its deterministic stages, with external reputation results unavailable.

## Interpretation limits

These are measured results on a tiny, synthetic, project-authored set, not a representative or independently adjudicated dataset. With only three examples of each class in the test split, one changed prediction shifts per-class rates by 0.333. The perfect baseline validation result is not evidence of generalization. Do not present these values as production accuracy, calibrated confidence, or a safety guarantee. Dataset provenance and extension guidance are in [`ml/DATASETS.md`](../../ml/DATASETS.md).
