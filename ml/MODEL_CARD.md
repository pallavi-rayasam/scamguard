# Model card: `message-text-v1`

## Summary and intended use

`message-text-v1` is a TF-IDF word unigram/bigram feature pipeline followed by balanced Logistic Regression. It provides an experimental scam-like versus legitimate-looking suggestion for one bounded message. It is advisory only. The prediction is not an indicator, finding, verified fact, evidence-strength input, recommendation input, risk-score input, or probability. It cannot override URL reputation, deterministic rules, or an LLM explanation/fallback.

The backend loads the versioned joblib artifact once during FastAPI startup. The model version and artifact digest are checked against a JSON manifest, including the installed scikit-learn and joblib versions. Missing, corrupt, mismatched, disabled, or incompatible artifacts return an explicit non-completed status; they do not prevent an investigation. Use `ML_MODEL_ENABLED=false` to disable inference, `ML_MODEL_VERSION` to select the expected version, and `ML_MODEL_PATH` to select its `pipeline.joblib` file. The matching `manifest.json` must sit beside the artifact.

## Training and preprocessing

Reproduce the artifact from the repository root with:

```powershell
.\.venv\Scripts\python.exe ml\train_model.py
```

The model fits the training partition only. The declared validation partition selects the decision threshold; the test partition is used once for a descriptive report. Seed 42 is recorded in the manifest. Training uses `ml/data/indian_scam_examples_v2.csv`. Training and inference share the same normalizer, sensitive-value redaction, and URL masking: URL paths, query strings, identifiers, OTPs, and credential/card-like values are not model features. The classifier returns a class only. No calibrated probability is produced.

The artifact is a Python joblib serialization. Only load the build-produced, digest-checked artifact from a trusted repository/deployment image. The manifest digest detects artifact corruption, but a hash manifest is not a cryptographic signature against an actor who can replace both files; protect build inputs and image provenance accordingly.

## Data and evaluation

The v2 dataset has 182 rows: 166 scam and 16 legitimate. Training has 170 rows (160 scam, 10 legitimate); validation and test each have six rows (three per class). The 150 reviewed additions are scam-only, and all overlap the sourced candidate corpus. This is severe class imbalance and narrow source diversity. The test set is frozen and only six rows; any observed metric is highly uncertain and is not evidence of generalization, safety, or production readiness. The synthetic stress-test corpus is not independent benchmark evidence.

Dataset provenance, licensing, privacy screening, exclusion counts, and known source overlap are documented in `ml/DATASETS.md`. Confirm source attribution and redistribution rights before release. The incoming annotation file contains reviewer metadata and declared personal data; it is not a training feature source and must remain access-controlled.

## Limitations and monitoring

- Do not interpret `scam`/`legitimate` as verified truth or a guarantee of safety.
- No calibrated confidence is available; the report explicitly says calibration is not justified.
- The legitimate class is very small; real bank, OTP, courier, utility, and ordinary conversations are underrepresented.
- Language, dialect, channel, source and time coverage are limited. No reliable fairness or subgroup performance claim is available.
- The classifier is not connected to risk aggregation. An unavailable/failed/disabled model has no effect on deterministic report content.
- Re-evaluate on a larger, independently written or independently sourced, privacy-reviewed and adjudicated holdout before changing the intended use.
