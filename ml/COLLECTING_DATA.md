# Adding and reviewing evaluation examples

Use [`data/template.csv`](data/template.csv), whose columns are `text,label,category,source,author,split`.

## Authorship, source, and review

- Write project-authored messages independently. Do not copy, lightly rewrite, translate, or paraphrase another contributor's example. Use a stable, non-identifying author slug for original writing.
- For licensed external data, preserve row-level source citation and licence in `source`; do not claim a reviewer is the original author. If original authorship is unavailable, record `source_author_unrecorded`.
- Do not treat a source dataset's original label, a proposed label, or generic spam as a verified scam label. Preserve the source label and reviewer decision separately. Uncertain labels are excluded from binary training until adjudicated.
- Keep reviewer IDs and notes as restricted annotation metadata. Never use them as message features, model prompts, or author identity.
- Confirm licence and attribution requirements before copying data into a derived dataset. Do not add machine-generated examples to inflate a corpus.

## Privacy and quality gates

- Remove or redact names, phone numbers, email addresses, account numbers, Aadhaar-like values, UPI IDs, card numbers, real OTPs, tracking numbers, live URLs, and private conversations unless collection and use have been explicitly approved.
- Pattern scans are conservative and can produce false positives. Every potential sensitive value must be reviewed without printing it in logs or reports; unresolved rows must stay out of training.
- Require an accepted verified label, `message_quality=good`, `keep_for_training=YES`, and `contains_personal_data=no`. Preserve the original incoming file and create a derived file through `ml/adapt_incoming_reviews.py`.
- The adapter excludes uncertain and unusable rows, privacy flags, possible Aadhaar/UPI/card patterns, and exact/near duplicates that could leak across splits. The exclusion CSV contains record references and reason codes, not message text.

## Split handling and evaluation

- Set all new accepted examples to `split=train`. Do not add new validation/test rows or change the original 32-row baseline split. The adapter creates `ml/data/indian_scam_examples_v2.csv` from the untouched baseline plus eligible training rows.
- The adapter checks exact and near-duplicate overlap across train, validation, and test using the evaluation thresholds. Do not train on the raw `sourced_scam_candidates.csv` in addition to its reviewed subset.
- Add independently authored or sourced, privacy-reviewed genuine messages, including real bank alerts, OTP notices that warn recipients not to share codes, bill reminders, and ordinary courier updates. Scam-only additions cannot improve legitimate-message coverage.
- Run the v2 evaluation after data changes. Report the actual dataset size and class distribution. The six-row frozen test remains far too small to establish reliable generalization; do not tune rules or thresholds on it or report synthetic stress-test results as an independent benchmark.

The original 32 examples use `legacy_author_unrecorded` because historical author metadata was not captured. Do not reuse that sentinel for new project-authored submissions.

## Rebuild the isolated live advisory model

From the repository root, train the reproducible `message-text-v1` artifact with:

```powershell
.\.venv\Scripts\python.exe ml\train_model.py
```

The trainer validates split leakage, fits only the train rows, selects its decision threshold on validation rows, and records the dataset hash, source revision, dependency versions, parameters, split counts, and small held-out test metrics in the artifact manifest. It does not modify the dataset or the frozen splits. The production API loads the artifact once at startup. Set `ML_MODEL_ENABLED=false` to disable live inference, or set `ML_MODEL_PATH` and `ML_MODEL_VERSION` to select a matching artifact. A missing, invalid, or incompatible artifact makes the advisory unavailable and leaves the investigation API usable.

Do not treat model output as a probability or as verified evidence. Calibration is not justified by this dataset. The UI and PDF identify the class as an experimental suggestion and state that it does not affect deterministic scoring. Retrain after reviewed dataset or preprocessing changes, retain the manifest with the model artifact, run the full tests, and compare against a larger independently authored and adjudicated test set before making any stronger use claim.
