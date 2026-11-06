# Evaluation datasets

## `data/indian_scam_examples.csv`

- **Size:** 32 original, hand-labelled examples (16 `scam`, 16 `legitimate`). The evaluation command reports the actual split counts and measured metrics.
- **Source:** Written specifically for this project as short illustrative Indian-context SMS/chat examples. No user messages, scraped text, real phone numbers, URLs, names, financial identifiers, or third-party dataset records are included.
- **Licence:** CC BY 4.0 for this authored example file.
- **Labels:** Binary `scam`/`legitimate`, plus a descriptive category. These are author judgements for a demonstration set, not adjudicated ground truth.
- **Preprocessing:** UTF-8 CSV; no stemming, translation, deduplication, or content augmentation. The baseline applies scikit-learn word TF-IDF with unigrams/bigrams and logistic regression. The rules and full pipeline receive the text as written. Only LLM requests (when explicitly enabled) redact detected secrets and replace extracted URLs before transmission.
- **Splitting:** `split=auto` requests deterministic stratification by label using seed 42. Per class, 20% is assigned to test, 20% of the remainder to validation, and the rest to train. Override with `--seed`. CSVs with all split values explicitly set to `train`, `validation`, or `test` retain those assignments.
- **Limitations:** This tiny, synthetic, English-only collection is not representative of real scam prevalence, dialects, multilingual India, evolving tactics, or legitimate-message diversity. Random splits from one authored set do not establish generalization; similar wording may occur across splits. Do not cite these results as production accuracy or a user-safety guarantee. Expand with independently sourced, licensed, privacy-reviewed and adjudicated data before drawing performance conclusions.

Run the evaluation from the repository root:

```powershell
python ml/evaluate.py
```

The script writes no report file unless `--output` is supplied. LLM evaluation is skipped by default; `--include-llm` sends redacted validation and test samples to OpenAI if a key is configured. The full pipeline keeps external providers disabled unless `--allow-external` is passed.
