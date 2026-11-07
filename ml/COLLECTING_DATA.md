# Adding evaluation examples

Use [`data/template.csv`](data/template.csv), whose columns are `text,label,category,source,author,split`.

## Writing and attribution

- Write each message independently. Do not copy, lightly rewrite, translate, or paraphrase another contributor's example. A contributor should submit text they authored and a stable, non-identifying author slug such as `contributor-7`.
- Do not add machine-generated examples to inflate the dataset. Keep every source and label reviewable.
- Use `source` to describe where the example came from (for example, an original authored example or a licensed public dataset). Confirm the source licence permits this use before submission.
- Label the message's apparent purpose as `scam` or `legitimate` and use a concise category such as `banking_phishing`, `upi_fraud`, `utility_notice`, or `delivery_update`. Have a second reviewer resolve uncertain labels.

## Useful coverage

Add hard negatives as well as scam examples: genuine bank alerts, real OTP notices that warn recipients not to share codes, routine bill reminders, salary notices, and ordinary courier updates. Include a scam example only when it represents a plausible tactic; avoid using real victim data.

## Privacy and split handling

- Remove names, phone numbers, email addresses, account numbers, real OTPs, UPI IDs, tracking numbers, and live URLs. Do not submit private conversations or messages from users without permission and appropriate review.
- Set new accepted rows to `split=train`. The initial 32 `auto` rows remain in their existing seed-42 assignments when explicit training rows are added. Do not change or inspect the test set to tune rules, thresholds, or wording.
- Do not add new `validation` or `test` rows directly. A data steward must plan and document any future holdout-set revision.
- Run `python ml/evaluate.py` after adding rows. The evaluation fails if a train/test exact or near duplicate is detected. Check the reported dataset size and split counts; do not claim performance beyond the data.

The existing examples use `author=legacy_author_unrecorded` because person-level metadata was not captured when they were created. Do not reuse that value for new submissions.
