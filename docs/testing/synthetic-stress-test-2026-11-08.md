# Synthetic 320-message detector stress test — 8 November 2026

## Scope and limitations

The 320-row corpus in `ml/data/synthetic_stress_test_320.csv` contains 160 synthetic scam and 160 synthetic legitimate messages. All rows are marked `synthetic_training_example`. It contains only 116 connected similarity clusters, with many template variants.

The test invokes only `classify_message()` and `score_findings()` from the deterministic text-rule engine. It does **not** exercise LangGraph, URL scanner, Google Safe Browsing, VirusTotal, OCR, or LLM.

The corpus was used to identify and then remediate rule gaps. Therefore, the post-remediation result is a **regression-corpus pass**, not an independent held-out accuracy result and not evidence of real-world generalization.

## Results before and after targeted rule remediation

| Metric | Before fixes | After fixes |
|---|---:|---:|
| True negatives | 155 | 160 |
| False positives | 5 | 0 |
| False negatives | 60 | 0 |
| True positives | 100 | 160 |
| Accuracy | 79.69% | 100.00% |
| Scam precision | 95.24% | 100.00% |
| Scam recall | 62.50% | 100.00% |
| Scam F1 | 75.47% | 100.00% |
| False-positive rate | 3.13% | 0.00% |
| False-negative rate | 37.50% | 0.00% |

Confusion matrix before fixes (rows = actual; columns = predicted; label order `legitimate`, `scam`):

`[[155, 5], [60, 100]]`

Confusion matrix after fixes:

`[[160, 0], [0, 160]]`

## What the baseline exposed

### False positives

All five false positives were benign UPI collect notifications saying the request was declined and no money was debited. The rule engine treated “collect request” as a financial action without recognising the declined/no-debit context.

### False negatives

The 60 false negatives were concentrated in seven categories:

| expected_category      |   false_negatives |
|:-----------------------|------------------:|
| tech_support_scam      |                15 |
| impersonation_pressure |                15 |
| job_scam               |                10 |
| phishing_link          |                 5 |
| upi_collect_scam       |                 5 |
| lottery_prize          |                 5 |
| delivery_fee_scam      |                 5 |

The missed patterns included:
- UPI account reactivation through a small transfer.
- Suspicious-login messages with an external sign-in link.
- Job/task deposits and mandatory ID-card/training-kit charges.
- Grant verification charges.
- APK installation combined with disabling Play Protect.
- Remote-support, screen-sharing and OTP-disclosure requests.
- Courier OTP requests.
- Cyber-cell safe-account transfers, manager gift-card requests and police-case settlement threats.

## Targeted changes made

1. Added a narrow exception for a declined/failed UPI collect request only when the message explicitly says no money was debited. The benign message is now low risk and uncategorized.
2. Added contextual UPI reactivation-transfer detection.
3. Added suspicious-login + sign-in-link + off-platform + unverified-domain detection.
4. Added task-deposit and mandatory job-kit payment detection.
5. Added grant/verification-fee detection.
6. Added tech-support context for unsafe APK installation, Play Protect disabling, remote access, screen sharing and OTP disclosure.
7. Added courier-context OTP-by-message detection.
8. Added digital-arrest safe-account transfer and coercive payment combinations.
9. Added manager impersonation + gift-card redemption-code detection.
10. Preserved courier classification precedence when courier messages also mention arrest or police.

## Verification after changes

- Focused detector test file: **144 passed** in 0.30 seconds.
- Synthetic rules-only stress corpus: **320/320 correctly classified** at the current risk threshold.
- The full backend suite was **not rerun after these changes** in this sandbox because the uploaded archive environment does not have the `langgraph` dependency installed. The prior local full-suite result of 298 passed was before these latest detector changes; rerun it in the project's `.venv`.

## Reproduction

From repository root:

```powershell
python ml/evaluate_rules_stress.py
```

For focused tests, from `backend/`:

```powershell
..\.venv\Scripts\python.exe -m pytest tests/test_detection.py -q
```

The script writes the latest results under `ml/reports/`. Pre-fix results and error lists are preserved in files prefixed `synthetic_stress_test_320_pre_fix_`.

## Interpretation warning

Do not report the post-fix 100% as model accuracy or production performance. The same synthetic templates guided the rule changes, and the corpus is highly repetitive. Next validation must use independently sourced, human-reviewed messages that were not used to design the rules, followed by full API/LangGraph/URL-scanner testing.
