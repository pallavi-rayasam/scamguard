# ScamShield patch notes — 8 November 2026

## Files changed

- `backend/app/detection/rules.py`
- `backend/tests/test_detection.py`
- `data/seed/scam_categories.json`
- `CHECKLIST.md`
- `docs/limitations.md`
- `docs/testing/test-report.md`
- `ml/DATASETS.md`

## New files

- `docs/testing/dataset-audit-2026-11-08.md`
- `docs/testing/synthetic-stress-test-2026-11-08.md`
- `ml/audit_sourced_candidates.py`
- `ml/evaluate_rules_stress.py`
- `ml/data/synthetic_stress_test_320.csv`
- `ml/reports/sourced_candidate_duplicate_clusters.csv`
- `ml/reports/sourced_candidate_near_duplicate_pairs.csv`
- `ml/reports/synthetic_stress_test_320_results.csv`
- `ml/reports/synthetic_stress_test_320_false_positives.csv`
- `ml/reports/synthetic_stress_test_320_false_negatives.csv`
- `ml/reports/synthetic_stress_test_320_category_metrics.csv`
- `ml/reports/synthetic_stress_test_320_pre_fix_results.csv`
- `ml/reports/synthetic_stress_test_320_pre_fix_false_positives.csv`
- `ml/reports/synthetic_stress_test_320_pre_fix_false_negatives.csv`
- `ml/reports/synthetic_stress_test_320_pre_fix_category_metrics.csv`

## Detection changes

Added contextual rule coverage for UPI reactivation transfers, suspicious-login links, job/task deposits, mandatory job-kit fees, grant verification fees, unsafe APK/Play Protect instructions, remote-support and OTP disclosure requests, courier OTP requests, cyber-cell safe-account transfers, manager gift-card impersonation, and police-case settlement threats.

Added a narrow false-positive guard for a UPI collect request that is explicitly declined with no money debited. Courier context now takes precedence over generic digital-arrest classification when a courier message also mentions police/arrest threats.

## Verification

- Focused detector tests: **144 passed in 0.30s**.
- Synthetic rules-only regression corpus: **320/320 classified as expected after remediation**.
- Before remediation on that same corpus: 5 false positives and 60 false negatives.
- Sourced candidate audit script: 300 rows, 275 pairwise normalized exact/near matches, 189 similarity clusters.
- Python syntax, JSON parsing, and trailing-whitespace checks passed.

**Important:** The 320-row corpus is synthetic and was used to design the rules. Its post-fix 100% result is a regression-corpus pass, not independent accuracy or production validation. The complete backend suite was not rerun after these latest changes in the archive sandbox because `langgraph` is missing there. The previous 298-pass full-suite run predates this patch.

## Not completed by this patch

- No live Google Safe Browsing, VirusTotal, or OpenAI API call was made; keys are not configured.
- No live ML classifier was connected to the API. TF-IDF + Logistic Regression remains an offline evaluation baseline.
- The 300 sourced scam candidates were **not** merged into the approved training/evaluation dataset. They need manual label/category adjudication and a balanced genuine-message corpus.
- Full API/LangGraph/URL-scanner, PostgreSQL existing-volume, Docker, browser E2E, and PDF-download smoke tests remain to be run in the project environment.

## Apply the patch

Extract this ZIP into the existing repository root, preserving `.git` and your local `.env`. Overwrite files when prompted. Do not overwrite or delete your `.env`.

Then in PowerShell:

```powershell
Set-Location C:\dev\scamshield\backend
.\.venv\Scripts\Activate.ps1
python -m pytest tests/test_detection.py -q
python -m pytest
Set-Location ..
python ml\audit_sourced_candidates.py
python ml\evaluate_rules_stress.py
git diff --check
git status
```

If the complete backend suite passes, review the diff, then commit and push from the repository root:

```powershell
git add PATCH_NOTES.md CHECKLIST.md backend/app/detection/rules.py backend/tests/test_detection.py data/seed/scam_categories.json docs/limitations.md docs/testing/test-report.md docs/testing/dataset-audit-2026-11-08.md docs/testing/synthetic-stress-test-2026-11-08.md ml/DATASETS.md ml/audit_sourced_candidates.py ml/evaluate_rules_stress.py ml/data/synthetic_stress_test_320.csv ml/reports
git commit -m "fix: improve scam detection coverage and add dataset audits"
git push origin develop
```

Keep API keys only in your local ignored `.env`; never add `.env` to Git.
