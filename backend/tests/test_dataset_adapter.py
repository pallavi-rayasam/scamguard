import csv
import json
from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ml.adapt_incoming_reviews import (  # noqa: E402
    AUTHOR_UNRECORDED,
    INPUT_REQUIRED_COLUMNS,
    _cross_split_duplicates,
    _leakage_match_kind,
    adapt_dataset,
    detect_sensitive_patterns,
)
from ml.evaluate import load_dataset, split_dataset  # noqa: E402

BASELINE = ROOT / "ml" / "data" / "indian_scam_examples.csv"
INCOMING = ROOT / "ml" / "data" / "incoming" / "scamshieldcsv.csv"


def _record(record_id="review-001", text=None, **overrides):
    row = {
        "review_id": record_id,
        "cluster_id": f"cluster-{record_id}",
        "source_label": "Smishing",
        "verified_label": "scam",
        "verified_category": "banking_phishing",
        "message_text": text or f"A reviewed example asks the recipient to verify a sample account {record_id}.",
        "source_citation": f"Mendeley record citation {record_id}",
        "license": "CC BY 4.0",
        "message_quality": "good",
        "contains_personal_data": "no",
        "keep_for_training": "YES",
        "proposed_label": "legitimate",
        "reviewer_id": "reviewer-secret-label",
        "reviewer_notes": "private reviewer note must not enter features",
    }
    row.update(overrides)
    return row


def _write_input(path, rows, columns=None):
    fields = columns or [*INPUT_REQUIRED_COLUMNS, "proposed_label", "reviewer_id", "reviewer_notes"]
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with Path(path).open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows({key: row.get(key, "") for key in fields} for row in rows)


def _run(tmp_path, rows, *, baseline=BASELINE, suffix="run"):
    tmp_path.mkdir(parents=True, exist_ok=True)
    source = tmp_path / f"{suffix}-source.csv"
    output = tmp_path / f"{suffix}-dataset.csv"
    exclusions = tmp_path / f"{suffix}-exclusions.csv"
    summary = tmp_path / f"{suffix}-summary.json"
    _write_input(source, rows)
    result = adapt_dataset(
        source_path=source,
        baseline_path=baseline,
        output_path=output,
        exclusion_csv_path=exclusions,
        summary_json_path=summary,
    )
    return result, output, exclusions, summary


def _custom_baseline(path, test_text="A separate frozen test message has distinct content."):
    rows = [
        {"text": "A separate train message with distinct content.", "label": "scam", "category": "x", "source": "test", "author": "author-a", "split": "train"},
        {"text": "A separate validation notification has distinct content.", "label": "legitimate", "category": "x", "source": "test", "author": "author-a", "split": "validation"},
        {"text": test_text, "label": "scam", "category": "x", "source": "test", "author": "author-a", "split": "test"},
    ]
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=["text", "label", "category", "source", "author", "split"])
        writer.writeheader()
        writer.writerows(rows)
    return rows


def test_input_schema_validation_fails_closed(tmp_path):
    source = tmp_path / "missing-verified-label.csv"
    columns = [name for name in INPUT_REQUIRED_COLUMNS if name != "verified_label"]
    _write_input(source, [_record()], columns=columns)
    with pytest.raises(ValueError, match="verified_label"):
        adapt_dataset(
            source_path=source,
            baseline_path=BASELINE,
            output_path=tmp_path / "out.csv",
            exclusion_csv_path=tmp_path / "excluded.csv",
            summary_json_path=tmp_path / "summary.json",
        )


def test_invalid_verified_label_is_rejected(tmp_path):
    source = tmp_path / "bad-label.csv"
    _write_input(source, [_record(verified_label="fraud")])
    with pytest.raises(ValueError, match="unsupported verified_label"):
        adapt_dataset(
            source_path=source,
            baseline_path=BASELINE,
            output_path=tmp_path / "out.csv",
            exclusion_csv_path=tmp_path / "excluded.csv",
            summary_json_path=tmp_path / "summary.json",
        )


def test_verified_label_controls_admission_not_proposed_label(tmp_path):
    summary, output, exclusions, _ = _run(tmp_path, [
        _record("verified-scam", proposed_label="legitimate"),
        _record("uncertain-one", verified_label="uncertain", proposed_label="scam", keep_for_training="NO"),
    ])
    assert summary["accepted_training_records"] == 1
    rows = load_dataset(output)
    added = rows[32]
    assert added["label"] == "scam"
    excluded = list(csv.DictReader(exclusions.open(encoding="utf-8", newline="")))
    assert excluded[0]["review_id"] == "uncertain-one"
    assert "verified_label_not_scam" in excluded[0]["exclusion_reasons"]


def test_unusable_record_is_excluded(tmp_path):
    summary, _, exclusions, _ = _run(tmp_path, [_record(message_quality="unusable")])
    assert summary["accepted_training_records"] == 0
    assert "message_quality_not_good" in next(csv.DictReader(exclusions.open(encoding="utf-8", newline="")))["exclusion_reasons"]


def test_personal_data_record_is_excluded(tmp_path):
    summary, _, exclusions, _ = _run(tmp_path, [_record(contains_personal_data="yes")])
    assert summary["accepted_training_records"] == 0
    assert "contains_personal_data" in next(csv.DictReader(exclusions.open(encoding="utf-8", newline="")))["exclusion_reasons"]


@pytest.mark.parametrize(
    ("text", "expected_reason"),
    [
        ("Identity number 1234 5678 9012 is shown here.", "possible_aadhaar_value"),
        ("UPI handle sampleuser@ybl is shown here.", "possible_upi_value"),
        ("Card number 4111 1111 1111 1111 is shown here.", "possible_card_value"),
    ],
    ids=["aadhaar-like", "upi-like", "card-like"],
)
def test_sensitive_patterns_are_detected_and_excluded(tmp_path, text, expected_reason):
    assert expected_reason in detect_sensitive_patterns(text)
    summary, _, exclusions, _ = _run(tmp_path, [_record(message_text=text)])
    assert summary["accepted_training_records"] == 0
    report = next(csv.DictReader(exclusions.open(encoding="utf-8", newline="")))
    assert expected_reason in report["exclusion_reasons"]
    assert text not in Path(exclusions).read_text(encoding="utf-8")


def test_duplicate_training_records_are_deduplicated_deterministically(tmp_path):
    repeated = "A unique reviewed message requests a payment to unlock a fictional benefit."
    summary, output, exclusions, _ = _run(tmp_path, [
        _record("review-002", text=repeated),
        _record("review-001", text=repeated),
    ])
    assert summary["accepted_training_records"] == 1
    added = load_dataset(output)[32]
    assert '"record_id":"review-001"' in added["source"]
    excluded = list(csv.DictReader(exclusions.open(encoding="utf-8", newline="")))
    assert len(excluded) == 1
    assert excluded[0]["review_id"] == "review-002"
    assert "duplicate_with_accepted_training_record" in excluded[0]["exclusion_reasons"]


def test_near_duplicate_of_frozen_test_is_excluded(tmp_path):
    baseline = tmp_path / "custom-baseline.csv"
    _custom_baseline(baseline, "Your bank account will be blocked immediately")
    near = "Your bank account will be blocked immediately tonight"
    assert _leakage_match_kind("Your bank account will be blocked immediately", near) == "near_duplicate"
    summary, _, exclusions, _ = _run(
        tmp_path,
        [_record(message_text=near)],
        baseline=baseline,
        suffix="near",
    )
    assert summary["accepted_training_records"] == 0
    report = next(csv.DictReader(exclusions.open(encoding="utf-8", newline="")))
    assert "duplicate_with_frozen_test" in report["exclusion_reasons"]


def test_provenance_is_preserved_without_reviewer_authorship_or_features(tmp_path):
    _, output, _, _ = _run(tmp_path, [_record("trace-me")])
    rows = load_dataset(output)
    added = rows[32]
    provenance = json.loads(added["source"])
    assert provenance["record_id"] == "trace-me"
    assert provenance["source_citation"] == "Mendeley record citation trace-me"
    assert provenance["license"] == "CC BY 4.0"
    assert provenance["source_label"] == "Smishing"
    assert added["author"] == AUTHOR_UNRECORDED
    assert "reviewer-secret-label" not in added["author"]
    assert set(added) == {"text", "label", "category", "source", "author", "split"}
    assert "private reviewer note" not in Path(output).read_text(encoding="utf-8")


def test_frozen_baseline_rows_validation_and_test_splits_are_preserved(tmp_path):
    original_rows = load_dataset(BASELINE)
    original_splits = split_dataset(original_rows, seed=42)
    _, output, _, _ = _run(tmp_path, [_record()])
    versioned_rows = load_dataset(output)
    assert versioned_rows[:len(original_rows)] == original_rows
    versioned_splits = split_dataset(versioned_rows, seed=42)
    for split in ("validation", "test"):
        assert versioned_splits[split] == original_splits[split]
    assert _cross_split_duplicates(versioned_splits) == []


def test_adapter_outputs_are_reproducible(tmp_path):
    records = [_record("review-b"), _record("review-a")]
    result_a, out_a, exc_a, sum_a = _run(tmp_path / "a", records, suffix="same")
    result_b, out_b, exc_b, sum_b = _run(tmp_path / "b", records, suffix="same")
    assert result_a == result_b
    assert out_a.read_bytes() == out_b.read_bytes()
    assert exc_a.read_bytes() == exc_b.read_bytes()
    assert sum_a.read_bytes() == sum_b.read_bytes()


def test_current_review_file_has_expected_audited_counts(tmp_path):
    summary = adapt_dataset(
        source_path=INCOMING,
        baseline_path=BASELINE,
        output_path=tmp_path / "current-v2.csv",
        exclusion_csv_path=tmp_path / "current-exclusions.csv",
        summary_json_path=tmp_path / "current-summary.json",
    )
    assert summary["input_records"] == 188
    assert summary["accepted_training_records"] == 150
    assert summary["excluded_records"] == 38
    assert summary["final_dataset_records"] == 182
    assert summary["final_class_distribution"] == {"legitimate": 16, "scam": 166}
    assert summary["split_counts"] == {"train": 170, "validation": 6, "test": 6}
    assert summary["label_counts_by_split"] == {
        "train": {"legitimate": 10, "scam": 160},
        "validation": {"legitimate": 3, "scam": 3},
        "test": {"legitimate": 3, "scam": 3},
    }
    assert summary["cross_split_exact_or_near_duplicate_pairs"] == 0


def test_adapter_refuses_to_overwrite_preserved_dataset(tmp_path):
    with pytest.raises(ValueError, match="must not overwrite protected datasets"):
        adapt_dataset(
            source_path=INCOMING,
            baseline_path=BASELINE,
            output_path=BASELINE,
            exclusion_csv_path=tmp_path / "excluded.csv",
            summary_json_path=tmp_path / "summary.json",
        )
