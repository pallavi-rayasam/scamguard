"""Build a versioned evaluation dataset from reviewed incoming annotations.

The incoming file remains immutable. Only privacy-cleared, reviewer-accepted scam
rows are appended to the frozen baseline as training examples.
"""
from __future__ import annotations

import argparse
from collections import Counter
import csv
import json
from pathlib import Path
import re
import sys
import unicodedata
from difflib import SequenceMatcher

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ml.evaluate import REQUIRED_COLUMNS, load_dataset, split_dataset  # noqa: E402

INCOMING = ROOT / "ml" / "data" / "incoming" / "scamshieldcsv.csv"
BASELINE = ROOT / "ml" / "data" / "indian_scam_examples.csv"
OUTPUT = ROOT / "ml" / "data" / "indian_scam_examples_v2.csv"
EXCLUSION_CSV = ROOT / "ml" / "reports" / "incoming_review_exclusions.csv"
SUMMARY_JSON = ROOT / "ml" / "reports" / "incoming_review_adapter_summary.json"
AUTHOR_UNRECORDED = "source_author_unrecorded"

INPUT_REQUIRED_COLUMNS = (
    "review_id",
    "cluster_id",
    "source_label",
    "verified_label",
    "verified_category",
    "message_text",
    "source_citation",
    "license",
    "message_quality",
    "contains_personal_data",
    "keep_for_training",
)
VALID_LABELS = {"scam", "legitimate", "uncertain"}
VALID_QUALITY = {"good", "unusable"}
VALID_YES_NO = {"yes", "no"}

# These patterns deliberately err on the side of exclusion. They identify possible
# sensitive data only; no matched value is logged or included in the reports.
AADHAAR_PATTERN = re.compile(r"(?<!\d)(?:\d[ -]?){11}\d(?!\d)")
UPI_PATTERN = re.compile(r"(?i)\b(?P<address>[a-z0-9._-]{2,}@[a-z][a-z0-9.-]{1,})\b")
CARD_PATTERN = re.compile(r"(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)")


def detect_sensitive_patterns(text: str) -> set[str]:
    """Return names of possible sensitive-value families, never their contents."""
    matches: set[str] = set()
    if AADHAAR_PATTERN.search(text):
        matches.add("possible_aadhaar_value")
    if any("." not in match.group("address").rsplit("@", 1)[1] for match in UPI_PATTERN.finditer(text)):
        matches.add("possible_upi_value")
    if CARD_PATTERN.search(text):
        matches.add("possible_card_value")
    return matches


def _normalize_for_leakage(text: str) -> str:
    normalized = unicodedata.normalize("NFKC", text).casefold()
    return " ".join(re.findall(r"\w+", normalized, flags=re.UNICODE))


def _leakage_match_kind(left: str, right: str) -> str | None:
    """Use the evaluation harness thresholds for exact and near-duplicate checks."""
    a, b = _normalize_for_leakage(left), _normalize_for_leakage(right)
    if a == b:
        return "exact"
    if not a or not b:
        return None
    sequence_ratio = SequenceMatcher(None, a, b, autojunk=False).ratio()
    left_tokens, right_tokens = set(a.split()), set(b.split())
    union = left_tokens | right_tokens
    jaccard = len(left_tokens & right_tokens) / len(union) if union else 0.0
    if sequence_ratio >= 0.92 or (min(len(left_tokens), len(right_tokens)) >= 5 and jaccard >= 0.85):
        return "near_duplicate"
    return None


def _cross_split_duplicates(splits: dict[str, list[dict[str, str]]]) -> list[dict[str, object]]:
    names = ("train", "validation", "test")
    found: list[dict[str, object]] = []
    for left_pos, left_name in enumerate(names):
        for right_name in names[left_pos + 1 :]:
            for left_index, left in enumerate(splits[left_name]):
                for right_index, right in enumerate(splits[right_name]):
                    kind = _leakage_match_kind(left["text"], right["text"])
                    if kind:
                        found.append({
                            "left_split": left_name,
                            "left_index": left_index,
                            "right_split": right_name,
                            "right_index": right_index,
                            "kind": kind,
                        })
    return found


def _read_input(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames is None:
            raise ValueError("Incoming CSV is empty or has no header")
        missing = [column for column in INPUT_REQUIRED_COLUMNS if column not in reader.fieldnames]
        if missing:
            raise ValueError(f"Incoming CSV is missing required columns: {', '.join(missing)}")
        rows: list[dict[str, str]] = []
        seen_ids: set[str] = set()
        for line, raw in enumerate(reader, start=2):
            row = {key: (raw.get(key) or "").strip() for key in INPUT_REQUIRED_COLUMNS}
            if not row["review_id"] or not row["cluster_id"] or not row["message_text"].strip():
                raise ValueError(f"Incoming row {line} needs review_id, cluster_id, and message_text")
            if row["review_id"] in seen_ids:
                raise ValueError(f"Incoming row {line} duplicates a review_id")
            seen_ids.add(row["review_id"])
            if row["verified_label"].casefold() not in VALID_LABELS:
                raise ValueError(f"Incoming row {line} has an unsupported verified_label")
            if row["message_quality"].casefold() not in VALID_QUALITY:
                raise ValueError(f"Incoming row {line} has an unsupported message_quality")
            if row["contains_personal_data"].casefold() not in VALID_YES_NO:
                raise ValueError(f"Incoming row {line} has an invalid contains_personal_data value")
            if row["keep_for_training"].casefold() not in VALID_YES_NO:
                raise ValueError(f"Incoming row {line} has an invalid keep_for_training value")
            for column in ("source_label", "verified_category", "source_citation", "license"):
                if not row[column]:
                    raise ValueError(f"Incoming row {line} needs a non-empty {column}")
            row["_row_number"] = str(line)
            rows.append(row)
    if not rows:
        raise ValueError("Incoming CSV contains no records")
    return rows


def _read_baseline(path: Path) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
    # Use the evaluation loader for its schema/label validation, while retaining the
    # raw column values for the versioned file so the baseline records stay unchanged.
    evaluated = load_dataset(path)
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        raw_rows = [
            {column: (row.get(column) or "") for column in REQUIRED_COLUMNS}
            for row in reader
        ]
    if len(raw_rows) != len(evaluated):
        raise ValueError("Baseline row count changed while reading")
    for raw, evaluated_row in zip(raw_rows, evaluated, strict=True):
        if any(raw[column] != evaluated_row[column] for column in REQUIRED_COLUMNS):
            raise ValueError("Baseline contains values that the evaluation loader would normalize")
    return raw_rows, evaluated


def _candidate_row(row: dict[str, str]) -> dict[str, str]:
    # Keep source attribution/citation in the existing source field. Reviewer IDs and
    # notes are intentionally neither copied nor used as model features/authorship.
    provenance = {
        "dataset": "reviewed incoming scam corpus",
        "record_id": row["review_id"],
        "source_label": row["source_label"],
        "source_citation": row["source_citation"],
        "license": row["license"],
    }
    return {
        "text": row["message_text"],
        "label": "scam",
        "category": row["verified_category"],
        "source": json.dumps(provenance, ensure_ascii=False, sort_keys=True, separators=(",", ":")),
        "author": AUTHOR_UNRECORDED,
        "split": "train",
    }


def _write_csv(path: Path, rows: list[dict[str, str]], fieldnames: tuple[str, ...] | list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, extrasaction="raise")
        writer.writeheader()
        writer.writerows(rows)


def adapt_dataset(
    *,
    source_path: Path = INCOMING,
    baseline_path: Path = BASELINE,
    output_path: Path = OUTPUT,
    exclusion_csv_path: Path = EXCLUSION_CSV,
    summary_json_path: Path = SUMMARY_JSON,
    seed: int = 42,
) -> dict[str, object]:
    protected = {
        source_path.resolve(),
        baseline_path.resolve(),
        INCOMING.resolve(),
        BASELINE.resolve(),
        (ROOT / "ml" / "data" / "sourced_scam_candidates.csv").resolve(),
        (ROOT / "ml" / "data" / "synthetic_stress_test_320.csv").resolve(),
    }
    targets = [output_path.resolve(), exclusion_csv_path.resolve(), summary_json_path.resolve()]
    if any(target in protected for target in targets) or len(set(targets)) != len(targets):
        raise ValueError("Output paths must be distinct and must not overwrite protected datasets")

    incoming = _read_input(source_path)
    baseline_raw, baseline_eval = _read_baseline(baseline_path)
    baseline_splits = split_dataset(baseline_eval, seed=seed)
    if _cross_split_duplicates(baseline_splits):
        raise ValueError("Baseline already has exact or near-duplicate leakage across splits")

    accepted: list[dict[str, str]] = []
    accepted_eval: list[dict[str, str]] = []
    exclusions: list[dict[str, str]] = []
    reason_counts: Counter[str] = Counter()

    # Stable order makes the duplicate winner and resulting CSV reproducible.
    for row in sorted(incoming, key=lambda item: (item["review_id"].casefold(), item["review_id"])):
        reasons: set[str] = set()
        if row["verified_label"].casefold() != "scam":
            reasons.add("verified_label_not_scam")
        if row["keep_for_training"].casefold() != "yes":
            reasons.add("not_approved_for_training")
        if row["message_quality"].casefold() != "good":
            reasons.add("message_quality_not_good")
        if row["contains_personal_data"].casefold() != "no":
            reasons.add("contains_personal_data")
        reasons.update(detect_sensitive_patterns(row["message_text"]))

        if not reasons:
            for split_name, split_rows in baseline_splits.items():
                for prior in split_rows:
                    kind = _leakage_match_kind(row["message_text"], prior["text"])
                    if kind:
                        if split_name in {"validation", "test"}:
                            reasons.add(f"duplicate_with_frozen_{split_name}")
                        else:
                            reasons.add("duplicate_with_baseline_training_record")
            for prior in accepted_eval:
                if _leakage_match_kind(row["message_text"], prior["text"]):
                    reasons.add("duplicate_with_accepted_training_record")

        if reasons:
            reason_list = sorted(reasons)
            exclusions.append({
                "review_id": row["review_id"],
                "cluster_id": row["cluster_id"],
                "source_row_number": row["_row_number"],
                "exclusion_reasons": ";".join(reason_list),
            })
            reason_counts.update(reason_list)
            continue

        candidate = _candidate_row(row)
        accepted.append(candidate)
        accepted_eval.append({**candidate, "text": candidate["text"], "label": candidate["label"]})

    combined_eval = [*baseline_eval, *accepted_eval]
    final_splits = split_dataset(combined_eval, seed=seed)
    leakage = _cross_split_duplicates(final_splits)
    if leakage:
        first = leakage[0]
        raise ValueError(
            "Output would contain cross-split leakage: "
            f"{first['left_split']} row {first['left_index']} vs "
            f"{first['right_split']} row {first['right_index']} ({first['kind']})"
        )

    final_rows = [*baseline_raw, *accepted]
    _write_csv(output_path, final_rows, REQUIRED_COLUMNS)
    _write_csv(exclusion_csv_path, exclusions, ("review_id", "cluster_id", "source_row_number", "exclusion_reasons"))

    summary: dict[str, object] = {
        "source_file": source_path.name,
        "baseline_file": baseline_path.name,
        "output_file": output_path.name,
        "seed": seed,
        "input_records": len(incoming),
        "accepted_training_records": len(accepted),
        "excluded_records": len(exclusions),
        "exclusion_reason_counts_overlapping": dict(sorted(reason_counts.items())),
        "exclusion_reason_counts_note": "A record can have multiple reasons; these counts are not mutually exclusive.",
        "final_dataset_records": len(final_rows),
        "final_class_distribution": dict(sorted(Counter(row["label"] for row in final_rows).items())),
        "split_counts": {name: len(final_splits[name]) for name in ("train", "validation", "test")},
        "label_counts_by_split": {
            name: dict(sorted(Counter(row["label"] for row in final_splits[name]).items()))
            for name in ("train", "validation", "test")
        },
        "cross_split_exact_or_near_duplicate_pairs": 0,
        "author_policy": AUTHOR_UNRECORDED,
        "reviewer_notes_or_ids_used_as_features": False,
    }
    summary_json_path.parent.mkdir(parents=True, exist_ok=True)
    summary_json_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return summary


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=INCOMING)
    parser.add_argument("--baseline", type=Path, default=BASELINE)
    parser.add_argument("--output", type=Path, default=OUTPUT)
    parser.add_argument("--exclusion-csv", type=Path, default=EXCLUSION_CSV)
    parser.add_argument("--summary-json", type=Path, default=SUMMARY_JSON)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()
    summary = adapt_dataset(
        source_path=args.source,
        baseline_path=args.baseline,
        output_path=args.output,
        exclusion_csv_path=args.exclusion_csv,
        summary_json_path=args.summary_json,
        seed=args.seed,
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
