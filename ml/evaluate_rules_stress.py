"""Rules-only stress test on the explicitly synthetic 320-message corpus.

Run from repository root:
    python ml/evaluate_rules_stress.py

This is a development regression aid, not a real-world accuracy benchmark.
"""
from __future__ import annotations

import csv
from collections import Counter, defaultdict
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
BACKEND = ROOT / "backend"
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

from app.detection.rules import classify_message
from app.detection.scoring import score_findings

SOURCE = ROOT / "ml" / "data" / "synthetic_stress_test_320.csv"
OUT = ROOT / "ml" / "reports"


def main() -> None:
    with SOURCE.open(encoding="utf-8-sig", newline="") as f:
        rows = list(csv.DictReader(f))
    if not rows:
        raise SystemExit("Stress-test CSV is empty.")

    results = []
    for row in rows:
        result = classify_message(row["message"])
        score, level, findings = score_findings(result["findings"])
        prediction = "scam" if score >= 25 else "legitimate"
        results.append({
            "message_id": row["message_id"],
            "actual": row["label"],
            "predicted": prediction,
            "score": score,
            "risk_level": level,
            "expected_category": row["category"],
            "detected_category": result.get("category"),
            "signals": ";".join(sorted({f.get("indicator", "") for f in findings})),
            "message": row["message"],
        })

    labels = ("legitimate", "scam")
    tn = sum(r["actual"] == "legitimate" and r["predicted"] == "legitimate" for r in results)
    fp = sum(r["actual"] == "legitimate" and r["predicted"] == "scam" for r in results)
    fn = sum(r["actual"] == "scam" and r["predicted"] == "legitimate" for r in results)
    tp = sum(r["actual"] == "scam" and r["predicted"] == "scam" for r in results)
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    fpr = fp / (fp + tn) if fp + tn else 0.0
    fnr = fn / (fn + tp) if fn + tp else 0.0

    OUT.mkdir(parents=True, exist_ok=True)
    with (OUT / "synthetic_stress_test_320_results.csv").open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(results[0]))
        writer.writeheader()
        writer.writerows(results)

    for filename, predicate in (
        ("synthetic_stress_test_320_false_positives.csv", lambda r: r["actual"] == "legitimate" and r["predicted"] == "scam"),
        ("synthetic_stress_test_320_false_negatives.csv", lambda r: r["actual"] == "scam" and r["predicted"] == "legitimate"),
    ):
        subset = [r for r in results if predicate(r)]
        with (OUT / filename).open("w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=list(results[0]))
            writer.writeheader()
            writer.writerows(subset)

    category_counts: dict[str, Counter] = defaultdict(Counter)
    for r in results:
        if r["actual"] == "scam":
            category_counts[r["expected_category"]]["support"] += 1
            category_counts[r["expected_category"]]["detected"] += r["predicted"] == "scam"
    with (OUT / "synthetic_stress_test_320_category_metrics.csv").open("w", encoding="utf-8", newline="") as f:
        fields = ["category", "scam_support", "scam_detected", "scam_recall"]
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for category, values in sorted(category_counts.items()):
            support = values["support"]
            writer.writerow({
                "category": category,
                "scam_support": support,
                "scam_detected": values["detected"],
                "scam_recall": round(values["detected"] / support, 4) if support else 0.0,
            })

    print(f"Samples: {len(results)}")
    print(f"Confusion matrix [[TN, FP], [FN, TP]]: [[{tn}, {fp}], [{fn}, {tp}]]")
    print(f"Accuracy: {(tn + tp) / len(results):.4f}")
    print(f"Scam precision: {precision:.4f}")
    print(f"Scam recall: {recall:.4f}")
    print(f"Scam F1: {f1:.4f}")
    print(f"False-positive rate: {fpr:.4f}")
    print(f"False-negative rate: {fnr:.4f}")
    print("WARNING: synthetic rules-only stress test; not a real-world benchmark.")


if __name__ == "__main__":
    main()
