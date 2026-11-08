"""Audit sourced scam candidates for exact/near duplicates without silently deleting rows.

Run from the repository root:
    python ml/audit_sourced_candidates.py
"""
from __future__ import annotations

import csv
from collections import Counter
from difflib import SequenceMatcher
from pathlib import Path
import re
import unicodedata

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "ml" / "data" / "sourced_scam_candidates.csv"
OUT = ROOT / "ml" / "reports"
REQUIRED = ("text", "label", "category", "source", "author", "split")


def normalize(text: str) -> str:
    text = unicodedata.normalize("NFKC", text).casefold()
    return re.sub(r"\W+", " ", text).strip()


def match_kind(left: str, right: str) -> tuple[str | None, float]:
    a, b = normalize(left), normalize(right)
    if a == b:
        return "exact_normalized", 1.0
    if not a or not b:
        return None, 0.0
    sequence = SequenceMatcher(None, a, b, autojunk=False).ratio()
    at, bt = set(a.split()), set(b.split())
    union = at | bt
    jaccard = len(at & bt) / len(union) if union else 0.0
    if sequence >= 0.92 or (min(len(at), len(bt)) >= 5 and jaccard >= 0.85):
        return "near_duplicate", max(sequence, jaccard)
    return None, max(sequence, jaccard)


def main() -> None:
    with SOURCE.open(encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        missing = [name for name in REQUIRED if name not in (reader.fieldnames or [])]
        if missing:
            raise SystemExit(f"Missing required columns: {missing}")
        rows = list(reader)

    n = len(rows)
    parent = list(range(n))

    def find(x: int) -> int:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a: int, b: int) -> None:
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[rb] = ra

    pairs = []
    for i in range(n):
        for j in range(i + 1, n):
            kind, similarity = match_kind(rows[i]["text"], rows[j]["text"])
            if kind:
                pairs.append((i, j, kind, similarity))
                union(i, j)

    clusters: dict[int, list[int]] = {}
    for i in range(n):
        clusters.setdefault(find(i), []).append(i)

    OUT.mkdir(parents=True, exist_ok=True)
    cluster_records = []
    for cluster_no, members in enumerate(sorted(clusters.values(), key=min), start=1):
        eligible = [
            i for i in members
            if "original_label=spam" not in rows[i]["source"].casefold()
        ]
        representative = (
            max(eligible, key=lambda i: (len(rows[i]["text"]), -i))
            if eligible else None
        )
        for i in members:
            original = re.search(r"original_label=([^;]+)", rows[i]["source"], re.I)
            cluster_records.append({
                "source_row_index": i,
                "cluster_id": f"C{cluster_no:03d}",
                "cluster_size": len(members),
                "is_cluster_representative": i == representative,
                "eligible_scam_candidate": "original_label=spam" not in rows[i]["source"].casefold(),
                "original_source_label": original.group(1).strip() if original else "unknown",
                **rows[i],
            })

    with (OUT / "sourced_candidate_duplicate_clusters.csv").open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(cluster_records[0]))
        writer.writeheader()
        writer.writerows(cluster_records)

    pair_records = [{
        "left_source_row_index": i,
        "right_source_row_index": j,
        "match_type": kind,
        "similarity": round(similarity, 4),
        "left_text": rows[i]["text"],
        "right_text": rows[j]["text"],
    } for i, j, kind, similarity in pairs]
    with (OUT / "sourced_candidate_near_duplicate_pairs.csv").open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(pair_records[0]) if pair_records else [
            "left_source_row_index", "right_source_row_index", "match_type", "similarity", "left_text", "right_text"
        ])
        writer.writeheader()
        writer.writerows(pair_records)

    labels = Counter(re.search(r"original_label=([^;]+)", r["source"], re.I).group(1).strip().casefold()
                     if re.search(r"original_label=([^;]+)", r["source"], re.I) else "unknown"
                     for r in rows)
    sizes = Counter(len(m) for m in clusters.values())
    print(f"Rows: {n}")
    print(f"Pairwise exact/near-duplicate matches: {len(pairs)}")
    print(f"  Exact after NFKC/casefold/punctuation normalization: {sum(p[2] == 'exact_normalized' for p in pairs)}")
    print(f"  Near duplicates: {sum(p[2] == 'near_duplicate' for p in pairs)}")
    print(f"Connected similarity clusters: {len(clusters)}")
    print(f"Cluster size distribution: {dict(sorted(sizes.items()))}")
    print(f"Original source labels: {dict(labels)}")
    print("No rows were deleted or promoted to an approved training set.")


if __name__ == "__main__":
    main()
