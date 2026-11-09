"""Train and persist the versioned ScamShield message-text model."""
from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

import joblib
import sklearn

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
BACKEND_PATH = ROOT / "backend"
if str(BACKEND_PATH) not in sys.path:
    sys.path.insert(0, str(BACKEND_PATH))

from ml.evaluate import _binary_metrics, load_dataset, split_dataset  # noqa: E402
from ml.model_pipeline import (  # noqa: E402
    DEFAULT_SEED,
    MODEL_VERSION,
    PIPELINE_PARAMETERS,
    build_pipeline,
    choose_scam_threshold,
    find_cross_split_leakage,
    preprocess_texts,
    positive_probabilities,
)

DEFAULT_DATASET = ROOT / "ml" / "data" / "indian_scam_examples_v2.csv"
DEFAULT_OUTPUT = ROOT / "ml" / "artifacts" / MODEL_VERSION


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _source_revision() -> dict[str, object]:
    try:
        revision = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, check=True,
            capture_output=True, text=True, timeout=5,
        ).stdout.strip()
        dirty = bool(subprocess.run(
            ["git", "status", "--porcelain"], cwd=ROOT, check=True,
            capture_output=True, text=True, timeout=5,
        ).stdout.strip())
        return {"commit": revision, "working_tree_dirty": dirty}
    except (OSError, subprocess.SubprocessError):
        return {"commit": None, "working_tree_dirty": None}


def _dependency_versions() -> dict[str, str]:
    return {
        "python": ".".join(map(str, sys.version_info[:3])),
        "scikit_learn": sklearn.__version__,
        "joblib": importlib.metadata.version("joblib"),
    }


def _training_source_hashes() -> dict[str, str]:
    source_paths = (
        ROOT / "ml" / "model_pipeline.py",
        ROOT / "ml" / "train_model.py",
        ROOT / "ml" / "evaluate.py",
        ROOT / "backend" / "app" / "detection" / "normalize.py",
    )
    return {path.relative_to(ROOT).as_posix(): _sha256_file(path) for path in source_paths}


def train_and_save(
    dataset_path: Path = DEFAULT_DATASET,
    output_dir: Path = DEFAULT_OUTPUT,
    seed: int = DEFAULT_SEED,
) -> dict[str, object]:
    dataset_path = Path(dataset_path)
    output_dir = Path(output_dir)
    rows = load_dataset(dataset_path)
    splits = split_dataset(rows, seed=seed)
    leakage = find_cross_split_leakage(splits)
    if leakage:
        first = leakage[0]
        raise ValueError(
            "exact/near-duplicate leakage across splits: "
            f"{first['left_split']} row {first['left_index']} vs "
            f"{first['right_split']} row {first['right_index']} ({first['kind']})"
        )
    train_rows = splits["train"]
    validation_rows = splits["validation"]
    test_rows = splits["test"]
    if {row["label"] for row in train_rows} != {"scam", "legitimate"}:
        raise ValueError("training split must contain both labels")
    if {row["label"] for row in validation_rows} != {"scam", "legitimate"}:
        raise ValueError("validation split must contain both labels")

    pipeline = build_pipeline(seed=seed)
    pipeline.fit(
        preprocess_texts([row["text"] for row in train_rows]),
        [row["label"] for row in train_rows],
    )
    validation_probabilities = positive_probabilities(pipeline, [row["text"] for row in validation_rows])
    threshold = choose_scam_threshold([row["label"] for row in validation_rows], validation_probabilities)
    test_predictions = [
        "scam" if value >= threshold else "legitimate"
        for value in positive_probabilities(pipeline, [row["text"] for row in test_rows])
    ]
    test_metrics = _binary_metrics([row["label"] for row in test_rows], test_predictions)

    output_dir.mkdir(parents=True, exist_ok=True)
    artifact_path = output_dir / "pipeline.joblib"
    manifest_path = output_dir / "manifest.json"
    with tempfile.NamedTemporaryFile(prefix="pipeline-", suffix=".joblib", dir=output_dir, delete=False) as temp_file:
        temporary_artifact = Path(temp_file.name)
    try:
        joblib.dump(pipeline, temporary_artifact, compress=3)
        artifact_digest = _sha256_file(temporary_artifact)
        os.replace(temporary_artifact, artifact_path)
    finally:
        temporary_artifact.unlink(missing_ok=True)

    label_counts = {
        name: {label: sum(row["label"] == label for row in partition) for label in ("legitimate", "scam")}
        for name, partition in splits.items()
    }
    resolved_dataset = dataset_path.resolve()
    relative_dataset = resolved_dataset.relative_to(ROOT).as_posix() if resolved_dataset.is_relative_to(ROOT) else dataset_path.name
    manifest: dict[str, object] = {
        "manifest_schema_version": 1,
        "model_version": MODEL_VERSION,
        "artifact_file": artifact_path.name,
        "artifact_sha256": artifact_digest,
        "training_dataset": relative_dataset,
        "training_dataset_sha256": _sha256_file(dataset_path),
        "source_code_revision": _source_revision(),
        "training_source_sha256": _training_source_hashes(),
        "dependencies": _dependency_versions(),
        "training_parameters": {
            "seed": seed,
            "pipeline": {
                "tfidf": {
                    **PIPELINE_PARAMETERS["tfidf"],
                    "ngram_range": list(PIPELINE_PARAMETERS["tfidf"]["ngram_range"]),
                },
                "classifier": {**PIPELINE_PARAMETERS["classifier"], "random_state": seed},
            },
            "decision_threshold": threshold,
            "decision_threshold_selected_on": "validation only",
            "fit_partition": "train only",
        },
        "label_mapping": {"class_labels": list(pipeline.classes_), "positive_class": "scam"},
        "class_labels": list(pipeline.classes_),
        "split_counts": {name: len(partition) for name, partition in splits.items()},
        "label_counts_by_split": label_counts,
        "calibration_status": "not_justified",
        "calibrated_probability_supported": False,
        "intended_use": "Experimental single-message classification advisory; never determines risk severity.",
        "limitations": [
            "The held-out test split contains only six records.",
            "The training data is highly imbalanced and has limited source diversity.",
            "The model is not calibrated and must not be displayed as a probability.",
        ],
        "held_out_test_metrics": test_metrics,
    }
    temporary_manifest = manifest_path.with_suffix(".json.tmp")
    temporary_manifest.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    os.replace(temporary_manifest, manifest_path)
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", type=Path, default=DEFAULT_DATASET)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    args = parser.parse_args()
    print(json.dumps(train_and_save(args.dataset, args.output_dir, args.seed), ensure_ascii=False, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
