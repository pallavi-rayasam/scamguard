"""Shared, privacy-preserving preprocessing and model construction for offline and live use."""
from __future__ import annotations

import sys
import unicodedata
from difflib import SequenceMatcher
from pathlib import Path
import re

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline

ROOT = Path(__file__).resolve().parents[1]
BACKEND_PATH = ROOT / "backend"
if str(BACKEND_PATH) not in sys.path:
    sys.path.insert(0, str(BACKEND_PATH))

from app.detection.normalize import (  # noqa: E402
    extract_urls,
    normalize_text,
    redact_sensitive,
    redact_urls_in_text,
)

MODEL_VERSION = "message-text-v1"
DEFAULT_SEED = 42
DECISION_THRESHOLD = 0.5
PIPELINE_PARAMETERS = {
    "tfidf": {"ngram_range": (1, 2), "sublinear_tf": True, "max_features": 20_000},
    "classifier": {"max_iter": 2000, "class_weight": "balanced"},
}


def preprocess_text(text: str) -> str:
    """Apply the same deterministic redaction and URL masking before fit and inference."""
    normalized = normalize_text(text)
    redacted, _ = redact_sensitive(normalized)
    redacted = redact_urls_in_text(redacted, extract_urls(redacted))
    return normalize_text(redacted)


def preprocess_texts(texts: list[str]) -> list[str]:
    return [preprocess_text(text) for text in texts]


def build_pipeline(seed: int = DEFAULT_SEED) -> Pipeline:
    parameters = PIPELINE_PARAMETERS
    return Pipeline([
        ("tfidf", TfidfVectorizer(**parameters["tfidf"])),
        ("classifier", LogisticRegression(**parameters["classifier"], random_state=seed)),
    ])


def positive_probabilities(model: Pipeline, texts: list[str]) -> list[float]:
    classes = list(model.classes_)
    if "scam" not in classes:
        raise ValueError("Fitted classifier has no scam class")
    probabilities = model.predict_proba(preprocess_texts(texts))
    return [float(row[classes.index("scam")]) for row in probabilities]


def choose_scam_threshold(actual: list[str], probabilities: list[float]) -> float:
    """Select an F1 threshold using validation values only (caller controls the split)."""
    if len(actual) != len(probabilities) or not actual:
        raise ValueError("Threshold selection needs equally sized, non-empty values")
    candidates = sorted({0.0, 0.5, 1.0, *(float(value) for value in probabilities)})
    ranked: list[tuple[float, float, float]] = []
    for threshold in candidates:
        predicted = ["scam" if value >= threshold else "legitimate" for value in probabilities]
        tp = sum(expected == "scam" and got == "scam" for expected, got in zip(actual, predicted, strict=True))
        fp = sum(expected == "legitimate" and got == "scam" for expected, got in zip(actual, predicted, strict=True))
        fn = sum(expected == "scam" and got == "legitimate" for expected, got in zip(actual, predicted, strict=True))
        precision = tp / (tp + fp) if tp + fp else 0.0
        recall = tp / (tp + fn) if tp + fn else 0.0
        f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
        ranked.append((f1, -abs(threshold - 0.5), threshold))
    return max(ranked)[2]


def _normalized_text(text: str) -> str:
    normalized = unicodedata.normalize("NFKC", text).casefold()
    return " ".join(re.findall(r"\w+", normalized, flags=re.UNICODE))


def find_cross_split_leakage(splits: dict[str, list[dict[str, str]]]) -> list[dict[str, object]]:
    """Find exact and high-similarity duplicates between any two declared partitions."""
    found: list[dict[str, object]] = []
    names = ("train", "validation", "test")
    for left_index, left_name in enumerate(names):
        for right_name in names[left_index + 1:]:
            for i, left in enumerate(splits.get(left_name, [])):
                left_text = _normalized_text(left["text"])
                left_tokens = set(left_text.split())
                for j, right in enumerate(splits.get(right_name, [])):
                    right_text = _normalized_text(right["text"])
                    if left_text == right_text:
                        kind, similarity = "exact", 1.0
                    else:
                        right_tokens = set(right_text.split())
                        union = left_tokens | right_tokens
                        jaccard = len(left_tokens & right_tokens) / len(union) if union else 0.0
                        ratio = SequenceMatcher(None, left_text, right_text, autojunk=False).ratio()
                        if ratio < 0.92 and not (min(len(left_tokens), len(right_tokens)) >= 5 and jaccard >= 0.85):
                            continue
                        kind, similarity = "near_duplicate", max(ratio, jaccard)
                    found.append({
                        "left_split": left_name,
                        "left_index": i,
                        "right_split": right_name,
                        "right_index": j,
                        "kind": kind,
                        "similarity": round(similarity, 4),
                    })
    return found
