"""Trusted, fail-safe loader and advisory inference for the message classifier."""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import importlib.metadata
import json
import logging
import math
from pathlib import Path
import sys
from typing import Any

import joblib
from sklearn.pipeline import Pipeline

from app.schemas.common import MLPredictionResult

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))
from ml.model_pipeline import MODEL_VERSION, preprocess_text  # noqa: E402

logger = logging.getLogger(__name__)
MAX_MESSAGE_CHARS = 12_000
SUPPORTED_INPUT_TYPES = {"text", "sms", "whatsapp", "email", "screenshot", "message", "payment_request"}
REQUIRED_MANIFEST_KEYS = {
    "manifest_schema_version", "model_version", "artifact_file", "artifact_sha256",
    "dependencies", "training_parameters", "class_labels", "calibration_status",
}


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _failure_log(event: str, category: str, exc: Exception | None = None) -> None:
    fields: dict[str, str] = {"event": event, "failure_category": category}
    if exc is not None:
        fields["exception_type"] = type(exc).__name__
    logger.warning("%s", json.dumps(fields, sort_keys=True))


def _result(
    status: str,
    *,
    predicted_class: str | None = None,
    model_version: str | None = None,
) -> dict[str, Any]:
    return MLPredictionResult(
        status=status,
        predicted_class=predicted_class,
        calibrated_probability=None,
        calibration_status="not_justified",
        model_version=model_version,
    ).model_dump(mode="json")


@dataclass
class MessagePredictor:
    pipeline: Pipeline | None = None
    model_version: str | None = None
    decision_threshold: float = 0.5
    availability_status: str = "unavailable"
    failure_category: str | None = None

    @classmethod
    def unavailable(cls, category: str, expected_version: str | None = None) -> "MessagePredictor":
        _failure_log("ml_model_load_failure", category)
        return cls(model_version=expected_version, availability_status="unavailable", failure_category=category)

    @classmethod
    def load(
        cls,
        artifact_path: str | Path,
        *,
        expected_version: str = MODEL_VERSION,
        enabled: bool = True,
    ) -> "MessagePredictor":
        if not enabled:
            return cls(model_version=None, availability_status="disabled", failure_category="disabled_by_configuration")
        path = Path(artifact_path)
        manifest_path = path.with_name("manifest.json")
        if not path.is_file() or not manifest_path.is_file():
            return cls.unavailable("model_artifact_missing", expected_version)
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            if not isinstance(manifest, dict) or not REQUIRED_MANIFEST_KEYS.issubset(manifest):
                return cls.unavailable("manifest_invalid", expected_version)
            if manifest.get("manifest_schema_version") != 1:
                return cls.unavailable("manifest_version_unsupported", expected_version)
            if manifest.get("model_version") != expected_version or manifest.get("artifact_file") != path.name:
                return cls.unavailable("model_version_mismatch", expected_version)
            expected_digest = manifest.get("artifact_sha256")
            if not isinstance(expected_digest, str) or len(expected_digest) != 64:
                return cls.unavailable("manifest_digest_invalid", expected_version)
            if _sha256_file(path) != expected_digest:
                return cls.unavailable("artifact_digest_mismatch", expected_version)
            dependencies = manifest.get("dependencies")
            if not isinstance(dependencies, dict):
                return cls.unavailable("manifest_dependencies_invalid", expected_version)
            if (
                dependencies.get("scikit_learn") != importlib.metadata.version("scikit-learn")
                or dependencies.get("joblib") != importlib.metadata.version("joblib")
            ):
                return cls.unavailable("model_dependency_version_mismatch", expected_version)
            if manifest.get("class_labels") != ["legitimate", "scam"]:
                return cls.unavailable("model_labels_invalid", expected_version)
            if manifest.get("calibration_status") != "not_justified":
                return cls.unavailable("model_calibration_metadata_invalid", expected_version)
            parameters = manifest.get("training_parameters")
            threshold = parameters.get("decision_threshold") if isinstance(parameters, dict) else None
            if not isinstance(threshold, (int, float)) or not math.isfinite(float(threshold)) or not 0 <= threshold <= 1:
                return cls.unavailable("model_threshold_invalid", expected_version)
            pipeline = joblib.load(path)
            if not isinstance(pipeline, Pipeline) or not hasattr(pipeline, "predict_proba"):
                return cls.unavailable("model_artifact_invalid", expected_version)
            if list(pipeline.classes_) != ["legitimate", "scam"]:
                return cls.unavailable("model_labels_invalid", expected_version)
            return cls(
                pipeline=pipeline,
                model_version=expected_version,
                decision_threshold=float(threshold),
                availability_status="available",
            )
        except Exception as exc:
            # Exception strings and artifact paths are intentionally omitted.
            _failure_log("ml_model_load_failure", "model_load_failed", exc)
            return cls(
                model_version=expected_version,
                availability_status="unavailable",
                failure_category="model_load_failed",
            )

    def predict(self, text: str, input_type: str = "text") -> dict[str, Any]:
        version = self.model_version
        if not isinstance(input_type, str) or input_type not in SUPPORTED_INPUT_TYPES:
            return _result("skipped", model_version=version)
        if not isinstance(text, str) or not text.strip() or len(text) > MAX_MESSAGE_CHARS:
            return _result("skipped", model_version=version)
        if self.availability_status == "disabled":
            return _result("skipped", model_version=version)
        if self.availability_status != "available" or self.pipeline is None:
            return _result("unavailable", model_version=version)
        try:
            processed = preprocess_text(text)
            probabilities = self.pipeline.predict_proba([processed])[0]
            classes = list(self.pipeline.classes_)
            score = float(probabilities[classes.index("scam")])
            label = "scam" if score >= self.decision_threshold else "legitimate"
            return _result("completed", predicted_class=label, model_version=version)
        except Exception as exc:
            _failure_log("ml_inference_failure", "inference_failed", exc)
            return _result("failed", model_version=version)
