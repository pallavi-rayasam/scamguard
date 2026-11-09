from dataclasses import replace
import json
from datetime import datetime, timezone
from io import BytesIO

import pytest
from app.agents import workflow
from app.ml.predictor import MessagePredictor
from app.reports.pdf import build_investigation_pdf
from app.schemas.common import MLPredictionResult
from pypdf import PdfReader
from ml.model_pipeline import MODEL_VERSION
from ml.train_model import DEFAULT_DATASET, train_and_save


def test_training_persists_reloadable_versioned_artifact(tmp_path):
    output = tmp_path / MODEL_VERSION
    manifest = train_and_save(DEFAULT_DATASET, output, seed=17)

    loaded = MessagePredictor.load(output / "pipeline.joblib", expected_version=MODEL_VERSION)

    assert loaded.availability_status == "available"
    assert manifest["model_version"] == MODEL_VERSION
    assert manifest["source_code_revision"]["commit"]
    assert "ml/model_pipeline.py" in manifest["training_source_sha256"]
    assert manifest["training_parameters"]["fit_partition"] == "train only"
    assert manifest["training_parameters"]["decision_threshold_selected_on"] == "validation only"
    assert manifest["calibration_status"] == "not_justified"


def test_training_is_reproducible_for_same_seed(tmp_path):
    first_dir = tmp_path / "first"
    second_dir = tmp_path / "second"
    first_manifest = train_and_save(DEFAULT_DATASET, first_dir, seed=23)
    second_manifest = train_and_save(DEFAULT_DATASET, second_dir, seed=23)
    first = MessagePredictor.load(first_dir / "pipeline.joblib")
    second = MessagePredictor.load(second_dir / "pipeline.joblib")
    sample = "Your parcel is held. Pay the fee using the link today."

    assert first_manifest["training_parameters"] == second_manifest["training_parameters"]
    assert first.pipeline.predict([sample]) == second.pipeline.predict([sample])
    assert first_manifest["split_counts"] == {"train": 170, "validation": 6, "test": 6}


def test_predict_returns_advisory_without_uncalibrated_probability(tmp_path):
    output = tmp_path / MODEL_VERSION
    train_and_save(DEFAULT_DATASET, output)
    predictor = MessagePredictor.load(output / "pipeline.joblib")

    result = predictor.predict("Your parcel is held. Pay a clearance fee through this link now.", "text")

    assert result["status"] == "completed"
    assert result["predicted_class"] in {"scam", "legitimate"}
    assert result["calibrated_probability"] is None
    assert result["calibration_status"] == "not_justified"
    assert result["model_version"] == MODEL_VERSION


def test_model_load_fails_safe_for_missing_corrupt_and_wrong_version_artifacts(tmp_path):
    missing = MessagePredictor.load(tmp_path / "missing.joblib")
    assert missing.availability_status == "unavailable"
    assert missing.predict("ordinary message")["status"] == "unavailable"

    output = tmp_path / MODEL_VERSION
    train_and_save(DEFAULT_DATASET, output)
    artifact = output / "pipeline.joblib"
    wrong_version = MessagePredictor.load(artifact, expected_version="another-version")
    assert wrong_version.availability_status == "unavailable"
    assert wrong_version.failure_category == "model_version_mismatch"

    artifact.write_bytes(artifact.read_bytes() + b"corruption")
    corrupt = MessagePredictor.load(artifact)
    assert corrupt.availability_status == "unavailable"
    assert corrupt.failure_category == "artifact_digest_mismatch"


def test_manifest_malformed_and_explicit_disable_are_safe(tmp_path):
    output = tmp_path / MODEL_VERSION
    train_and_save(DEFAULT_DATASET, output)
    manifest_path = output / "manifest.json"
    manifest_path.write_text(json.dumps({"model_version": MODEL_VERSION}), encoding="utf-8")
    malformed = MessagePredictor.load(output / "pipeline.joblib")
    assert malformed.availability_status == "unavailable"
    assert malformed.failure_category == "manifest_invalid"

    disabled = MessagePredictor.load(output / "pipeline.joblib", enabled=False)
    assert disabled.predict("text")["status"] == "skipped"


def test_invalid_oversized_and_unsupported_inputs_are_skipped(tmp_path):
    output = tmp_path / MODEL_VERSION
    train_and_save(DEFAULT_DATASET, output)
    predictor = MessagePredictor.load(output / "pipeline.joblib")

    assert predictor.predict(" ", "text")["status"] == "skipped"
    assert predictor.predict("x" * 12_001, "text")["status"] == "skipped"
    assert predictor.predict("one message", "conversation")["status"] == "skipped"
    assert predictor.predict("transaction data", "transaction")["status"] == "skipped"
    assert predictor.predict("https://example.com", "url")["status"] == "skipped"
    assert predictor.predict("ordinary text", ["text"])["status"] == "skipped"


def test_sensitive_values_and_url_paths_are_redacted_before_model_features():
    class RecordingPipeline:
        classes_ = ["legitimate", "scam"]
        received = None

        def predict_proba(self, texts):
            self.received = texts[0]
            return [[0.1, 0.9]]

    pipeline = RecordingPipeline()
    predictor = MessagePredictor(
        pipeline=pipeline,
        model_version=MODEL_VERSION,
        availability_status="available",
    )
    result = predictor.predict(
        "Your OTP is 123456. Verify at https://bank.example/path?token=secret",
        "text",
    )

    assert result["status"] == "completed"
    assert "123456" not in pipeline.received
    assert "/path" not in pipeline.received
    assert "token=secret" not in pipeline.received


def test_ml_failure_does_not_change_deterministic_investigation(monkeypatch, tmp_path):
    output = tmp_path / MODEL_VERSION
    train_and_save(DEFAULT_DATASET, output)
    available = MessagePredictor.load(output / "pipeline.joblib")
    unavailable = MessagePredictor.unavailable("test_unavailable", MODEL_VERSION)
    monkeypatch.setattr(workflow, "settings", replace(workflow.settings, url_scanner_url=""))
    monkeypatch.setattr(workflow, "get_explanation_provider", lambda: None)

    with_ml = workflow.investigate("Your account will be suspended. Verify through this link now.", "text", ml_predictor=available)
    without_ml = workflow.investigate("Your account will be suspended. Verify through this link now.", "text", ml_predictor=unavailable)

    for field in (
        "risk_score", "risk_level", "category", "findings", "evidence_strength",
        "recommendations", "explanation", "explanation_source", "threat_intel_results",
        "url_scans", "data_availability",
    ):
        assert with_ml[field] == without_ml[field]
    assert with_ml["ml_prediction"]["status"] == "completed"
    assert without_ml["ml_prediction"]["status"] == "unavailable"
    assert not any(item.get("source") == "ml_model" for item in with_ml["findings"])


def test_inference_exception_is_contained_and_does_not_change_findings(monkeypatch):
    class BrokenPredictor:
        def predict(self, *_args, **_kwargs):
            raise RuntimeError("private diagnostic is intentionally not exposed")

    monkeypatch.setattr(workflow, "settings", replace(workflow.settings, url_scanner_url=""))
    monkeypatch.setattr(workflow, "get_explanation_provider", lambda: None)
    report = workflow.investigate("A routine message without a link.", "text", ml_predictor=BrokenPredictor())

    assert report["ml_prediction"]["status"] == "failed"
    assert report["risk_score"] == 0
    assert report["findings"] == []


def test_pdf_includes_ml_advisory_without_claiming_probability():
    report = {
        "risk_score": 12,
        "risk_level": "Low",
        "category": None,
        "input_type": "text",
        "ml_prediction": {
            "status": "completed",
            "predicted_class": "scam",
            "calibrated_probability": None,
            "calibration_status": "not_justified",
            "model_version": MODEL_VERSION,
        },
    }
    pdf = build_investigation_pdf(report, datetime(2026, 1, 1, tzinfo=timezone.utc))
    text = "\n".join(page.extract_text() or "" for page in PdfReader(BytesIO(pdf)).pages)

    assert "Experimental ML suggestion" in text
    assert "scam-like" in text
    assert "does not change the deterministic score" in text
    assert "no probability is shown" in text


def test_prediction_schema_rejects_unvalidated_output():
    with pytest.raises(ValueError):
        MLPredictionResult(status="completed", predicted_class=None)
    with pytest.raises(ValueError):
        MLPredictionResult(status="completed", predicted_class="scam", calibrated_probability=0.99)
