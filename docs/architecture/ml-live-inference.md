# Live ML advisory integration

The backend loads `message-text-v1` once in the FastAPI lifespan from the configured model path. `ML_MODEL_ENABLED` can disable it; `ML_MODEL_VERSION` and `ML_MODEL_PATH` select the expected artifact. The model loader verifies the adjacent manifest, model version, artifact SHA-256, class labels, calibration metadata, and installed scikit-learn/joblib versions. Load errors are safely logged by category and the API remains available.

Only a single supported message is classified. URL-only, transaction, multi-message conversation, empty, invalid, and over-limit inputs return `skipped`; unavailable artifacts and inference errors return explicit `unavailable` or `failed` states. Shared preprocessing normalizes text, redacts sensitive values, and replaces URLs before both model fitting and live prediction.

The report stores a separate `ml_prediction` object with `status`, `predicted_class`, `calibrated_probability` (always null), `calibration_status` (`not_justified`), and `model_version`. The report page and PDF label it an experimental suggestion. It is not added to findings/evidence and cannot change category, risk score/level, evidence strength, deterministic findings, recommendations, URL intelligence, or LLM/fallback content. Its purpose is offline validation plus low-stakes presentation only; do not expand its role without a larger independent evaluation.

The model is packaged into the backend Docker image under `/app/ml/artifacts/message-text-v1`. The image also contains the shared preprocessing module. Local development defaults to the matching workspace artifact path. Build a fresh artifact with `python ml/train_model.py` before rebuilding the backend image.
