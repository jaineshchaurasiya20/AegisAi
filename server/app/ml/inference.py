"""
AegisAI ML Inference Engine
Hybrid dual-model approach:
  1. XGBoost (ONNX Runtime) — supervised classifier for known intrusion signatures
  2. Isolation Forest (scikit-learn) — unsupervised anomaly detector for zero-days

If ONNX model file is not present, falls back to simulation mode for demo purposes.
"""
import os
import random
import numpy as np
from pathlib import Path
from typing import Any, Dict, Optional
from loguru import logger
from app.ml.preprocessor import extract_features_from_host, FEATURE_COLUMNS
from app.collector.host_monitor import get_host_snapshot

from app.core.path_utils import get_resource_path

MODEL_DIR = Path(get_resource_path("server/app/ml/models"))
if not MODEL_DIR.exists():
    MODEL_DIR = Path(__file__).parent / "models"

XGB_ONNX_PATH = MODEL_DIR / "xgb_threat_model.onnx"
IFOREST_ONNX_PATH = MODEL_DIR / "isolation_forest.onnx"

_xgb_session = None
_iforest_session = None


def _load_models():
    """Lazy-load exported ONNX models when artifacts are available."""
    global _xgb_session, _iforest_session
    if not (XGB_ONNX_PATH.exists() or IFOREST_ONNX_PATH.exists()):
        return
    try:
        import onnxruntime as ort
    except ImportError:
        logger.warning("onnxruntime is not installed; using simulated ML scores.")
        return

    if XGB_ONNX_PATH.exists() and _xgb_session is None:
        try:
            _xgb_session = ort.InferenceSession(
                str(XGB_ONNX_PATH), providers=["CPUExecutionProvider"]
            )
            logger.info("XGBoost ONNX model loaded successfully.")
        except Exception as e:
            logger.warning(f"Failed to load XGBoost ONNX model: {e}. Using simulation mode.")
    if IFOREST_ONNX_PATH.exists() and _iforest_session is None:
        try:
            _iforest_session = ort.InferenceSession(
                str(IFOREST_ONNX_PATH), providers=["CPUExecutionProvider"]
            )
            logger.info("Isolation Forest ONNX model loaded successfully.")
        except Exception as e:
            logger.warning(f"Failed to load Isolation Forest ONNX model: {e}. Using simulation mode.")


def _positive_class_score(outputs: list) -> float:
    """Extract the positive-class probability from common ONNX classifier outputs."""
    for output in outputs:
        if isinstance(output, list) and output and isinstance(output[0], dict):
            probability = output[0].get(1, output[0].get("1"))
            if probability is not None:
                return float(probability)
        values = np.asarray(output)
        if values.ndim == 2 and values.shape[1] >= 2:
            return float(values[0, 1])
    raise ValueError("ONNX classifier did not return a positive-class probability")


def _anomaly_score(outputs: list) -> float:
    """Map Isolation Forest's ONNX decision score to a 0..1 anomaly probability."""
    for output in reversed(outputs):
        values = np.asarray(output)
        if values.dtype.kind not in "f" or not values.size:
            continue
        raw_score = float(values.reshape(values.shape[0], -1)[0, -1])
        # sklearn's IsolationForest decision_function is lower for anomalies.
        return float(np.clip(1.0 - (raw_score + 0.5), 0.0, 1.0))
    raise ValueError("ONNX Isolation Forest did not return a numeric decision score")


def _simulate_xgboost_score(features: np.ndarray) -> float:
    """Deterministic-ish simulation of XGBoost threat probability score."""
    # Use feature magnitudes to produce a plausible score
    norm = np.linalg.norm(features)
    base = 1 / (1 + np.exp(-0.3 * (norm - 3.0)))  # sigmoid around norm=3
    noise = random.uniform(-0.08, 0.08)
    return float(np.clip(base + noise, 0.01, 0.99))


def _simulate_isolation_score(features: np.ndarray) -> float:
    """Simulate Isolation Forest anomaly score (higher = more anomalous)."""
    norm = np.linalg.norm(features)
    # Anomaly score mapped to [0,1]: higher norm = more anomalous
    score = 1 / (1 + np.exp(-0.2 * (norm - 4.0)))
    return float(np.clip(score + random.uniform(-0.05, 0.05), 0.0, 1.0))


async def run_inference(host_snapshot: Dict[str, Any] = None) -> Dict[str, Any]:
    """
    Run dual-model inference on a host snapshot.
    Returns fused threat score, individual model scores, and feature vector.
    Gracefully degrades if models are unavailable (rules.md §4).
    """
    _load_models()

    if host_snapshot is None:
        host_snapshot = await get_host_snapshot()
    # ---------------------------------------------------------------------
    # Synthetic anomaly override: allow callers to pass a dict containing
    # "isolation_forest_score" (>=0.70) to force the deception pipeline.
    # When present we bypass the normal model scoring path for Isolation Forest
    # and use the supplied value directly. This is useful for end‑to‑end tests
    # and unit‑style verification of the honeypot redirection.
    # ---------------------------------------------------------------------
    synthetic_if_score: Optional[float] = None
    synthetic_xgb_score: Optional[float] = None
    if isinstance(host_snapshot, dict):
        if "isolation_forest_score" in host_snapshot:
            try:
                synthetic_if_score = float(host_snapshot["isolation_forest_score"])
            except Exception as e:
                logger.warning(f"Invalid synthetic isolation_forest_score supplied: {e}")
        if "xgboost_score" in host_snapshot:
            try:
                synthetic_xgb_score = float(host_snapshot["xgboost_score"])
            except Exception as e:
                logger.warning(f"Invalid synthetic xgboost_score supplied: {e}")
    # ---------------------------------------------------------------------

    features = extract_features_from_host(host_snapshot)

    # --- XGBoost inference ---
    xgb_score: float
    if synthetic_xgb_score is not None:
        xgb_score = synthetic_xgb_score
    elif _xgb_session is not None:
        try:
            input_name = _xgb_session.get_inputs()[0].name
            raw_out = _xgb_session.run(None, {input_name: features})
            xgb_score = _positive_class_score(raw_out)
        except Exception as e:
            logger.warning(f"XGBoost ONNX inference error: {e}. Falling back to simulation.")
            xgb_score = _simulate_xgboost_score(features)
    else:
        xgb_score = _simulate_xgboost_score(features)

    # --- Isolation Forest inference ---
    if_score: float
    if synthetic_if_score is not None:
        if_score = synthetic_if_score
    elif _iforest_session is not None:
        try:
            input_name = _iforest_session.get_inputs()[0].name
            raw_if = _iforest_session.run(None, {input_name: features})
            # Convert decision score to [0,1] — lower decision score = more anomalous
            if_score = _anomaly_score(raw_if)
        except Exception as e:
            logger.warning(f"Isolation Forest ONNX inference error: {e}. Falling back to simulation.")
            if_score = _simulate_isolation_score(features)
    else:
        if_score = _simulate_isolation_score(features)

    # Fuse scores: weighted average (XGBoost 60%, IF 40%)
    fused_score = round(0.60 * xgb_score + 0.40 * if_score, 4)

    severity = (
        "critical" if fused_score > 0.88
        else "high" if fused_score > 0.70
        else "medium" if fused_score > 0.45
        else "low"
    )

    # Deception Hook: Trigger Honeypot trap on zero-day Isolation Forest anomaly (unclassified pattern)
    deception_capture = None
    if if_score >= 0.70:
        try:
            from app.deception.honeypot_emulator import honeypot_emulator
            deception_capture = honeypot_emulator.redirect_threat({
                "source_ip": "198.51.100.88",
                "port": 4444,
                "threat_type": "Zero-Day Anomaly Probe (Isolation Forest)",
                "raw_payload": "UNCLASSIFIED_ZERO_DAY_ANOMALY_VECTOR",
                "command_executed": "recon_probe_synthetic_route",
            })
        except Exception as e:
            logger.warning(f"Failed to redirect threat to honeypot: {e}")

    return {
        "threat_score": fused_score,
        "xgboost_score": round(xgb_score, 4),
        "isolation_forest_score": round(if_score, 4),
        "severity": severity,
        "feature_vector": features.flatten().tolist(),
        "feature_names": FEATURE_COLUMNS,
        "deception_capture": deception_capture,
        "inference_engine": "ONNX Runtime (CPU)" if (_xgb_session is not None or _iforest_session is not None) else "Simulated Fallback",
        "is_onnx_live": bool(_xgb_session is not None and _iforest_session is not None),
    }
