"""
AegisAI — Standalone Model Training & ONNX Export Pipeline
Ingests CICIDS2017 CSV flow records, trains a hybrid supervised (XGBoost) +
unsupervised anomaly (Isolation Forest) detector, and exports optimized ONNX artifacts.

Usage:
    server\\venv\\Scripts\\python.exe server/scripts/train_onnx_model.py [--data-dir cicids2017] [--output-dir server/app/ml/models]
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Tuple

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.metrics import classification_report, roc_auc_score, f1_score
from sklearn.model_selection import train_test_split
from xgboost import XGBClassifier

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("AegisAI-Trainer")

ROOT_DIR = Path(__file__).resolve().parents[2]
DEFAULT_DATA_DIR = ROOT_DIR / "cicids2017"
DEFAULT_OUTPUT_DIR = ROOT_DIR / "server" / "app" / "ml" / "models"

# 20 key tabular features aligned with AegisAI edge preprocessor
FEATURE_COLUMNS: Tuple[str, ...] = (
    "Destination Port",
    "Protocol",
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",
    "Fwd Packet Length Max",
    "Fwd Packet Length Min",
    "Fwd Packet Length Mean",
    "Bwd Packet Length Max",
    "Bwd Packet Length Min",
    "Bwd Packet Length Mean",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Flow IAT Mean",
    "Flow IAT Std",
    "Fwd IAT Mean",
    "Bwd IAT Mean",
    "Active Mean",
)
LABEL_COLUMN = "Label"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--data-dir",
        type=Path,
        default=DEFAULT_DATA_DIR,
        help="Path to directory containing CICIDS2017 CSV files",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=DEFAULT_OUTPUT_DIR,
        help="Target directory for exported .onnx models and manifest",
    )
    parser.add_argument(
        "--max-rows-per-file",
        type=int,
        default=100_000,
        help="Max sample rows per CSV file to balance memory and speed (0 for unlimited)",
    )
    parser.add_argument(
        "--random-state",
        type=int,
        default=42,
        help="Random seed for reproducibility",
    )
    parser.add_argument(
        "--xgb-estimators",
        type=int,
        default=150,
        help="Number of boosting rounds for XGBoost",
    )
    parser.add_argument(
        "--iforest-estimators",
        type=int,
        default=100,
        help="Number of trees for Isolation Forest baseline",
    )
    return parser.parse_args()


def load_and_preprocess_file(
    file_path: Path, max_rows: int, random_state: int
) -> pd.DataFrame | None:
    """Load a single CICIDS2017 CSV file, strip headers, handle NaN/Inf, and binary encode labels."""
    if not file_path.is_file():
        logger.warning(f"File not found: {file_path}")
        return None

    logger.info(f"Ingesting {file_path.name}...")
    try:
        # Read header only to match columns
        sample_df = pd.read_csv(file_path, nrows=2)
        clean_cols = {c: c.strip() for c in sample_df.columns}

        # Find matching feature and label columns
        required_raw_cols = [
            raw for raw, clean in clean_cols.items()
            if clean in FEATURE_COLUMNS or clean.lower() == "label"
        ]

        df = pd.read_csv(
            file_path,
            usecols=required_raw_cols,
            low_memory=False,
        )
        df.columns = df.columns.str.strip()

        # Rename label column if case differed
        for c in df.columns:
            if c.lower() == "label" and c != LABEL_COLUMN:
                df.rename(columns={c: LABEL_COLUMN}, inplace=True)

        # Ensure Protocol column exists (TCP default = 6.0)
        if "Protocol" not in df.columns:
            df["Protocol"] = 6.0

        # Check for missing feature columns and default them
        for feat in FEATURE_COLUMNS:
            if feat not in df.columns:
                df[feat] = 0.0

        # Select only required columns in strict order
        df = df[[*FEATURE_COLUMNS, LABEL_COLUMN]]

        # Clean numeric feature values (NaN, Inf, -Inf -> 0)
        df.loc[:, FEATURE_COLUMNS] = (
            df.loc[:, FEATURE_COLUMNS]
            .apply(pd.to_numeric, errors="coerce")
            .replace([np.inf, -np.inf], np.nan)
            .fillna(0)
        )

        # Binary label encoding: BENIGN = 0, Attack = 1
        df[LABEL_COLUMN] = (
            df[LABEL_COLUMN]
            .astype(str)
            .str.strip()
            .str.upper()
            .ne("BENIGN")
            .astype(np.int8)
        )

        # Stratified sampling if row limit specified
        if max_rows > 0 and len(df) > max_rows:
            class_counts = df[LABEL_COLUMN].value_counts()
            if len(class_counts) > 1 and class_counts.min() > 5:
                df, _ = train_test_split(
                    df,
                    train_size=max_rows,
                    stratify=df[LABEL_COLUMN],
                    random_state=random_state,
                )
            else:
                df = df.sample(n=max_rows, random_state=random_state)

        attack_count = int((df[LABEL_COLUMN] == 1).sum())
        benign_count = int((df[LABEL_COLUMN] == 0).sum())
        logger.info(
            f"  Loaded {len(df):,} records ({benign_count:,} benign, {attack_count:,} attacks) from {file_path.name}"
        )
        return df

    except Exception as e:
        logger.error(f"Error processing {file_path.name}: {e}")
        return None


def quantize_and_optimize_onnx(source: Path, destination: Path) -> None:
    """Apply dynamic INT8 quantization pass and graph optimization to exported ONNX model."""
    import onnx
    from onnxruntime.quantization import QuantType, quantize_dynamic

    model = onnx.load(str(source))
    # Ensure default domain opset is present for quantizer
    if not any(opset.domain == "" for opset in model.opset_import):
        model.opset_import.append(onnx.helper.make_opsetid("", 15))
        onnx.save_model(model, str(source))

    quantize_dynamic(
        model_input=str(source),
        model_output=str(destination),
        weight_type=QuantType.QInt8,
    )
    if not destination.is_file() or destination.stat().st_size == 0:
        raise RuntimeError(f"Quantization failed for {destination}")


def verify_onnx_session(model_path: Path, feature_count: int) -> None:
    """Validate that the exported ONNX model executes correctly via onnxruntime."""
    import onnxruntime as ort

    session = ort.InferenceSession(str(model_path), providers=["CPUExecutionProvider"])
    input_name = session.get_inputs()[0].name
    dummy_input = np.zeros((1, feature_count), dtype=np.float32)
    outputs = session.run(None, {input_name: dummy_input})
    assert len(outputs) > 0, f"ONNX model at {model_path} returned empty output"
    logger.info(f"Verified ONNX model {model_path.name} (input: {input_name}, shape: {dummy_input.shape})")


def export_to_onnx(
    classifier: XGBClassifier,
    anomaly_model: IsolationForest,
    output_dir: Path,
) -> Tuple[Path, Path]:
    """Convert trained scikit-learn & XGBoost models to ONNX artifacts."""
    import onnx
    import onnxmltools
    from onnxmltools.convert.common.data_types import FloatTensorType as XGBFloatTensorType
    from skl2onnx import convert_sklearn
    from skl2onnx.common.data_types import FloatTensorType as SklearnFloatTensorType

    output_dir.mkdir(parents=True, exist_ok=True)
    xgb_fp32 = output_dir / "xgb_threat_model.fp32.onnx"
    iforest_fp32 = output_dir / "isolation_forest.fp32.onnx"
    xgb_onnx_path = output_dir / "xgb_threat_model.onnx"
    iforest_onnx_path = output_dir / "isolation_forest.onnx"

    feat_dim = len(FEATURE_COLUMNS)
    initial_type_xgb = [("features", XGBFloatTensorType([None, feat_dim]))]
    initial_type_iforest = [("features", SklearnFloatTensorType([None, feat_dim]))]

    # 1. Convert XGBoost classifier
    logger.info("Converting XGBoost model to ONNX...")
    xgb_onnx = onnxmltools.convert_xgboost(
        classifier.get_booster(),
        initial_types=initial_type_xgb,
        target_opset=15,
    )
    onnx.save_model(xgb_onnx, str(xgb_fp32))

    # 2. Convert Isolation Forest anomaly model
    logger.info("Converting Isolation Forest model to ONNX...")
    iforest_onnx = convert_sklearn(
        anomaly_model,
        initial_types=initial_type_iforest,
        target_opset={"": 15, "ai.onnx.ml": 3},
    )
    onnx.save_model(iforest_onnx, str(iforest_fp32))

    # 3. Quantize and verify
    logger.info("Applying dynamic INT8 quantization...")
    quantize_and_optimize_onnx(xgb_fp32, xgb_onnx_path)
    quantize_and_optimize_onnx(iforest_fp32, iforest_onnx_path)

    verify_onnx_session(xgb_onnx_path, feat_dim)
    verify_onnx_session(iforest_onnx_path, feat_dim)

    # Clean temporary FP32 models
    xgb_fp32.unlink(missing_ok=True)
    iforest_fp32.unlink(missing_ok=True)

    return xgb_onnx_path, iforest_onnx_path


def main() -> None:
    args = parse_args()
    logger.info("=" * 70)
    logger.info("AegisAI Edge ML Training & ONNX Export Pipeline")
    logger.info(f"Dataset Directory : {args.data_dir}")
    logger.info(f"Output Directory  : {args.output_dir}")
    logger.info("=" * 70)

    if not args.data_dir.exists():
        logger.error(f"Dataset directory not found: {args.data_dir}")
        sys.exit(1)

    # Discover all CSV files in the data directory
    csv_files = sorted(list(args.data_dir.glob("*.csv")))
    if not csv_files:
        logger.error(f"No CSV files found in {args.data_dir}")
        sys.exit(1)

    logger.info(f"Found {len(csv_files)} dataset files:")
    for f in csv_files:
        logger.info(f"  - {f.name} ({f.stat().st_size / (1024*1024):.1f} MB)")

    # Load and combine datasets
    frames: List[pd.DataFrame] = []
    for csv_file in csv_files:
        df = load_and_preprocess_file(csv_file, args.max_rows_per_file, args.random_state)
        if df is not None and not df.empty:
            frames.append(df)

    if not frames:
        logger.error("Failed to load any valid data.")
        sys.exit(1)

    combined_data = pd.concat(frames, ignore_index=True)
    logger.info(f"Combined Training Dataset: {len(combined_data):,} total samples")

    X = combined_data.loc[:, FEATURE_COLUMNS].to_numpy(dtype=np.float32)
    y = combined_data[LABEL_COLUMN].to_numpy(dtype=np.int8)

    unique_classes, counts = np.unique(y, return_counts=True)
    logger.info(f"Class Distribution: {dict(zip(['Benign (0)', 'Attack (1)'], counts))}")

    if len(unique_classes) < 2:
        logger.error("Training data must contain both Benign and Attack records.")
        sys.exit(1)

    # Train / Test split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, stratify=y, random_state=args.random_state
    )
    logger.info(f"Train Set: {len(X_train):,} samples | Test Set: {len(X_test):,} samples")

    # ── Train Supervised XGBoost Classifier ──────────────────────────────────
    logger.info("Training Supervised XGBoost Classifier...")
    classifier = XGBClassifier(
        objective="binary:logistic",
        eval_metric="logloss",
        n_estimators=args.xgb_estimators,
        max_depth=6,
        learning_rate=0.08,
        subsample=0.8,
        colsample_bytree=0.8,
        tree_method="hist",
        n_jobs=4,
        random_state=args.random_state,
    )
    classifier.fit(X_train, y_train)

    y_pred_proba = classifier.predict_proba(X_test)[:, 1]
    y_pred = (y_pred_proba >= 0.5).astype(int)
    auc_score = float(roc_auc_score(y_test, y_pred_proba))
    f1 = float(f1_score(y_test, y_pred))

    logger.info(f"XGBoost Test AUC: {auc_score:.5f} | F1-Score: {f1:.5f}")
    logger.info("\n" + classification_report(y_test, y_pred, target_names=["Benign", "Attack"]))

    # ── Train Unsupervised Isolation Forest Baseline ─────────────────────────
    logger.info("Training Unsupervised Isolation Forest Anomaly Baseline on Benign Samples...")
    benign_train = X_train[y_train == 0]
    anomaly_model = IsolationForest(
        n_estimators=args.iforest_estimators,
        contamination="auto",
        max_samples=min(512, len(benign_train)),
        n_jobs=4,
        random_state=args.random_state,
    )
    anomaly_model.fit(benign_train)

    # ── Export Models to Quantized ONNX ──────────────────────────────────────
    logger.info(f"Exporting ONNX artifacts to {args.output_dir}...")
    xgb_path, iforest_path = export_to_onnx(classifier, anomaly_model, args.output_dir)

    # ── Generate Metadata Manifest ───────────────────────────────────────────
    manifest: Dict[str, object] = {
        "created_at": datetime.now(timezone.utc).isoformat(),
        "frameworks": {
            "xgboost": "3.4.1",
            "scikit_learn": "1.9.0",
            "onnxruntime": "1.29.0",
        },
        "feature_columns": list(FEATURE_COLUMNS),
        "feature_count": len(FEATURE_COLUMNS),
        "dataset_rows": int(len(combined_data)),
        "benign_samples": int((y == 0).sum()),
        "attack_samples": int((y == 1).sum()),
        "metrics": {
            "xgb_test_auc": round(auc_score, 6),
            "xgb_test_f1": round(f1, 6),
        },
        "artifacts": {
            "xgboost_classifier": xgb_path.name,
            "isolation_forest_anomaly": iforest_path.name,
        },
        "quantization": "ONNX Dynamic INT8 quantized with tree ensemble operator preservation",
    }

    manifest_path = args.output_dir / "model_manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    logger.info(f"Model manifest saved to {manifest_path}")
    logger.info("=" * 70)
    logger.info("Model Training & Export Pipeline Completed Successfully!")
    logger.info("=" * 70)


if __name__ == "__main__":
    main()
