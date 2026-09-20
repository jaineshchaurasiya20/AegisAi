"""
AegisAI ML Preprocessor — CICIDS2017 schema compatible feature extraction.
Maps raw host telemetry into the 20 CICIDS2017 features expected by the ONNX models.
"""
import numpy as np
from typing import Dict, Any, List

# Feature columns expected by the model (CICIDS2017 subset — 20 key features)
FEATURE_COLUMNS: List[str] = [
    "dst_port", "protocol", "flow_duration", "tot_fwd_pkts", "tot_bwd_pkts",
    "totlen_fwd_pkts", "totlen_bwd_pkts", "fwd_pkt_len_max", "fwd_pkt_len_min",
    "fwd_pkt_len_mean", "bwd_pkt_len_max", "bwd_pkt_len_min", "bwd_pkt_len_mean",
    "flow_byts_per_s", "flow_pkts_per_s", "flow_iat_mean", "flow_iat_std",
    "fwd_iat_mean", "bwd_iat_mean", "active_mean",
]

# Pre-computed normalization stats (mean/std from CICIDS2017 training set approximation)
FEATURE_STATS: Dict[str, Dict[str, float]] = {
    "dst_port":          {"mean": 1024.0, "std": 16384.0},
    "protocol":          {"mean": 6.0,    "std": 2.5},
    "flow_duration":     {"mean": 5e6,    "std": 2e7},
    "tot_fwd_pkts":      {"mean": 12.0,   "std": 50.0},
    "tot_bwd_pkts":      {"mean": 8.0,    "std": 30.0},
    "totlen_fwd_pkts":   {"mean": 1500.0, "std": 8000.0},
    "totlen_bwd_pkts":   {"mean": 800.0,  "std": 4000.0},
    "fwd_pkt_len_max":   {"mean": 500.0,  "std": 600.0},
    "fwd_pkt_len_min":   {"mean": 20.0,   "std": 40.0},
    "fwd_pkt_len_mean":  {"mean": 120.0,  "std": 200.0},
    "bwd_pkt_len_max":   {"mean": 300.0,  "std": 500.0},
    "bwd_pkt_len_min":   {"mean": 20.0,   "std": 40.0},
    "bwd_pkt_len_mean":  {"mean": 100.0,  "std": 180.0},
    "flow_byts_per_s":   {"mean": 50000.0,"std": 200000.0},
    "flow_pkts_per_s":   {"mean": 200.0,  "std": 800.0},
    "flow_iat_mean":     {"mean": 5e5,    "std": 2e6},
    "flow_iat_std":      {"mean": 1e6,    "std": 5e6},
    "fwd_iat_mean":      {"mean": 8e5,    "std": 3e6},
    "bwd_iat_mean":      {"mean": 7e5,    "std": 2.5e6},
    "active_mean":       {"mean": 3e5,    "std": 1e6},
}


def extract_features_from_host(host_snapshot: Dict[str, Any]) -> np.ndarray:
    """
    Map psutil host snapshot fields to CICIDS2017-compatible feature vector.
    Missing values are imputed with the feature mean.
    """
    raw: Dict[str, float] = {col: FEATURE_STATS[col]["mean"] for col in FEATURE_COLUMNS}

    # Map available host fields to feature names
    raw["protocol"] = 6.0  # TCP default
    raw["flow_duration"] = host_snapshot.get("cpu_percent", 5.0) * 1e5
    raw["flow_byts_per_s"] = host_snapshot.get("bytes_sent_per_s", 0.0)
    raw["flow_pkts_per_s"] = host_snapshot.get("packets_sent_per_s", 0.0)
    raw["active_mean"] = host_snapshot.get("memory_percent", 30.0) * 1e4
    raw["tot_fwd_pkts"] = host_snapshot.get("connections", 10)

    # The training script consumes raw CICIDS2017 feature values, so runtime must
    # preserve that scale instead of applying a second, incompatible normalization.
    feature_vec = np.array([raw[col] for col in FEATURE_COLUMNS], dtype=np.float32)

    return feature_vec.reshape(1, -1)
