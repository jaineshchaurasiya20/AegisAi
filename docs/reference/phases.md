# Project Implementation Phases

## Phase 1: Environment Setup & Core Engine Design
- [ ] Initialize Git repository and create directory structure (`client/`, `server/`, `docs/`).
- [ ] Set up FastAPI backend with SQLite/In-memory storage.
- [ ] Set up React frontend with Vite and Tailwind CSS.
- [ ] Implement synthetic/Kaggle dataset loaders (CICIDS2017 / NSL-KDD subset).

## Phase 2: ML Model Training & XAI Pipeline
- [ ] Train XGBoost model for supervised network intrusion detection.
- [ ] Train Isolation Forest model for unsupervised anomaly detection.
- [ ] Convert models to ONNX runtime format for optimized edge inference.
- [ ] Implement SHAP feature extraction pipeline for real-time model interpretability.

## Phase 3: Real-Time Host Collector & Automation
- [ ] Build `host_monitor.py` script using `psutil` to track system process IDs, CPU, RAM, and active socket connections.
- [ ] Integrate background inference loop linking telemetry collector to trained ML models.
- [ ] Build automated containment engine (`process_killer.py`) with safety kill-switch configurations.

## Phase 4: Frontend Dashboard & WebSocket Integration
- [ ] Design authentication / login view and modern layout (Sidebar, Topbar).
- [ ] Build Real-Time Monitoring Dashboard with dynamic threat counters and system health gauges.
- [ ] Implement WebSocket endpoint in FastAPI to broadcast live telemetry to React UI.
- [ ] Integrate XAI Modal component to visualize SHAP feature importance charts upon alert clicks.

## Phase 5: Testing, Optimization & Documentation
- [ ] Conduct performance benchmark tests (evaluate CPU/RAM impact of the agent).
- [ ] Perform end-to-end simulation of a malicious process execution and test automated isolation.
- [ ] Finalize documentation and update project memory logs.
