# Development Rules, Boundaries & Coding Guidelines

## 1. Technology Choices & Constraints
* **Mandatory Stack:** React (Vite) + Tailwind CSS for Frontend; Python (FastAPI) for Backend.
* **ML Model Packaging:** Export trained models to `.onnx` or compact `.joblib` files to ensure low memory footprints during local execution.
* **No Cloud Dependency for Inference:** All real-time threat evaluations must occur locally on the host machine/edge node.

---

## 2. Code Quality & Performance Standards
* **Asynchronous Processing:** Long-running monitoring loops and packet sniffing MUST run asynchronously (via `asyncio` or background threads) to avoid blocking FastAPI endpoints.
* **Resource Guardrails:** The monitoring collector must pause or drop sampling rate if host system memory exceeds 85% utilization.
* **Frontend Responsiveness:** All UI components must be fully responsive, accessible, and render smoothly without layout shifts during real-time data pushes.

---

## 3. Boundaries & Ethical Guardrails
* **No Destructive Actions Without Guardrails:** Automated containment (killing processes) must require explicit admin opt-in in `config.yaml`.
* **Privilege Elevation Warnings:** Ensure network interface manipulation scripts clearly notify the admin regarding necessary `sudo`/Administrator privileges.
* **Data Privacy:** Local telemetry logs must never be exported outside the deployment network unless cloud log aggregation is explicitly configured by the user.

---

## 4. Error Handling & Resilience
* **Graceful Degradation:** If the XAI SHAP explainer fails or times out, the backend must fall back to basic feature weights without crashing the inference pipeline.
* **WebSocket Auto-Reconnect:** The React frontend must implement exponential backoff reconnection logic for WebSocket drops.
* **Structured Logging:** Use Python `logging` with JSON formatting for backend operations.
