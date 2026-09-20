# System Architecture & Technical Specifications

## 1. System Architecture Overview

```
[ Local Endpoint / Host System ]
              │
              ├──> Host Telemetry Collector (psutil / Network Sniffer)
              │
              ▼
[ AegisAI Local Edge Agent (Python / FastAPI) ]
              │
              ├──> Preprocessing & Feature Extraction Engine
              │
              ├──> Hybrid ML Engine (ONNX Runtime: XGBoost + Isolation Forest)
              │
              ├──> Explainable AI Engine (SHAP / TreeExplainer)
              │
              └──> Local Action Trigger (Process Containment & Port Isolation)
              │
              ▼ (WebSocket / REST API)
[ AegisAI Web Dashboard (React + Tailwind CSS) ]
```

---

## 2. Technology Stack

### Frontend
* **Framework:** React.js (Vite)
* **Styling:** Tailwind CSS + Lucide Icons
* **State Management:** React Context API / Zustand
* **Charts & Data Visualization:** Recharts, Tremor / Chart.js
* **Real-time Communication:** Socket.io-client / Native WebSockets

### Backend & ML Core
* **Language:** Python 3.10+
* **Framework:** FastAPI (Asynchronous REST API + WebSockets)
* **ML Libraries:** XGBoost, Scikit-learn, ONNX Runtime, SHAP
* **System Telemetry:** `psutil`, `scapy`
* **Data Storage:** SQLite (Local logs & user configurations) / MongoDB (Telemetry logs)

---

## 3. Recommended Folder & File Structure

```
aegis-ai/
├── client/                      # React Frontend Application
│   ├── public/
│   ├── src/
│   │   ├── assets/
│   │   ├── components/          # Reusable UI Components
│   │   │   ├── Header.jsx
│   │   │   ├── Sidebar.jsx
│   │   │   ├── ThreatCard.jsx
│   │   │   ├── XAIExplanationModal.jsx
│   │   │   └── NetworkChart.jsx
│   │   ├── pages/               # Application Views
│   │   │   ├── Dashboard.jsx
│   │   │   ├── ThreatLogs.jsx
│   │   │   ├── Analytics.jsx
│   │   │   └── Settings.jsx
│   │   ├── services/            # API & WebSocket Clients
│   │   │   ├── api.js
│   │   │   └── websocket.js
│   │   ├── App.jsx
│   │   └── main.jsx
│   ├── package.json
│   └── tailwind.config.js
│
├── server/                      # Python FastAPI Backend & Detection Core
│   ├── app/
│   │   ├── api/
│   │   │   ├── routes/
│   │   │   │   ├── auth.py
│   │   │   │   ├── telemetry.py
│   │   │   │   └── threats.py
│   │   │   └── websockets.py
│   │   ├── core/
│   │   │   ├── config.py
│   │   │   └── security.py
│   │   ├── ml/
│   │   │   ├── models/           # Trained ONNX / Pickle models
│   │   │   │   ├── xgboost_intrusion.onnx
│   │   │   │   └── isolation_forest.pkl
│   │   │   ├── preprocessor.py
│   │   │   ├── inference.py
│   │   │   └── xai_explainer.py
│   │   ├── collector/           # System Monitoring Agents
│   │   │   ├── host_monitor.py
│   │   │   └── packet_sniffer.py
│   │   ├── responder/           # Automated Containment Scripts
│   │   │   └── process_killer.py
│   │   └── main.py
│   ├── requirements.txt
│   └── config.yaml
│
└── docs/                        # Project Documentation
    ├── project_requirement_document.md
    ├── Architecture.md
    ├── rules.md
    ├── phases.md
    ├── design.md
    └── memory.md
```
