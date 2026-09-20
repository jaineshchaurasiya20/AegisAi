# Project Requirement Document (PRD)

## 1. Executive Summary & Vision
**Project Title:** AegisAI — Edge-Native Cyber Threat Detection & Autonomous Response Engine
**Vision:** Provide an affordable, lightweight, edge-native cybersecurity monitoring platform for SMBs and enterprise developers. AegisAI leverages hybrid Machine Learning models for zero-day threat detection, Explainable AI (XAI) to eliminate alert fatigue, and automated local containment scripts to minimize mean-time-to-respond (MTTR) without high cloud infrastructure costs.

---

## 2. Problem Statement
* **High Infrastructure Costs:** Existing enterprise SIEM/EDR platforms (e.g., Splunk, CrowdStrike) require expensive cloud ingestion and heavy processing fees.
* **Alert Fatigue:** Traditional rule-based or over-sensitive ML systems flood SOC (Security Operations Center) analysts with thousands of false positives daily.
* **Sophisticated Adversarial Attacks:** Modern malware and AI-generated phishing payloads easily evade signature-based antivirus solutions.

---

## 3. Target Audience & Users
1. **Small & Medium Businesses (SMBs):** Organizations requiring robust endpoint protection without enterprise-level cloud SOC budgets.
2. **DevOps & System Administrators:** Engineers needing real-time host-level process/network monitoring and automated script-based isolation.
3. **SOC Analysts / Security Engineers:** Analysts who require actionable insights (via XAI) rather than raw, uninterpreted alert logs.

---

## 4. Key Functional Requirements

### 4.1 Real-Time Host & Network Monitoring
* Continuous monitoring of CPU, RAM, open socket ports, and system process trees using `psutil`.
* Ingestion of raw network packet logs (CICIDS2017 schema compatible).

### 4.2 Edge-Native Hybrid Detection Engine
* **Supervised Classifier:** XGBoost model optimized via ONNX runtime for low-latency detection of known intrusion signatures.
* **Unsupervised Classifier:** Isolation Forest model for detecting zero-day anomalies and unexpected system behavior.

### 4.3 Explainable AI (XAI) & Threat Scoring
* Real-time calculation of feature attribution scores using SHAP (SHapley Additive exPlanations) / LIME.
* Visualization of top risk contributors (e.g., unusual outbound port, anomalous memory consumption spikes).

### 4.4 Automated Self-Healing & Containment
* Configurable rule engine for automated threat response.
* Automatic network interface isolation and malicious process termination upon exceeding critical risk thresholds.

### 4.5 Interactive Monitoring Dashboard
* Real-time threat telemetry dashboard built with React and Tailwind CSS.
* Live WebSocket feed of incoming network telemetry, risk trends, and system status.

---

## 5. Non-Functional Requirements
* **Latency:** Edge detection latency must remain under 50ms per batch inference.
* **Resource Footprint:** Agent RAM usage must stay below 150MB; CPU utilization must not exceed 5%.
* **Security:** All API communication secured via HTTPS / Secure WebSockets and JWT bearer tokens.
* **Reliability:** Local fallback logging if server connection is disrupted.
