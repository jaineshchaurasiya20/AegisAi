"""Full live test suite for AegisAI — all 6 subsystems"""
import json
import sys
from pathlib import Path
import httpx

BASE = "http://127.0.0.1:8000"
PASS = "[PASS]"
FAIL = "[FAIL]"

results = {}

# ── TEST 1: Auth ──────────────────────────────────────────────────────────────
print("=" * 60)
print("TEST 1: Authentication")
with httpx.Client(base_url=BASE, timeout=10.0) as client:
    r = client.post("/api/auth/login", data={"username": "admin", "password": "aegis2024"})
    token = r.json().get("access_token")
    ok = r.status_code == 200 and bool(token)
    print(f"  {PASS if ok else FAIL}  HTTP {r.status_code}  Token obtained: {bool(token)}")
    results["auth"] = ok
    H = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

    # ── TEST 2: Threat Logs ───────────────────────────────────────────────────
    print()
    print("TEST 2: Threat Logs")
    r = client.get("/api/threats/", headers=H)
    threats = r.json() if r.status_code == 200 else []
    ok = r.status_code == 200 and len(threats) > 0
    print(f"  {PASS if ok else FAIL}  HTTP {r.status_code}  Threats loaded: {len(threats)}")
    if threats:
        t = threats[0]
        print(f"  Sample -> id={t['id'][:8]}...  severity={t['severity']}  score={t['threat_score']}")
        tid = t["id"]
    else:
        tid = "test-fallback-id"
    results["threats"] = ok

    # ── TEST 3: XAI Explanation ───────────────────────────────────────────────
    print()
    print("TEST 3: On-Demand XAI Explanation")
    if tid != "test-fallback-id":
        r = client.get(f"/api/threats/{tid}/explain", headers=H)
        ok = r.status_code == 200
        print(f"  {PASS if ok else FAIL}  HTTP {r.status_code}")
        if ok:
            xai = r.json()
            print(f"  Features: {len(xai['feature_attributions'])}  Cached: {xai['cached']}  Time: {xai['execution_time_ms']}ms")
    else:
        ok = False
        print("  [SKIP] No real threat ID available")
    results["xai"] = ok

    # ── TEST 4: Deception / Honeypot ──────────────────────────────────────────
    print()
    print("TEST 4: Deception / Honeypot Engine")
    r_stats = client.get("/api/deception/stats", headers=H)
    r_sim = client.post(
        "/api/deception/simulate",
        headers=H,
        json={"trapType": "FAKE_FTP", "sourceIp": "10.99.0.1"},
    )
    ok = r_stats.status_code == 200 and r_sim.status_code == 200
    print(f"  Stats  {PASS if r_stats.status_code == 200 else FAIL}  HTTP {r_stats.status_code}")
    print(f"  Simulate  {PASS if r_sim.status_code == 200 else FAIL}  HTTP {r_sim.status_code}")
    if r_sim.status_code == 200:
        cap = r_sim.json()
        print(f"  Capture: trapType={cap['trapType']}  decoy={cap['decoyTarget']}  status={cap['isolationStatus']}")
    results["deception"] = ok

    # ── TEST 5: Agentic Remediation SSE Stream ────────────────────────────────
    print()
    print("TEST 5: Agentic Remediation SSE Stream")
    steps_seen = []
    patch_path = None
    try:
        stream_headers = {**H, "Accept": "text/event-stream"}
        with client.stream(
            "POST",
            "/api/agent/remediate",
            headers=stream_headers,
            json={"threat_id": tid, "mode": "AUTONOMOUS"},
            timeout=30.0,
        ) as resp:
            print(f"  HTTP {resp.status_code}")
            if resp.status_code == 200:
                for line in resp.iter_lines():
                    if not line:
                        continue
                    if line.startswith("data:"):
                        d = json.loads(line[5:].strip())
                        step = d.get("step", "?")
                        status = d.get("status", "INFO")
                        msg = d.get("message", "")
                        steps_seen.append(step)
                        icon = {"INFO": ">>", "COMPLETED": "[OK]", "ERROR": "[ERR]", "DONE": "[END]"}.get(status, ">>")
                        print(f"    {icon} [{step}]  {msg}")
                        if d.get("generated_patch"):
                            patch_path = d.get("generated_patch")
                        if step in ("Summary", "END"):
                            break
            ok = len(steps_seen) >= 4
            print(f"  Steps: {steps_seen}")
    except Exception as e:
        ok = False
        print(f"  [ERR] {e}")
    results["agent_sse"] = ok

    # ── TEST 6: ONNX Live Model Inference ─────────────────────────────────────
    print()
    print("TEST 6: ONNX Live Model Telemetry & Inference")
    r_model = client.get("/api/model/telemetry", headers=H)
    r_scan = client.post("/api/threats/scan", headers=H)
    ok = r_model.status_code == 200 and r_scan.status_code == 200
    print(f"  Telemetry {PASS if r_model.status_code == 200 else FAIL}  HTTP {r_model.status_code}")
    print(f"  Scan      {PASS if r_scan.status_code == 200 else FAIL}  HTTP {r_scan.status_code}")
    if r_model.status_code == 200:
        mdata = r_model.json()
        print(f"  Architecture: {mdata.get('dualModelArchitecture')}")
        print(f"  Quantization: {mdata.get('quantizationFormat')}")
        print(f"  AUC: {mdata.get('validationAuc')} | F1: {mdata.get('validationF1')}")
    results["onnx_inference"] = ok

print()
print("=" * 60)
print("FINAL TEST RESULTS:")
for name, passed in results.items():
    print(f"  {PASS if passed else FAIL} {name}")

all_pass = all(results.values())
print(f"OVERALL STATUS: {'ALL TESTS PASSED' if all_pass else 'SOME TESTS FAILED'}")
sys.exit(0 if all_pass else 1)
