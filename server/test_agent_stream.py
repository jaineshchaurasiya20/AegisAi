"""
AegisAI - Agentic Incident Response Engine: End-to-End SSE Stream Test
Tests the /api/agent/remediate SSE endpoint without UI.
"""
import json
import sys
import requests

API_BASE  = "http://127.0.0.1:8000"
LOGIN_URL = f"{API_BASE}/api/auth/login"
AGENT_URL = f"{API_BASE}/api/agent/remediate"

# -- 1. Authenticate ---------------------------------------------------------
print("[*] Authenticating...")
try:
    auth_resp = requests.post(
        LOGIN_URL,
        data={"username": "admin", "password": "aegis2024"},
        timeout=5,
    )
    token = auth_resp.json().get("access_token")
    if not token:
        print("[FAIL] Auth failed: " + auth_resp.text)
        sys.exit(1)
    print("[OK]  Token obtained.\n")
except Exception as e:
    print("[FAIL] Auth error: " + str(e))
    sys.exit(1)

# -- 2. Stream agent SSE -----------------------------------------------------
THREAT_ID = "thr_test_agent_99"
payload = {"threat_id": THREAT_ID, "mode": "AUTONOMOUS"}
headers = {
    "Authorization": "Bearer " + token,
    "Content-Type": "application/json",
    "Accept": "text/event-stream",
}

print("[>>] Sending POST to " + AGENT_URL)
print("     Payload: " + json.dumps(payload) + "\n" + "=" * 60)

try:
    response = requests.post(AGENT_URL, json=payload, headers=headers, stream=True, timeout=30)

    if response.status_code != 200:
        print("[FAIL] HTTP " + str(response.status_code) + ": " + response.text)
        sys.exit(1)

    print("[OK]  SSE Connection Established - Streaming Agent Reasoning Steps:\n")
    steps_seen = []
    icons = {"INFO": ">>", "COMPLETED": "[DONE]", "ERROR": "[ERR]", "FAILED": "[ERR]", "DONE": "[END]"}

    for raw_line in response.iter_lines():
        if not raw_line:
            continue
        line = raw_line.decode("utf-8") if isinstance(raw_line, bytes) else raw_line
        if line.startswith("data:"):
            raw_json = line[5:].strip()
            try:
                data = json.loads(raw_json)
                step    = data.get("step", "AGENT")
                status  = data.get("status", "INFO")
                message = data.get("message", "")
                steps_seen.append(step)
                icon = icons.get(status, ">>")
                print("  " + icon + " [" + step + "]  " + message + "  (status=" + status + ")")
                if step in ("Summary", "END"):
                    break
            except json.JSONDecodeError:
                print("  (raw) " + line)

    print("\n" + "=" * 60)
    print("[OK]  Stream complete. Steps received: " + str(steps_seen))

except Exception as e:
    print("[FAIL] Stream error: " + str(e))
    sys.exit(1)

# -- 3. Check patch files ----------------------------------------------------
import pathlib

patches_dir = pathlib.Path(__file__).parent / "app" / "agents" / "patches"
print("\n[DIR] Checking patches directory: " + str(patches_dir))
files = [f for f in patches_dir.iterdir() if f.is_file() and f.name != ".gitkeep"]
if files:
    print("[OK]  " + str(len(files)) + " patch file(s) found:")
    for f in sorted(files):
        print("      - " + f.name + "  (" + str(f.stat().st_size) + " bytes)")
    first = sorted(files)[0]
    print("\n[DOC] Contents of " + first.name + ":")
    print("-" * 40)
    print(first.read_text(encoding="utf-8"))
else:
    print("[WARN] No patch files yet (heuristics require port 4444 or ssh/ftp processes to generate patches).")
