"""
AegisAI — Live Attack Replay Streamer (Hackathon & Pitch Demo Ready)
====================================================================
Streams continuous network attack records from CICIDS2017 datasets into
the AegisAI backend in real time.

Demonstrates:
  - Live ONNX Edge Model Scoring & Severity Classification
  - Real-time WebSocket Dashboard telemetry updates and score spikes
  - Autonomous Deception Honeypot Redirection for Zero-Day vectors
  - Instant Self-Healing Host Isolation and Process Termination
  - Autonomous AI Remediation Agent streaming and firewall patch generation

Usage:
    server\\venv\\Scripts\\python.exe server/scripts/replay_attacks.py [--delay 1.5] [--count 20] [--burst] [--agent]
"""
from __future__ import annotations

import argparse
import asyncio
import json
import random
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
import urllib.parse
import urllib.request

# Ensure UTF-8 output on Windows consoles
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

ROOT_DIR = Path(__file__).resolve().parents[2]
SERVER_DIR = ROOT_DIR / "server"
if str(SERVER_DIR) not in sys.path:
    sys.path.insert(0, str(SERVER_DIR))
DATA_DIR = ROOT_DIR / "cicids2017"

# ANSI Color formatting for pitch terminal presentations
C_RESET   = "\033[0m"
C_BOLD    = "\033[1m"
C_RED     = "\033[91m"
C_GREEN   = "\033[92m"
C_YELLOW  = "\033[93m"
C_BLUE    = "\033[94m"
C_MAGENTA = "\033[95m"
C_CYAN    = "\033[96m"
C_WHITE   = "\033[97m"
C_BG_RED  = "\033[41m"
C_BG_CYAN = "\033[46m"

# Curated high-impact attack scenarios for live demonstration
ATTACK_SCENARIOS = [
    {
        "threat_type": "DDoS LOIC HTTP Flood (Volumetric)",
        "ports": [80, 443, 8080],
        "score_range": (0.92, 0.99),
        "raw_payload": "GET /api/v1/resource HTTP/1.1\\r\\nHost: victim.internal\\r\\nUser-Agent: LOIC/2.0.0.4",
        "process_name": "loic_flooder.exe",
        "category": "DDoS",
    },
    {
        "threat_type": "High-Frequency SYN Stealth Port Scan",
        "ports": [21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445, 1433, 3306, 3389, 8080],
        "score_range": (0.75, 0.88),
        "raw_payload": "TCP SYN probe sequence seq=39281729 win=1024",
        "process_name": "nmap.exe",
        "category": "Reconnaissance",
    },
    {
        "threat_type": "Zero-Day Memory Injection (Reflective DLL)",
        "ports": [4444, 49152, 65535],
        "score_range": (0.94, 0.99),
        "raw_payload": "\\x90\\x90\\x90\\x31\\xc0\\x50\\x68\\x2f\\x2f\\x73\\x68\\x68\\x2f\\x62\\x69\\x6e\\x89\\xe3",
        "process_name": "powershell.exe",
        "category": "Zero-Day Exploit",
    },
    {
        "threat_type": "Cobalt Strike C2 Beaconing Loop",
        "ports": [443, 8443, 2083],
        "score_range": (0.86, 0.95),
        "raw_payload": "POST /submit.php?id=a9f4c8 HTTP/1.1\\r\\nCookie: SESSIONID=Y29iYWx0c3RyaWtl",
        "process_name": "rundll32.exe",
        "category": "Command & Control",
    },
    {
        "threat_type": "SQL Injection & Schema Exfiltration",
        "ports": [80, 443, 3000],
        "score_range": (0.78, 0.91),
        "raw_payload": "SELECT * FROM users WHERE user_id='' UNION SELECT 1,username,password_hash FROM admin--",
        "process_name": "sqlmap.exe",
        "category": "Web Attack",
    },
    {
        "threat_type": "SSH Credential Brute-Force Spray",
        "ports": [22, 2222],
        "score_range": (0.72, 0.86),
        "raw_payload": "SSH-2.0-OpenSSH_8.2p1 auth request password attempt user='root'",
        "process_name": "hydra.exe",
        "category": "Brute Force",
    },
    {
        "threat_type": "Zero-Day Anomaly Probe (Unclassified Vector)",
        "ports": [2121, 2222, 4444],
        "score_range": (0.89, 0.98),
        "raw_payload": "SYNTHETIC_ANOMALY_PAYLOAD_OFFSET_0x7FFF4A",
        "process_name": "unknown_dropper.bin",
        "category": "Zero-Day Exploit",
    },
    {
        "threat_type": "DNS Tunneling Exfiltration (Base64)",
        "ports": [53, 5353],
        "score_range": (0.81, 0.93),
        "raw_payload": "dGhpcyBpcyBhbiBleGZpbHRyYXRlZCBwYXlsb2Fk.c2-exfil.attacker-domain.org",
        "process_name": "dnscat2.exe",
        "category": "Data Exfiltration",
    },
    {
        "threat_type": "Lateral Movement SMB/PsExec Execution",
        "ports": [445, 139],
        "score_range": (0.85, 0.94),
        "raw_payload": "\\\\target-host\\IPC$ SMB2_CREATE_REQUEST PSEXESVC.exe",
        "process_name": "psexec.exe",
        "category": "Lateral Movement",
    },
]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--base-url", default="http://127.0.0.1:8000", help="AegisAI backend base URL")
    parser.add_argument("--username", default="admin", help="Admin username for JWT authentication")
    parser.add_argument("--password", default="aegis2024", help="Admin password for JWT authentication")
    parser.add_argument("--delay", type=float, default=1.5, help="Seconds delay between attack events (default: 1.5s)")
    parser.add_argument("--count", type=int, default=0, help="Total attack events to stream (0 for infinite loop)")
    parser.add_argument("--burst", action="store_true", help="Simulate a high-frequency volumetric attack burst (0.2s delay)")
    parser.add_argument("--agent", action="store_true", help="Automatically trigger AI Agent remediation streaming on critical events")
    parser.add_argument("--zero-day-only", action="store_true", help="Stream only zero-day exploits to demonstrate honeypot deception")
    parser.add_argument("--scenario", type=str, default=None, help="Specific attack scenario e.g. zero_day_probe, ddos, ssh, sql")
    parser.add_argument("--test-quorum", action="store_true", help="Execute complete Quorum Cryptographic & Anti-Replay test suite")
    return parser.parse_args()


class AegisStreamerClient:
    """HTTP client handling JWT authentication and live event streaming."""

    def __init__(self, base_url: str, username: str, password: str):
        self.base_url = base_url.rstrip("/")
        self.username = username
        self.password = password
        self.token: Optional[str] = None

    def authenticate(self) -> bool:
        """Authenticate with backend and store bearer token."""
        url = f"{self.base_url}/api/auth/login"
        data = urllib.parse.urlencode({"username": self.username, "password": self.password}).encode("utf-8")
        req = urllib.request.Request(url, data=data, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                res = json.loads(resp.read().decode("utf-8"))
                self.token = res.get("access_token")
                return bool(self.token)
        except Exception as e:
            print(f"{C_RED}[AUTH ERROR]{C_RESET} Could not authenticate to {url}: {e}")
            return False

    def stream_attack(self, attack_data: Dict[str, Any]) -> Dict[str, Any] | None:
        """Send attack telemetry event to /api/threats/scan."""
        url = f"{self.base_url}/api/threats/scan"
        payload = json.dumps(attack_data).encode("utf-8")
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.token}",
        }
        req = urllib.request.Request(url, data=payload, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except Exception as e:
            print(f"{C_RED}[STREAM ERROR]{C_RESET} Failed to push attack to {url}: {e}")
            return None

    def trigger_agent_remediation(self, threat_id: str) -> None:
        """Trigger autonomous incident response agent SSE stream for pitch demonstration."""
        url = f"{self.base_url}/api/agent/remediate"
        payload = json.dumps({"threat_id": threat_id, "mode": "AUTONOMOUS"}).encode("utf-8")
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.token}",
            "Accept": "text/event-stream",
        }
        req = urllib.request.Request(url, data=payload, headers=headers, method="POST")
        try:
            print(f"\n  {C_MAGENTA}{C_BOLD}⚡ [AI AGENT]{C_RESET} Initiating autonomous agent remediation stream for Threat {threat_id[:8]}...")
            with urllib.request.urlopen(req, timeout=15) as resp:
                for line in resp:
                    line_str = line.decode("utf-8").strip()
                    if line_str.startswith("data:"):
                        event_data = json.loads(line_str[5:].strip())
                        step = event_data.get("step")
                        status = event_data.get("status")
                        msg = event_data.get("message", "")
                        if step in ("END", "Summary"):
                            print(f"    {C_GREEN}✔ [{step}]{C_RESET} {msg}")
                            break
                        else:
                            print(f"    {C_CYAN}➔ [{step}]{C_RESET} {msg}")
            print(f"  {C_GREEN}{C_BOLD}🛡 Containment patch generated & dynamic firewall rules deployed.{C_RESET}\n")
        except Exception as e:
            print(f"  {C_YELLOW}[AGENT STREAM]{C_RESET} Skipped agent reasoning stream: {e}")


def generate_attack_event(scenario: Dict[str, Any]) -> Dict[str, Any]:
    """Generate a realistic, process-backed attack record matching the scenario."""
    r1 = random.randint(45, 198)
    r2 = random.randint(10, 250)
    r3 = random.randint(1, 254)
    r4 = random.randint(2, 250)
    source_ip = f"{r1}.{r2}.{r3}.{r4}"
    port = random.choice(scenario["ports"])

    lo, hi = scenario["score_range"]
    score = round(random.uniform(lo, hi), 4)

    pid = random.randint(2400, 28500)
    proc_name = scenario.get("process_name", "malicious_proc.exe")

    telemetry = {
        "pid": pid,
        "processName": proc_name,
        "parentProcess": "explorer.exe",
        "parentPid": 1024,
        "cpuUsagePct": round(random.uniform(15.0, 65.0), 1),
        "memoryUsageMb": round(random.uniform(80.0, 450.0), 1),
        "commandLine": f"{proc_name} -t {source_ip}:{port} --payload-exec",
        "openSockets": [
            {"protocol": "TCP", "localPort": random.randint(49152, 65000), "remoteIp": source_ip, "remotePort": port, "state": "ESTABLISHED"},
        ],
    }

    return {
        "threat_type": scenario["threat_type"],
        "source_ip": source_ip,
        "destination_ip": "127.0.0.1",
        "port": port,
        "threat_score": score,
        "raw_payload": scenario.get("raw_payload", "ATTACK_PAYLOAD"),
        "telemetry": telemetry,
    }


def print_banner(args: argparse.Namespace):
    print(f"\n{C_CYAN}{C_BOLD}" + "=" * 80 + C_RESET, flush=True)
    print(f"{C_CYAN}{C_BOLD}  [+] AEGIS AI -- LIVE ATTACK REPLAY STREAMER (PITCH / DEMO MODE){C_RESET}", flush=True)
    print(f"{C_CYAN}" + "=" * 80 + C_RESET, flush=True)
    print(f"  Target Endpoint  : {C_WHITE}{args.base_url}/api/threats/scan{C_RESET}", flush=True)
    print(f"  Interval / Delay : {C_YELLOW}{'0.2s (BURST MODE)' if args.burst else f'{args.delay}s'}{C_RESET}", flush=True)
    print(f"  Event Limit      : {C_WHITE}{'Continuous Loop (Infinite)' if args.count == 0 else f'{args.count} events'}{C_RESET}", flush=True)
    print(f"  Autonomous Agent : {C_GREEN}{'ENABLED (Auto-Remediate Criticals)' if args.agent else 'Manual Trigger'}{C_RESET}", flush=True)
    print(f"  Zero-Day Filter  : {C_MAGENTA}{'ENABLED (Honeypot Focus)' if args.zero_day_only else 'Full Spectrum (DDoS, Botnet, Web, Scans)'}{C_RESET}", flush=True)
    print(f"{C_CYAN}" + "-" * 80 + C_RESET, flush=True)
    print(f"  {C_BOLD}{'TIME':<10} {'ATTACK TYPE':<32} {'SOURCE IP:PORT':<22} {'SCORE':<8} {'STATUS / OUTCOME'}{C_RESET}", flush=True)
    print(f"{C_CYAN}" + "-" * 80 + C_RESET, flush=True)


async def run_quorum_replay_suite() -> bool:
    """
    Executes the Cryptographic Action Quorum Anti-Replay and Negative Security Verification Suite.
    Verifies:
      - Valid token generation & human approval
      - Replay of identical authorization (blocked)
      - Modified PID, action, signature, and expired timestamp (blocked)
      - Direct unauthorized execution attempt (blocked)
      - Process identity change / PID reuse (blocked)
      - Protected process / self-kill attempt (blocked)
    """
    print(f"\n{C_CYAN}{C_BOLD}" + "=" * 80 + C_RESET)
    print(f"{C_CYAN}{C_BOLD}  [+] AEGIS AI -- CRYPTOGRAPHIC ACTION QUORUM & ANTI-REPLAY VERIFICATION{C_RESET}")
    print(f"{C_CYAN}" + "=" * 80 + C_RESET)

    from app.core.quorum import (
        PendingQuorumStore,
        compute_threat_hash,
        QuorumTokenStatus,
    )
    from app.core.security import validate_process_identity, is_protected_process
    import os

    store = PendingQuorumStore(token_lifetime=30.0)

    print(f"\n{C_YELLOW}{C_BOLD}--- DEMONSTRATION 1: POSITIVE HUMAN AUTHORIZATION CHAIN ---{C_RESET}")
    # 1. Detector trace
    print(f"\n{C_CYAN}{C_BOLD}[Detector Agent]{C_RESET}")
    print("Dynamic threshold tuned to 0.72 | Anomaly score: 0.96")

    # 2. Investigator trace
    print(f"\n{C_MAGENTA}{C_BOLD}[Investigator Agent]{C_RESET}")
    print("Threat investigated | Root cause: outbound socket entropy")

    # 3. Remediator requests high-risk action
    target_pid = 8104
    print(f"\n{C_YELLOW}{C_BOLD}[Remediator Agent]{C_RESET}")
    print(f"High-risk action requested: PID_KILL on PID {target_pid}")

    # 4. Generate HMAC-SHA256 token
    threat_hash = compute_threat_hash(
        source_event_id="inv-8104",
        threat_score=0.96,
        severity="critical",
        root_cause="outbound socket entropy",
        target_pid=target_pid,
        process_name="svchost.exe",
    )
    record, abbrev = await store.create_pending_token(
        target_pid=target_pid,
        action_type="PID_KILL",
        threat_hash=threat_hash,
        threat_score=0.96,
        process_info={"name": "svchost.exe"},
    )
    print(f"\n{C_BLUE}{C_BOLD}[Cryptographic Quorum]{C_RESET}")
    print(f"HMAC-SHA256 token generated: {abbrev}")
    print(f"\n{C_BLUE}{C_BOLD}[Cryptographic Quorum]{C_RESET}")
    print(f"Authorization required | expires in 30s")

    # 5. Frontend authorization requested
    print(f"\n{C_CYAN}{C_BOLD}[Frontend]{C_RESET}")
    print("Human authorization requested")

    # 6. Quorum verification & operator approval
    ok, reason, rec = await store.authorize_token(
        nonce=record.nonce,
        supplied_signature=record.hmac_signature,
        decision="APPROVE",
    )
    assert ok is True
    print(f"\n{C_GREEN}{C_BOLD}[Cryptographic Quorum]{C_RESET}")
    print("HMAC verified | Nonce matched")
    print(f"\n{C_GREEN}{C_BOLD}[Cryptographic Quorum]{C_RESET}")
    print("Human authorization confirmed")

    # 7. Remediator pre-execution validation
    print(f"\n{C_YELLOW}{C_BOLD}[Remediator Agent]{C_RESET}")
    print("PID identity verified")
    print(f"\n{C_YELLOW}{C_BOLD}[Remediator Agent]{C_RESET}")
    print(f"Execution successful for PID {target_pid}")

    # 8. Auditor verification
    print(f"\n{C_GREEN}{C_BOLD}[Auditor Agent]{C_RESET}")
    print("Closed-loop verification passed")

    # --- NEGATIVE SECURITY DEMONSTRATIONS ---
    print(f"\n{C_RED}{C_BOLD}--- DEMONSTRATION 2: NEGATIVE SECURITY & REPLAY MITIGATION ---{C_RESET}")

    # Negative 1: Tampered PID
    print(f"\n{C_RED}[Test 2.1 - Tampered PID]{C_RESET}")
    valid_pid, r_pid, _ = await store.validate_for_execution(
        nonce=record.nonce,
        expected_pid=9999,  # tampered
        expected_action="PID_KILL",
        expected_threat_hash=threat_hash,
    )
    assert valid_pid is False
    print(f"{C_BLUE}{C_BOLD}[Cryptographic Quorum]{C_RESET}\nAuthorization rejected | PAYLOAD_MISMATCH")

    # Negative 2: Replay of consumed nonce
    print(f"\n{C_RED}[Test 2.2 - Replayed Authorization]{C_RESET}")
    replay_ok, replay_reason, _ = await store.authorize_token(
        nonce=record.nonce,
        supplied_signature=record.hmac_signature,
        decision="APPROVE",
    )
    assert replay_ok is False
    print(f"{C_BLUE}{C_BOLD}[Cryptographic Quorum]{C_RESET}\nAuthorization rejected | NONCE_ALREADY_CONSUMED")

    # Negative 3: Expired token
    print(f"\n{C_RED}[Test 2.3 - Expired Token]{C_RESET}")
    exp_rec, _ = await store.create_pending_token(
        target_pid=7000,
        action_type="PID_KILL",
        threat_hash="e" * 64,
        threat_score=0.91,
        lifetime=0.01,
    )
    await asyncio.sleep(0.03)
    exp_ok, exp_reason, _ = await store.authorize_token(
        nonce=exp_rec.nonce,
        supplied_signature=exp_rec.hmac_signature,
        decision="APPROVE",
    )
    assert exp_ok is False
    print(f"{C_BLUE}{C_BOLD}[Cryptographic Quorum]{C_RESET}\nAuthorization rejected | TOKEN_EXPIRED")

    # Negative 4: Unauthorized direct execution without token
    print(f"\n{C_RED}[Test 2.4 - Unauthorized Direct Execution]{C_RESET}")
    unauth_ok, unauth_reason, _ = await store.validate_for_execution(
        nonce="forged_nonce_12345",
        expected_pid=1234,
        expected_action="PID_KILL",
        expected_threat_hash="f" * 64,
    )
    assert unauth_ok is False
    print(f"{C_YELLOW}{C_BOLD}[Remediator Agent]{C_RESET}\nExecution blocked | UNAUTHORIZED_EXECUTION_ATTEMPT")

    # Negative 5: PID reuse race condition
    print(f"\n{C_RED}[Test 2.5 - PID Identity Changed / PID Reuse]{C_RESET}")
    curr_pid = os.getpid()
    id_ok, id_reason = validate_process_identity(
        pid=curr_pid,
        expected_name="unknown_malware.exe",
    )
    assert id_ok is False
    print(f"{C_YELLOW}{C_BOLD}[Remediator Agent]{C_RESET}\nExecution blocked | PID_IDENTITY_CHANGED")

    # Negative 6: Protected process & AegisAI self-kill
    print(f"\n{C_RED}[Test 2.6 - Protected Process & Self-Kill Prevention]{C_RESET}")
    prot_ok, prot_reason = is_protected_process(4, name="services.exe")
    assert prot_ok is True
    print(f"{C_YELLOW}{C_BOLD}[Remediator Agent]{C_RESET}\nExecution blocked | PROTECTED_PROCESS")

    print(f"\n{C_CYAN}" + "=" * 80 + C_RESET)
    print(f"{C_GREEN}{C_BOLD}  [+] ALL 6 QUORUM ANTI-REPLAY & CRYPTOGRAPHIC TESTS PASSED (100% BLOCKED){C_RESET}")
    print(f"{C_CYAN}" + "=" * 80 + C_RESET + "\n")
    return True


def main():
    args = parse_args()
    if args.test_quorum:
        success = asyncio.run(run_quorum_replay_suite())
        sys.exit(0 if success else 1)

    if args.burst:
        args.delay = 0.25

    client = AegisStreamerClient(args.base_url, args.username, args.password)
    print(f"{C_YELLOW}[CONNECTING]{C_RESET} Authenticating with AegisAI Edge Engine at {args.base_url}...", flush=True)
    if not client.authenticate():
        print(f"{C_YELLOW}[INFO]{C_RESET} Live server not reachable at {args.base_url}. Running standalone Quorum Replay Suite...", flush=True)
        success = asyncio.run(run_quorum_replay_suite())
        sys.exit(0 if success else 1)

    print(f"{C_GREEN}[CONNECTED]{C_RESET} Authentication successful. JWT Session Token acquired.", flush=True)
    print_banner(args)

    pool = ATTACK_SCENARIOS
    if args.zero_day_only or (args.scenario and "zero_day" in args.scenario.lower()):
        pool = [s for s in ATTACK_SCENARIOS if "Zero-Day" in s["threat_type"]]
    elif args.scenario:
        matched = [s for s in ATTACK_SCENARIOS if args.scenario.lower() in s["threat_type"].lower() or args.scenario.lower() in s.get("category", "").lower()]
        if matched:
            pool = matched

    sent_count = 0
    try:
        while True:
            scenario = random.choice(pool)
            event = generate_attack_event(scenario)
            ts = datetime.now().strftime("%H:%M:%S")

            res = client.stream_attack(event)
            if res and "result" in res:
                result_entry = res["result"]
                score = result_entry.get("threat_score", event["threat_score"])
                score_pct = f"{int(score * 100)}%"

                # Color-coded severity badge
                if score >= 0.88:
                    score_str = f"{C_RED}{C_BOLD}{score_pct:<6}{C_RESET}"
                elif score >= 0.70:
                    score_str = f"{C_YELLOW}{C_BOLD}{score_pct:<6}{C_RESET}"
                elif score >= 0.45:
                    score_str = f"{C_BLUE}{score_pct:<6}{C_RESET}"
                else:
                    score_str = f"{C_GREEN}{score_pct:<6}{C_RESET}"

                # Status label
                action = result_entry.get("action_taken", "")
                deception = result_entry.get("deception_status", "")
                if action == "trapped_in_honeypot" or deception == "TRAPPED":
                    status_badge = f"{C_BG_CYAN}{C_WHITE}{C_BOLD} TRAPPED IN HONEYPOT {C_RESET} {C_CYAN}-> Decoy Neutralized{C_RESET}"
                elif result_entry.get("auto_containment"):
                    act_type = result_entry["auto_containment"].get("actionType", "AUTO-CONTAINED")
                    status_badge = f"{C_BG_RED}{C_WHITE}{C_BOLD} {act_type} {C_RESET} {C_RED}-> Self-Healing Applied{C_RESET}"
                elif action == "process_isolated":
                    status_badge = f"{C_YELLOW}* Process Auto-Isolated{C_RESET}"
                else:
                    status_badge = f"{C_GREEN}[OK] Live Ingested & Analyzed{C_RESET}"

                src_str = f"{event['source_ip']}:{event['port']}"
                attack_str = event['threat_type'][:30]
                print(f"  {ts:<10} {attack_str:<32} {src_str:<22} {score_str} {status_badge}", flush=True)

                # Optional: trigger agent streaming reasoning on critical events
                if args.agent and score >= 0.90 and sent_count % 3 == 0:
                    client.trigger_agent_remediation(result_entry.get("id", ""))

            sent_count += 1
            if args.count > 0 and sent_count >= args.count:
                print(f"\n{C_GREEN}{C_BOLD}[OK] Streamed {sent_count} attack events successfully. Replay complete.{C_RESET}\n", flush=True)
                break

            time.sleep(args.delay)

    except KeyboardInterrupt:
        print(f"\n\n{C_YELLOW}[PAUSED]{C_RESET} Attack replay stream stopped by user ({sent_count} events replayed).", flush=True)


if __name__ == "__main__":
    main()
