import subprocess
import json
import tempfile
import os


class SysmonEventCollector:

    def __init__(self):
        print("[ARGUS] Sysmon event collector initialized.")

    def get_process_events(self, max_events=20):

        powershell_script = f"""
$events = Get-WinEvent `
    -FilterHashtable @{{LogName="Microsoft-Windows-Sysmon/Operational"; Id=1}} `
    -MaxEvents {max_events} `
    -ErrorAction Stop

if ($null -eq $events) {{
    Write-Output "ARGUS_NO_EVENTS"
    exit 0
}}

$events |
    Select-Object RecordId, TimeCreated, Id, Message |
    ConvertTo-Json -Depth 5
"""

        script_path = None

        try:
            with tempfile.NamedTemporaryFile(
                mode="w",
                suffix=".ps1",
                delete=False,
                encoding="utf-8"
            ) as script_file:

                script_file.write(powershell_script)
                script_path = script_file.name

            command = [
                "powershell.exe",
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                script_path
            ]

            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=30
            )

        except subprocess.TimeoutExpired:
            print("[ARGUS ERROR] Sysmon query timed out.")
            return []

        finally:
            if script_path and os.path.exists(script_path):
                os.remove(script_path)

        if result.returncode != 0:
            print("[ARGUS ERROR] PowerShell failed.")
            print(result.stderr.strip())
            return []

        output = result.stdout.strip()

        if not output:
            print("[ARGUS] PowerShell returned no output.")
            return []

        if output == "ARGUS_NO_EVENTS":
            print("[ARGUS] No Sysmon process events found.")
            return []

        try:
            data = json.loads(output)

        except json.JSONDecodeError as error:
            print("[ARGUS ERROR] Could not parse Sysmon JSON.")
            print("Error:", error)
            print("Raw output:")
            print(output[:5000])
            return []

        if isinstance(data, dict):
            data = [data]

        print(
            f"[ARGUS] Retrieved "
            f"{len(data)} Sysmon process event(s)."
        )

        return data