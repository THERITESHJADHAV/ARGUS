import subprocess
import json


class WindowsEventCollector:

    def __init__(self):

        print(
            "[ARGUS] Windows event collector initialized."
        )


    # =====================================================
    # GET FAILED LOGIN EVENTS
    # Windows Security Event ID 4625
    # =====================================================

    def get_failed_login_events(
        self,
        max_events=20
    ):

        powershell_command = f"""
try {{
    $events = Get-WinEvent `
        -FilterHashtable @{{LogName='Security'; Id=4625}} `
        -MaxEvents {max_events} `
        -ErrorAction Stop

    if ($null -eq $events) {{
        Write-Output "ARGUS_NO_EVENTS"
    }}
    else {{
        $events |
        Select-Object RecordId, TimeCreated, Id, Message |
        ConvertTo-Json -Depth 5
    }}
}}
catch {{
    if ($_.Exception.Message -like "*No events were found*") {{
        Write-Output "ARGUS_NO_EVENTS"
    }}
    else {{
        Write-Output "ARGUS_QUERY_ERROR"
        Write-Output $_.Exception.Message
    }}
}}
"""


        command = [
            "powershell",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            powershell_command
        ]


        # -------------------------------------------------
        # Execute PowerShell
        # -------------------------------------------------

        try:

            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=30
            )

        except subprocess.TimeoutExpired:

            print(
                "[ARGUS ERROR] "
                "Windows event query timed out."
            )

            return []


        output = result.stdout.strip()


        # -------------------------------------------------
        # NO EVENTS
        # -------------------------------------------------

        if "ARGUS_NO_EVENTS" in output:
            return []


        # -------------------------------------------------
        # QUERY ERROR
        # -------------------------------------------------

        if "ARGUS_QUERY_ERROR" in output:

            print(
                "[ARGUS ERROR] "
                "Windows Security event query failed."
            )

            print(
                output
            )

            return []


        # -------------------------------------------------
        # Empty output
        # -------------------------------------------------

        if not output:
            return []


        # -------------------------------------------------
        # Parse JSON
        # -------------------------------------------------

        try:

            data = json.loads(
                output
            )

        except json.JSONDecodeError as error:

            print(
                "[ARGUS ERROR] "
                "Could not parse Windows event data."
            )

            print(
                "Error:",
                error
            )

            print(
                "Raw output:"
            )

            print(
                output[:3000]
            )

            return []


        # -------------------------------------------------
        # Single event → list
        # -------------------------------------------------

        if isinstance(
            data,
            dict
        ):

            data = [data]


        print(
            f"[ARGUS] Retrieved "
            f"{len(data)} failed-login event(s)."
        )


        return data

    # =====================================================
    # GET POWERSHELL SCRIPTBLOCK EVENTS
    # Windows PowerShell Operational Event ID 4104
    # =====================================================

    def get_powershell_events(self, max_events=20):
        powershell_command = (
            f"Get-WinEvent -FilterHashtable @{{LogName='Microsoft-Windows-PowerShell/Operational'; Id=4104}} "
            f"-MaxEvents {max_events} -ErrorAction SilentlyContinue | "
            f"Select-Object RecordId, TimeCreated, Id, Message | ConvertTo-Json -Compress"
        )
        command = [
            "powershell",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            powershell_command
        ]

        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=15
            )
        except subprocess.TimeoutExpired:
            return []

        output = result.stdout.strip()
        if not output:
            return []

        try:
            data = json.loads(output)
        except Exception:
            return []

        if isinstance(data, dict):
            data = [data]

        return data