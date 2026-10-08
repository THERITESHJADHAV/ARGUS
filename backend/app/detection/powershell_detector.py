import re
import os


class PowerShellDetector:

    def __init__(self):

        self.powershell_processes = {
            "powershell.exe",
            "pwsh.exe"
        }

        # Suspicious PowerShell indicators
        self.suspicious_patterns = {
            "encoded_command": [
                r"-enc\b",
                r"-encodedcommand\b"
            ],

            "execution_bypass": [
                r"-executionpolicy\s+bypass",
                r"-ep\s+bypass"
            ],

            "download_activity": [
                r"downloadstring",
                r"downloadfile",
                r"invoke-webrequest",
                r"\biwr\b",
                r"start-bitstransfer"
            ],

            "script_execution": [
                r"invoke-expression",
                r"\biex\b",
                r"\.?\s*invoke-command",
                r"invoke-restmethod"
            ],

            "obfuscation": [
                r"frombase64string",
                r"replace\s*\(",
                r"\[char\]",
                r"join\s*\(",
                r"-join\b"
            ],

            "hidden_execution": [
                r"-windowstyle\s+hidden",
                r"-w\s+hidden",
                r"-nop\b",
                r"-noprofile\b"
            ],

            "credential_or_security_activity": [
                r"sekurlsa",
                r"mimikatz",
                r"lsass",
                r"credential",
                r"securitycenter"
            ]
        }

    # ---------------------------------------------------------
    # Utility
    # ---------------------------------------------------------

    @staticmethod
    def get_process_name(image):

        if not image:
            return ""

        image = str(image).strip()

        return os.path.basename(
            image.replace("/", "\\")
        ).lower()

    # ---------------------------------------------------------
    # Detect PowerShell
    # ---------------------------------------------------------

    def is_powershell(self, event):

        image = event.get("image", "")

        process_name = self.get_process_name(
            image
        )

        return process_name in self.powershell_processes

    # ---------------------------------------------------------
    # Analyze command line
    # ---------------------------------------------------------

    def analyze_command_line(self, command_line):

        if not command_line:

            return {
                "matched": False,
                "categories": [],
                "indicators": []
            }

        command = str(
            command_line
        ).lower()

        categories = []
        indicators = []

        for category, patterns in self.suspicious_patterns.items():

            for pattern in patterns:

                match = re.search(
                    pattern,
                    command,
                    re.IGNORECASE
                )

                if match:

                    if category not in categories:
                        categories.append(category)

                    indicators.append(
                        match.group(0)
                    )

        return {
            "matched": len(indicators) > 0,
            "categories": categories,
            "indicators": indicators
        }

    # ---------------------------------------------------------
    # Calculate risk score
    # ---------------------------------------------------------

    def calculate_score(
        self,
        analysis,
        parent_image=None,
        integrity_level=None
    ):

        score = 0
        reasons = []

        categories = analysis["categories"]

        # PowerShell itself
        score += 10

        reasons.append(
            "PowerShell process detected"
        )

        # Encoded command
        if "encoded_command" in categories:

            score += 30

            reasons.append(
                "Encoded PowerShell command detected"
            )

        # Execution policy bypass
        if "execution_bypass" in categories:

            score += 25

            reasons.append(
                "PowerShell execution policy bypass detected"
            )

        # Download activity
        if "download_activity" in categories:

            score += 20

            reasons.append(
                "PowerShell download/network activity detected"
            )

        # Script execution
        if "script_execution" in categories:

            score += 20

            reasons.append(
                "PowerShell script execution technique detected"
            )

        # Obfuscation
        if "obfuscation" in categories:

            score += 20

            reasons.append(
                "Possible PowerShell obfuscation detected"
            )

        # Hidden execution
        if "hidden_execution" in categories:

            score += 15

            reasons.append(
                "Hidden or profile-bypassing PowerShell execution detected"
            )

        # Credential/security related activity
        if "credential_or_security_activity" in categories:

            score += 25

            reasons.append(
                "Credential or security-sensitive activity detected"
            )

        # Suspicious parent
        if parent_image:

            parent_name = self.get_process_name(
                parent_image
            )

            suspicious_parents = {
                "winword.exe",
                "excel.exe",
                "outlook.exe",
                "chrome.exe",
                "msedge.exe",
                "firefox.exe"
            }

            if parent_name in suspicious_parents:

                score += 20

                reasons.append(
                    f"PowerShell launched by {parent_name}"
                )

        # SYSTEM integrity
        if integrity_level:

            if str(
                integrity_level
            ).lower() == "system":

                score += 10

                reasons.append(
                    "PowerShell running with SYSTEM integrity"
                )

        score = min(
            score,
            100
        )

        return score, reasons

    # ---------------------------------------------------------
    # Main detector
    # ---------------------------------------------------------

    def process_event(self, event):

        if not self.is_powershell(event):

            return {
                "alert": False,
                "alert_type": "Suspicious PowerShell",
                "severity": "INFO",
                "risk_score": 0,
                "process_name": self.get_process_name(
                    event.get("image")
                ),
                "status": "NORMAL",
                "reasons": [
                    "Process is not PowerShell"
                ]
            }

        command_line = event.get(
            "command_line",
            ""
        )

        analysis = self.analyze_command_line(
            command_line
        )

        score, reasons = self.calculate_score(
            analysis,
            parent_image=event.get(
                "parent_image"
            ),
            integrity_level=event.get(
                "integrity_level"
            )
        )

        # Alert threshold
        alert = score >= 30

        if score >= 80:
            severity = "HIGH"

        elif score >= 60:
            severity = "MEDIUM"

        elif score >= 30:
            severity = "LOW"

        else:
            severity = "INFO"

        return {
            "alert": alert,
            "alert_type": "Suspicious PowerShell",
            "severity": severity,
            "risk_score": score,
            "process_name": self.get_process_name(
                event.get("image")
            ),
            "image": event.get("image"),
            "command_line": command_line,
            "parent_image": event.get(
                "parent_image"
            ),
            "parent_process_id": event.get(
                "parent_process_id"
            ),
            "process_id": event.get(
                "process_id"
            ),
            "user": event.get(
                "user"
            ),
            "integrity_level": event.get(
                "integrity_level"
            ),
            "sha256": event.get(
                "sha256"
            ),
            "timestamp": event.get(
                "timestamp"
            ),
            "categories": analysis["categories"],
            "indicators": analysis["indicators"],
            "reasons": reasons,
            "status": "NEW" if alert else "NORMAL"
        }