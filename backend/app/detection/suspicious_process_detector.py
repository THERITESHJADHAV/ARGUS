import os
import re


class SuspiciousProcessDetector:

    def __init__(self):

        # Processes that can legitimately be used for administration,
        # scripting, execution, or LOLBin-style activity.
        self.suspicious_processes = {
            "powershell.exe",
            "pwsh.exe",
            "cmd.exe",
            "wscript.exe",
            "cscript.exe",
            "mshta.exe",
            "rundll32.exe",
            "regsvr32.exe",
            "certutil.exe",
            "bitsadmin.exe",
            "wmic.exe",
            "msiexec.exe"
        }

        # Locations commonly writable by normal users.
        self.suspicious_locations = [
            "\\temp\\",
            "\\appdata\\local\\temp\\",
            "\\appdata\\roaming\\",
            "\\downloads\\",
            "\\public\\",
            "\\startup\\"
        ]

        # Command-line indicators associated with suspicious execution.
        self.suspicious_command_patterns = [
            r"-enc(?:odedcommand)?\b",
            r"frombase64string",
            r"invoke-expression",
            r"\biex\b",
            r"downloadstring",
            r"downloadfile",
            r"invoke-webrequest",
            r"start-bitstransfer",
            r"executionpolicy\s+bypass",
            r"-windowstyle\s+hidden",
            r"-nop\b",
            r"-noprofile\b",
            r"javascript:",
            r"vbscript:",
        ]

        # Parent-child combinations that deserve additional attention.
        self.suspicious_parent_pairs = [
            ("winword.exe", "powershell.exe"),
            ("winword.exe", "cmd.exe"),
            ("excel.exe", "powershell.exe"),
            ("excel.exe", "cmd.exe"),
            ("outlook.exe", "powershell.exe"),
            ("outlook.exe", "cmd.exe"),
            ("chrome.exe", "powershell.exe"),
            ("chrome.exe", "cmd.exe"),
            ("msedge.exe", "powershell.exe"),
            ("msedge.exe", "cmd.exe"),
            ("firefox.exe", "powershell.exe"),
            ("firefox.exe", "cmd.exe"),
        ]

    # ---------------------------------------------------------
    # Utility functions
    # ---------------------------------------------------------

    @staticmethod
    def normalize(value):

        if value is None:
            return ""

        return str(value).strip().lower()

    @staticmethod
    def get_process_name(image):

        if not image:
            return ""

        image = str(image).strip()

        return os.path.basename(
            image.replace("/", "\\")
        ).lower()

    # ---------------------------------------------------------
    # Individual detection checks
    # ---------------------------------------------------------

    def check_suspicious_process(self, process_name):

        return process_name in self.suspicious_processes

    def check_suspicious_location(self, image):

        image_lower = self.normalize(image)

        for location in self.suspicious_locations:

            if location in image_lower:
                return True

        return False

    def check_suspicious_command(self, command_line):

        command_lower = self.normalize(command_line)

        if not command_lower:
            return []

        matches = []

        for pattern in self.suspicious_command_patterns:

            if re.search(pattern, command_lower):
                matches.append(pattern)

        return matches

    def check_parent_child(self, parent_image, process_name):

        parent_name = self.get_process_name(
            parent_image
        )

        child_name = self.get_process_name(
            process_name
        )

        pair = (parent_name, child_name)

        return pair in self.suspicious_parent_pairs

    # ---------------------------------------------------------
    # Main detection function
    # ---------------------------------------------------------

    def process_event(self, event):

        image = event.get("image")
        command_line = event.get("command_line")
        parent_image = event.get("parent_image")

        process_name = self.get_process_name(
            image
        )

        score = 0
        reasons = []

        # -----------------------------------------------------
        # Rule 1: Suspicious process
        # -----------------------------------------------------

        if self.check_suspicious_process(process_name):

            score += 20

            reasons.append(
                f"Process is commonly used for script/system execution: "
                f"{process_name}"
            )

        # -----------------------------------------------------
        # Rule 2: Suspicious executable location
        # -----------------------------------------------------

        if self.check_suspicious_location(image):

            score += 30

            reasons.append(
                "Process executed from a user-writable/suspicious location"
            )

        # -----------------------------------------------------
        # Rule 3: Suspicious command line
        # -----------------------------------------------------

        command_matches = self.check_suspicious_command(
            command_line
        )

        if command_matches:

            score += min(
                30,
                len(command_matches) * 10
            )

            reasons.append(
                "Suspicious command-line indicators detected"
            )

        # -----------------------------------------------------
        # Rule 4: Suspicious parent-child relationship
        # -----------------------------------------------------

        if self.check_parent_child(
            parent_image,
            process_name
        ):

            score += 25

            parent_name = self.get_process_name(
                parent_image
            )

            reasons.append(
                f"Suspicious parent-child relationship: "
                f"{parent_name} -> {process_name}"
            )

        # -----------------------------------------------------
        # Rule 5: Integrity level
        # -----------------------------------------------------

        integrity = self.normalize(
            event.get("integrity_level")
        )

        if integrity == "system":

            score += 10

            reasons.append(
                "Process running with SYSTEM integrity"
            )

        # -----------------------------------------------------
        # Limit score
        # -----------------------------------------------------

        score = min(score, 100)

        # -----------------------------------------------------
        # Determine severity
        # -----------------------------------------------------

        if score >= 80:
            severity = "HIGH"

        elif score >= 60:
            severity = "MEDIUM"

        elif score >= 30:
            severity = "LOW"

        else:
            severity = "INFO"

        # -----------------------------------------------------
        # Determine alert
        # -----------------------------------------------------

        alert = score >= 30

        result = {
            "alert": alert,
            "alert_type": "Suspicious Process Execution",
            "severity": severity,
            "risk_score": score,
            "process_name": process_name,
            "image": image,
            "command_line": command_line,
            "parent_image": parent_image,
            "user": event.get("user"),
            "integrity_level": event.get("integrity_level"),
            "sha256": event.get("sha256"),
            "process_id": event.get("process_id"),
            "parent_process_id": event.get(
                "parent_process_id"
            ),
            "timestamp": event.get("timestamp"),
            "reasons": reasons,
            "status": "NEW" if alert else "NORMAL"
        }

        return result