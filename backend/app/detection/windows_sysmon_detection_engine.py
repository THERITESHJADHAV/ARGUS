import time

from .sysmon_event_collector import SysmonEventCollector
from .sysmon_event_parser import SysmonEventParser
from .suspicious_process_detector import SuspiciousProcessDetector
from .powershell_detector import PowerShellDetector


class WindowsSysmonDetectionEngine:

    def __init__(self, interval_seconds=5):

        print("=" * 70)
        print("ARGUS WINDOWS + SYSMON DETECTION ENGINE")
        print("=" * 70)

        self.interval_seconds = interval_seconds

        # -----------------------------------------------------
        # Components
        # -----------------------------------------------------

        self.collector = SysmonEventCollector()

        self.parser = SysmonEventParser()

        self.process_detector = (
            SuspiciousProcessDetector()
        )

        self.powershell_detector = (
            PowerShellDetector()
        )

        # -----------------------------------------------------
        # Runtime statistics
        # -----------------------------------------------------

        self.events_processed = 0
        self.process_alerts = 0
        self.powershell_alerts = 0

        # Prevent processing the same Sysmon event repeatedly
        self.processed_record_ids = set()

        print(
            "[ARGUS] Windows + Sysmon detection engine initialized."
        )

    # =========================================================
    # PROCESS ONE SYSMON EVENT
    # =========================================================

    def process_event(self, raw_event):

        # -----------------------------------------------------
        # Parse raw Sysmon event
        # -----------------------------------------------------

        parsed_event = self.parser.parse(
            raw_event
        )

        if parsed_event is None:

            print(
                "[ARGUS] Could not parse Sysmon event."
            )

            return []

        record_id = parsed_event.get(
            "record_id"
        )

        # -----------------------------------------------------
        # Avoid duplicate processing
        # -----------------------------------------------------

        if record_id is not None:

            if record_id in self.processed_record_ids:
                return []

            self.processed_record_ids.add(
                record_id
            )

        self.events_processed += 1

        alerts = []

        # -----------------------------------------------------
        # Suspicious Process Detector
        # -----------------------------------------------------

        process_result = (
            self.process_detector.process_event(
                parsed_event
            )
        )

        if process_result["alert"]:

            self.process_alerts += 1

            alerts.append(
                process_result
            )

            self.print_alert(
                process_result
            )

        # -----------------------------------------------------
        # PowerShell Detector
        # -----------------------------------------------------

        powershell_result = (
            self.powershell_detector.process_event(
                parsed_event
            )
        )

        if powershell_result["alert"]:

            self.powershell_alerts += 1

            alerts.append(
                powershell_result
            )

            self.print_alert(
                powershell_result
            )

        return alerts

    # =========================================================
    # SCAN SYSMON LOG
    # =========================================================

    def scan_once(self):

        print()
        print(
            "[ARGUS] Scanning Sysmon Event ID 1..."
        )

        events = (
            self.collector.get_process_events(
                max_events=50
            )
        )

        print(
            "[ARGUS] Sysmon events retrieved:",
            len(events)
        )

        total_alerts = 0

        # -----------------------------------------------------
        # Process events
        # -----------------------------------------------------

        for event in events:

            alerts = self.process_event(
                event
            )

            total_alerts += len(
                alerts
            )

        print(
            "[ARGUS] Alerts generated in this scan:",
            total_alerts
        )

        return total_alerts

    # =========================================================
    # PRINT ALERT
    # =========================================================

    @staticmethod
    def print_alert(result):

        print()
        print("!" * 70)
        print("🚨 ARGUS SECURITY ALERT")
        print("!" * 70)

        print(
            "Alert Type:",
            result.get("alert_type")
        )

        print(
            "Severity:",
            result.get("severity")
        )

        print(
            "Risk Score:",
            result.get("risk_score")
        )

        print(
            "Process:",
            result.get("process_name")
        )

        print(
            "Image:",
            result.get("image")
        )

        print(
            "Parent:",
            result.get("parent_image")
        )

        print(
            "User:",
            result.get("user")
        )

        print(
            "Command:",
            result.get("command_line")
        )

        print(
            "SHA256:",
            result.get("sha256")
        )

        print(
            "Status:",
            result.get("status")
        )

        print("Reasons:")

        for reason in result.get(
            "reasons",
            []
        ):

            print(
                " -",
                reason
            )

        print("!" * 70)

    # =========================================================
    # CONTINUOUS MONITORING
    # =========================================================

    def start(self):

        print()
        print("=" * 70)
        print(
            "ARGUS WINDOWS + SYSMON MONITORING STARTED"
        )
        print("=" * 70)

        print(
            "Monitoring: Sysmon Event ID 1"
        )

        print(
            "Check interval:",
            self.interval_seconds,
            "seconds"
        )

        print(
            "Press CTRL+C to stop."
        )

        print()

        try:

            while True:

                self.scan_once()

                time.sleep(
                    self.interval_seconds
                )

        except KeyboardInterrupt:

            print()
            print(
                "[ARGUS] Windows + Sysmon monitoring stopped."
            )

        finally:

            self.print_summary()

    # =========================================================
    # SUMMARY
    # =========================================================

    def print_summary(self):

        print()
        print("=" * 70)
        print(
            "ARGUS WINDOWS + SYSMON SUMMARY"
        )
        print("=" * 70)

        print(
            "Events processed:",
            self.events_processed
        )

        print(
            "Process alerts:",
            self.process_alerts
        )

        print(
            "PowerShell alerts:",
            self.powershell_alerts
        )

        print(
            "Unique Record IDs:",
            len(self.processed_record_ids)
        )

        print("=" * 70)