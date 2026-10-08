import time

from .windows_event_collector import (
    WindowsEventCollector
)

from .failed_login_parser import (
    FailedLoginParser
)

from .failed_login_detector import (
    FailedLoginDetector
)


class WindowsDetectionEngine:

    def __init__(
        self,
        failure_threshold=5,
        time_window_seconds=60
    ):

        print("=" * 70)
        print("ARGUS WINDOWS DETECTION ENGINE")
        print("=" * 70)

        # -------------------------------------------------
        # Windows event collector
        # -------------------------------------------------

        self.collector = WindowsEventCollector()

        # -------------------------------------------------
        # Failed login parser
        # -------------------------------------------------

        self.parser = FailedLoginParser()

        # -------------------------------------------------
        # Failed login detector
        # -------------------------------------------------

        self.failed_login_detector = (
            FailedLoginDetector(
                failure_threshold=failure_threshold,
                time_window_seconds=time_window_seconds
            )
        )

        # -------------------------------------------------
        # Statistics
        # -------------------------------------------------

        self.events_processed = 0
        self.alerts_generated = 0

        print(
            "[ARGUS] Windows detection engine initialized."
        )


    # =====================================================
    # PROCESS ONE WINDOWS EVENT
    # =====================================================

    def process_event(self, event):

        # -------------------------------------------------
        # Parse raw Windows event
        # -------------------------------------------------

        parsed_event = self.parser.parse(
            event
        )

        self.events_processed += 1

        # -------------------------------------------------
        # Run failed-login detector
        # -------------------------------------------------

        result = (
            self.failed_login_detector
            .process_event(
                parsed_event
            )
        )

        # -------------------------------------------------
        # Normal event
        # -------------------------------------------------

        if not result["alert"]:

            print(
                "[ARGUS] Failed login:",
                result["failure_count"],
                "| Source:",
                result["source_ip"],
                "| User:",
                result["username"]
            )

            return result

        # -------------------------------------------------
        # ALERT
        # -------------------------------------------------

        self.alerts_generated += 1

        print()
        print("=" * 70)
        print("🚨 ARGUS BRUTE FORCE / FAILED LOGIN ALERT")
        print("=" * 70)

        print(
            "Alert Type:",
            result["alert_type"]
        )

        print(
            "Severity:",
            result["severity"]
        )

        print(
            "Source IP:",
            result["source_ip"]
        )

        print(
            "Username:",
            result["username"]
        )

        print(
            "Failure Count:",
            result["failure_count"]
        )

        print(
            "Time Window:",
            result["time_window_seconds"],
            "seconds"
        )

        print(
            "Status:",
            result["status"]
        )

        print("=" * 70)

        return result


    # =====================================================
    # SCAN WINDOWS SECURITY LOG ONCE
    # =====================================================

    def scan_once(self):

        print()
        print(
            "[ARGUS] Scanning Windows Security log..."
        )

        events = (
            self.collector
            .get_failed_login_events(
                max_events=50
            )
        )

        print(
            "[ARGUS] Events retrieved:",
            len(events)
        )

        for event in events:

            self.process_event(
                event
            )


        return len(events)


    # =====================================================
    # CONTINUOUS MONITORING
    # =====================================================

    def start(
        self,
        interval_seconds=5
    ):

        print()
        print("=" * 70)
        print("ARGUS WINDOWS DETECTION ENGINE STARTED")
        print("=" * 70)

        print(
            "Monitoring: Windows Security Event ID 4625"
        )

        print(
            "Check interval:",
            interval_seconds,
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
                    interval_seconds
                )

        except KeyboardInterrupt:

            print()
            print(
                "[ARGUS] Windows monitoring stopped."
            )

        finally:

            self.print_summary()


    # =====================================================
    # SUMMARY
    # =====================================================

    def print_summary(self):

        print()
        print("=" * 70)
        print("ARGUS WINDOWS DETECTION SUMMARY")
        print("=" * 70)

        print(
            "Events processed:",
            self.events_processed
        )

        print(
            "Alerts generated:",
            self.alerts_generated
        )

        print("=" * 70)