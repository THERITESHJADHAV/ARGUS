from collections import defaultdict
from datetime import datetime, timezone


class FailedLoginDetector:

    def __init__(
        self,
        failure_threshold=5,
        time_window_seconds=60
    ):

        self.failure_threshold = (
            failure_threshold
        )

        self.time_window_seconds = (
            time_window_seconds
        )

        self.failed_attempts = (
            defaultdict(list)
        )


    # =====================================================
    # PROCESS FAILED LOGIN
    # =====================================================

    def process_event(
        self,
        event
    ):

        source_ip = event.get(
            "source_ip"
        )

        username = event.get(
            "username"
        )

        timestamp = event.get(
            "timestamp"
        )


        # -------------------------------------------------
        # Ignore events without source
        # -------------------------------------------------

        if not source_ip:

            return {
                "alert": False
            }


        # -------------------------------------------------
        # Create current timestamp
        # -------------------------------------------------

        now = datetime.now(
            timezone.utc
        )


        key = (
            source_ip,
            username
        )


        # -------------------------------------------------
        # Store attempt
        # -------------------------------------------------

        self.failed_attempts[key].append(
            now
        )


        # -------------------------------------------------
        # Remove old attempts
        # -------------------------------------------------

        valid_attempts = []

        for attempt in self.failed_attempts[key]:

            age = (
                now - attempt
            ).total_seconds()


            if age <= self.time_window_seconds:

                valid_attempts.append(
                    attempt
                )


        self.failed_attempts[key] = (
            valid_attempts
        )


        failure_count = len(
            valid_attempts
        )


        # -------------------------------------------------
        # Detect brute force
        # -------------------------------------------------

        if failure_count >= self.failure_threshold:

            return {

                "alert": True,

                "alert_type":
                    "Brute Force / Failed Login",

                "severity":
                    "HIGH",

                "source_ip":
                    source_ip,

                "username":
                    username,

                "failure_count":
                    failure_count,

                "time_window_seconds":
                    self.time_window_seconds,

                "status":
                    "NEW"
            }


        return {

            "alert": False,

            "alert_type":
                "Brute Force / Failed Login",

            "source_ip":
                source_ip,

            "username":
                username,

            "failure_count":
                failure_count
        }