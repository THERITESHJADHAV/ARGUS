from datetime import datetime, timezone
import uuid


class AlertManager:

    def __init__(self):

        self.alerts = []

        print(
            "[ARGUS] Alert manager initialized."
        )

    # =========================================================
    # CREATE UNIQUE ALERT ID
    # =========================================================

    @staticmethod
    def generate_alert_id():

        return (
            "ARGUS-"
            + uuid.uuid4().hex[:12].upper()
        )

    # =========================================================
    # NORMALIZE SEVERITY
    # =========================================================

    @staticmethod
    def normalize_severity(severity):

        if not severity:
            return "INFO"

        severity = str(
            severity
        ).upper()

        allowed = {
            "INFO",
            "LOW",
            "MEDIUM",
            "HIGH",
            "CRITICAL"
        }

        if severity in allowed:
            return severity

        return "INFO"

    # =========================================================
    # NORMALIZE RISK SCORE
    # =========================================================

    @staticmethod
    def normalize_risk_score(score):

        try:

            score = float(score)

        except (
            TypeError,
            ValueError
        ):

            return 0

        return round(
            max(
                0,
                min(
                    score,
                    100
                )
            ),
            2
        )

    # =========================================================
    # CREATE UNIFIED ALERT
    # =========================================================

    def create_alert(
        self,
        detector_result,
        detector_name
    ):

        if not detector_result:
            return None

        if not detector_result.get(
            "alert",
            False
        ):
            return None

        timestamp = detector_result.get(
            "timestamp"
        )

        if not timestamp:

            timestamp = (
                datetime.now(
                    timezone.utc
                ).isoformat()
            )

        alert = {

            # -------------------------------------------------
            # Identity
            # -------------------------------------------------

            "alert_id":
                self.generate_alert_id(),

            "timestamp":
                timestamp,

            # -------------------------------------------------
            # Detection information
            # -------------------------------------------------

            "alert_type":
                detector_result.get(
                    "alert_type",
                    "Unknown"
                ),

            "detector":
                detector_name,

            "severity":
                self.normalize_severity(
                    detector_result.get(
                        "severity"
                    )
                ),

            "risk_score":
                self.normalize_risk_score(
                    detector_result.get(
                        "risk_score",
                        0
                    )
                ),

            # -------------------------------------------------
            # Network information
            # -------------------------------------------------

            "source_ip":
                detector_result.get(
                    "source_ip"
                ),

            "destination_ip":
                detector_result.get(
                    "destination_ip"
                ),

            "source_port":
                detector_result.get(
                    "source_port"
                ),

            "destination_port":
                detector_result.get(
                    "destination_port"
                ),

            # -------------------------------------------------
            # Host/process information
            # -------------------------------------------------

            "process_name":
                detector_result.get(
                    "process_name"
                ),

            "image":
                detector_result.get(
                    "image"
                ),

            "process_id":
                detector_result.get(
                    "process_id"
                ),

            "parent_process_id":
                detector_result.get(
                    "parent_process_id"
                ),

            "parent_image":
                detector_result.get(
                    "parent_image"
                ),

            "command_line":
                detector_result.get(
                    "command_line"
                ),

            "user":
                detector_result.get(
                    "user"
                ),

            "integrity_level":
                detector_result.get(
                    "integrity_level"
                ),

            "sha256":
                detector_result.get(
                    "sha256"
                ),

            # -------------------------------------------------
            # Detection context
            # -------------------------------------------------

            "reasons":
                detector_result.get(
                    "reasons",
                    []
                ),

            "indicators":
                detector_result.get(
                    "indicators",
                    []
                ),

            "categories":
                detector_result.get(
                    "categories",
                    []
                ),

            # -------------------------------------------------
            # Alert lifecycle
            # -------------------------------------------------

            "status":
                detector_result.get(
                    "status",
                    "NEW"
                ),

            # -------------------------------------------------
            # Investigation / response fields
            # These will be populated later.
            # -------------------------------------------------

            "mitre_techniques": [],

            "ioc_matches": [],

            "investigation": None,

            "recommended_action": None,

            "response_action": None,

            "response_status": "NOT_STARTED"
        }

        self.alerts.append(
            alert
        )

        return alert

    # =========================================================
    # GET ALL ALERTS
    # =========================================================

    def get_alerts(self):

        return list(
            self.alerts
        )

    # =========================================================
    # GET ALERT BY ID
    # =========================================================

    def get_alert(
        self,
        alert_id
    ):

        for alert in self.alerts:

            if alert["alert_id"] == alert_id:
                return alert

        return None

    # =========================================================
    # UPDATE ALERT STATUS
    # =========================================================

    def update_status(
        self,
        alert_id,
        status
    ):

        alert = self.get_alert(
            alert_id
        )

        if alert is None:
            return None

        alert["status"] = status

        return alert

    # =========================================================
    # SUMMARY
    # =========================================================

    def get_summary(self):

        summary = {

            "total_alerts":
                len(self.alerts),

            "critical":
                0,

            "high":
                0,

            "medium":
                0,

            "low":
                0,

            "info":
                0
        }

        for alert in self.alerts:

            severity = (
                alert["severity"]
                .lower()
            )

            if severity in summary:
                summary[severity] += 1

        return summary