from pathlib import Path

from .network_detection_engine import NetworkDetectionEngine
from .windows_detection_engine import WindowsDetectionEngine
from .alert_manager import AlertManager


class ArgusDetectionService:

    def __init__(
        self,
        network_model_path=None,
        windows_interval=5
    ):

        print("=" * 70)
        print("ARGUS UNIFIED DETECTION SERVICE")
        print("=" * 70)

        # -----------------------------------------------------
        # Alert Manager
        # -----------------------------------------------------

        self.alert_manager = AlertManager()

        # -----------------------------------------------------
        # Network model
        # -----------------------------------------------------

        if network_model_path is None:

            network_model_path = (
                Path(__file__).resolve().parent.parent
                / "models"
                / "argus_network_best_model.joblib"
            )

        network_model_path = str(
            network_model_path
        )

        print(
            "[ARGUS] Network model:",
            network_model_path
        )

        # -----------------------------------------------------
        # Network Detection Engine
        # -----------------------------------------------------

        self.network_engine = NetworkDetectionEngine(
            network_model_path
        )

        # -----------------------------------------------------
        # Windows Detection Engine
        # -----------------------------------------------------

        self.windows_engine = WindowsDetectionEngine()
        # -----------------------------------------------------
        # Statistics
        # -----------------------------------------------------

        self.total_alerts = 0

        print(
            "[ARGUS] Unified detection service initialized."
        )

    # =========================================================
    # PROCESS NETWORK RESULT
    # =========================================================

    def process_network_result(self, result):

        if not result:
            return None

        if not result.get("alert", False):
            return None

        detector_name = result.get(
            "detector",
            "network"
        )

        alert = self.alert_manager.create_alert(
            result,
            detector_name
        )

        if alert:

            self.total_alerts += 1

            self.print_alert(alert)

        return alert

    # =========================================================
    # PROCESS WINDOWS RESULT
    # =========================================================

    def process_windows_result(self, result):

        if not result:
            return None

        if not result.get("alert", False):
            return None

        alert_type = result.get(
            "alert_type",
            ""
        )

        if alert_type == "Suspicious PowerShell":

            detector_name = "powershell_detector"

        elif alert_type == "Suspicious Process Execution":

            detector_name = "process_detector"

        elif alert_type == "Brute Force / Failed Login":

            detector_name = "failed_login_detector"

        else:

            detector_name = "windows_detector"

        alert = self.alert_manager.create_alert(
            result,
            detector_name
        )

        if alert:

            self.total_alerts += 1

            self.print_alert(alert)

        return alert

    # =========================================================
    # PRINT ALERT
    # =========================================================

    @staticmethod
    def print_alert(alert):

        print()
        print("#" * 70)
        print("ARGUS UNIFIED SECURITY ALERT")
        print("#" * 70)

        print(
            "Alert ID:",
            alert["alert_id"]
        )

        print(
            "Alert Type:",
            alert["alert_type"]
        )

        print(
            "Detector:",
            alert["detector"]
        )

        print(
            "Severity:",
            alert["severity"]
        )

        print(
            "Risk Score:",
            alert["risk_score"]
        )

        if alert.get("source_ip"):

            print(
                "Source IP:",
                alert["source_ip"]
            )

        if alert.get("destination_ip"):

            print(
                "Destination IP:",
                alert["destination_ip"]
            )

        if alert.get("process_name"):

            print(
                "Process:",
                alert["process_name"]
            )

        if alert.get("user"):

            print(
                "User:",
                alert["user"]
            )

        print(
            "Status:",
            alert["status"]
        )

        print("#" * 70)

    # =========================================================
    # GET ALERTS
    # =========================================================

    def get_alerts(self):

        return self.alert_manager.get_alerts()

    # =========================================================
    # GET SUMMARY
    # =========================================================

    def get_summary(self):

        summary = self.alert_manager.get_summary()

        summary[
            "total_alerts_generated"
        ] = self.total_alerts

        return summary