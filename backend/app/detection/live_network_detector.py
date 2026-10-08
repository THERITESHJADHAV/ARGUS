import pandas as pd

from .network_collector import NetworkCollector
from .flow_feature_extractor import FlowFeatureExtractor
from .network_detector import NetworkDetector
from .network_features import NETWORK_FEATURES
from .alert import create_network_alert


class LiveNetworkDetector:

    def __init__(self, model_path):

        print("=" * 70)
        print("ARGUS LIVE NETWORK DETECTOR")
        print("=" * 70)

        # ---------------------------------------------
        # Flow extractor
        # ---------------------------------------------

        self.extractor = FlowFeatureExtractor()

        # ---------------------------------------------
        # Trained Random Forest
        # ---------------------------------------------

        self.detector = NetworkDetector(
            model_path=model_path
        )

        # ---------------------------------------------
        # Live packet collector
        # ---------------------------------------------

        self.collector = NetworkCollector(
            callback=self.handle_packet
        )

        self.packet_count = 0
        self.flow_count = 0
        self.alert_count = 0

        print(
            "[ARGUS] Live network detector initialized."
        )


    # =================================================
    # PACKET CALLBACK
    # =================================================

    def handle_packet(self, event):

        self.packet_count += 1

        print()
        print(
            f"[PACKET {self.packet_count}]"
        )

        print(
            f"{event['source_ip']} "
            f"→ "
            f"{event['destination_ip']}"
        )

        print(
            f"{event['protocol']} "
            f"{event['source_port']} "
            f"→ "
            f"{event['destination_port']}"
        )

        print(
            f"Size: {event['packet_size']}"
        )


        # ---------------------------------------------
        # Add packet to flow extractor
        # ---------------------------------------------

        features = self.extractor.add_packet(
            event
        )


        # No completed flow yet
        if features is None:
            return


        self.flow_count += 1


        print()
        print(
            "[ARGUS FLOW CREATED]"
        )

        print(
            "Flow number:",
            self.flow_count
        )


        # =================================================
        # VALIDATE FEATURES
        # =================================================

        missing = [
            feature
            for feature in NETWORK_FEATURES
            if feature not in features
        ]

        if missing:

            print(
                "[ARGUS ERROR] Missing features:"
            )

            for feature in missing:
                print(
                    " -",
                    feature
                )

            return


        # =================================================
        # CREATE MODEL INPUT
        # =================================================

        flow_df = pd.DataFrame(
            [
                {
                    feature: features[feature]
                    for feature in NETWORK_FEATURES
                }
            ]
        )


        print()
        print(
            "[ARGUS] Sending flow to Random Forest..."
        )


        # =================================================
        # RUN MODEL
        # =================================================

        try:

            prediction_results = (
                self.detector.predict(
                    flow_df
                )
            )

        except Exception as error:

            print()
            print(
                "[ARGUS ERROR] Model prediction failed."
            )

            print(
                "Error:",
                error
            )

            return


        result = prediction_results[0]


        # =================================================
        # DISPLAY RESULT
        # =================================================

        print()
        print("=" * 70)
        print("ARGUS NETWORK ML RESULT")
        print("=" * 70)

        print(
            "Prediction:",
            result["prediction"]
        )

        print(
            "Attack Probability:",
            result["attack_probability"]
        )

        print(
            "Confidence:",
            result["confidence"]
        )

        print("=" * 70)


        # =================================================
        # CREATE ARGUS ALERT
        # =================================================

        alert = create_network_alert(

            prediction_result=result,

            source_ip=event.get(
                "source_ip"
            ),

            destination_ip=event.get(
                "destination_ip"
            ),

            destination_port=event.get(
                "destination_port"
            )
        )


        # =================================================
        # ATTACK ALERT
        # =================================================

        if result["prediction"] == "ATTACK":

            self.alert_count += 1

            print()
            print(
                "🚨" * 10
            )

            print(
                "ARGUS NETWORK ATTACK ALERT"
            )

            print(
                "🚨" * 10
            )

            print(
                "Alert Type:",
                alert["alert_type"]
            )

            print(
                "Severity:",
                alert["severity"]
            )

            print(
                "Source IP:",
                alert["source_ip"]
            )

            print(
                "Destination IP:",
                alert["destination_ip"]
            )

            print(
                "Destination Port:",
                alert["destination_port"]
            )

            print(
                "Attack Probability:",
                alert["attack_probability"]
            )

            print(
                "Confidence:",
                alert["confidence"]
            )

            print(
                "Status:",
                alert["status"]
            )

            print(
                "🚨" * 10
            )


    # =================================================
    # START MONITORING
    # =================================================

    def start(self, interface=None):

        print()
        print(
            "[ARGUS] Starting live network detection..."
        )

        print(
            "[ARGUS] Monitoring network traffic..."
        )

        print(
            "[ARGUS] Press CTRL+C to stop."
        )

        print()

        try:

            self.collector.start(
                interface=interface
            )

        except KeyboardInterrupt:

            print()
            print(
                "[ARGUS] Network detection stopped."
            )

        finally:

            print()
            print("=" * 70)
            print("ARGUS NETWORK DETECTOR SUMMARY")
            print("=" * 70)

            print(
                "Packets captured:",
                self.packet_count
            )

            print(
                "Flows created:",
                self.flow_count
            )

            print(
                "Network alerts:",
                self.alert_count
            )

            print("=" * 70)