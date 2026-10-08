import pandas as pd

from .network_collector import NetworkCollector
from .flow_feature_extractor import FlowFeatureExtractor
from .network_detector import NetworkDetector
from .port_scan_detector import PortScanDetector
from .outbound_detector import OutboundDetector


class NetworkDetectionEngine:

    def __init__(self, model_path):

        print("=" * 70)
        print("ARGUS NETWORK DETECTION ENGINE")
        print("=" * 70)

        # -------------------------------------------------
        # ONE network collector
        # -------------------------------------------------

        self.collector = NetworkCollector(
            callback=self.handle_event
        )

        # -------------------------------------------------
        # Flow feature extractor
        # -------------------------------------------------

        self.flow_extractor = FlowFeatureExtractor()

        # -------------------------------------------------
        # Machine Learning detector
        # -------------------------------------------------

        self.network_detector = NetworkDetector(
            model_path=model_path
        )

        # -------------------------------------------------
        # Port scan detector
        # -------------------------------------------------

        self.port_scan_detector = PortScanDetector(
            port_threshold=20,
            time_window_seconds=60
        )

        # -------------------------------------------------
        # Outbound IOC detector
        # -------------------------------------------------

        self.outbound_detector = OutboundDetector()

        # -------------------------------------------------
        # Statistics
        # -------------------------------------------------

        self.packet_count = 0
        self.flow_count = 0
        self.network_ml_alerts = 0
        self.port_scan_alerts = 0
        self.outbound_alerts = 0

        print(
            "[ARGUS] Network detection engine initialized."
        )


    # =====================================================
    # ADD IOC
    # =====================================================

    def add_ioc(self, destination_ip):

        self.outbound_detector.add_ioc(
            destination_ip
        )

        print(
            "[ARGUS] IOC added:",
            destination_ip
        )


    # =====================================================
    # PROCESS NETWORK EVENT
    # =====================================================

    def handle_event(self, event):

        self.packet_count += 1

        source_ip = event.get(
            "source_ip"
        )

        destination_ip = event.get(
            "destination_ip"
        )

        destination_port = event.get(
            "destination_port"
        )


        # =================================================
        # 1. PORT SCAN DETECTION
        # =================================================

        if destination_port is not None:

            port_result = (
                self.port_scan_detector
                .process_connection(

                    source_ip=source_ip,

                    destination_ip=destination_ip,

                    destination_port=destination_port
                )
            )

            if port_result["alert"]:

                self.port_scan_alerts += 1

                print()
                print("=" * 70)
                print("🚨 ARGUS PORT SCAN ALERT")
                print("=" * 70)

                print(
                    "Source IP:",
                    port_result["source_ip"]
                )

                print(
                    "Unique Ports:",
                    port_result["unique_ports"]
                )

                print(
                    "Unique Hosts:",
                    port_result["unique_hosts"]
                )

                print(
                    "Severity:",
                    port_result["severity"]
                )

                print("=" * 70)


        # =================================================
        # 2. SUSPICIOUS OUTBOUND DETECTION
        # =================================================

        if destination_ip is not None:

            outbound_result = (
                self.outbound_detector
                .check_connection(

                    source_ip=source_ip,

                    destination_ip=destination_ip,

                    destination_port=destination_port
                )
            )

            if outbound_result["alert"]:

                self.outbound_alerts += 1

                print()
                print("=" * 70)
                print(
                    "🚨 ARGUS SUSPICIOUS OUTBOUND ALERT"
                )
                print("=" * 70)

                print(
                    "Source IP:",
                    outbound_result["source_ip"]
                )

                print(
                    "Destination IP:",
                    outbound_result["destination_ip"]
                )

                print(
                    "Destination Port:",
                    outbound_result["destination_port"]
                )

                print(
                    "Reason:",
                    outbound_result["reason"]
                )

                print(
                    "Severity:",
                    outbound_result["severity"]
                )

                print("=" * 70)


        # =================================================
        # 3. FLOW FEATURE EXTRACTION
        # =================================================

        features = (
            self.flow_extractor
            .add_packet(event)
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
        # 4. SEND FLOW TO RANDOM FOREST
        # =================================================

        flow_df = pd.DataFrame(
            [features]
        )


        try:

            result = (
                self.network_detector
                .predict(flow_df)
            )[0]

        except Exception as error:

            print()
            print(
                "[ARGUS ERROR] "
                "Network ML prediction failed."
            )

            print(
                "Error:",
                error
            )

            return


        # =================================================
        # 5. DISPLAY ML RESULT
        # =================================================

        print()
        print(
            "[ARGUS NETWORK ML RESULT]"
        )

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


        # =================================================
        # 6. NETWORK ML ALERT
        # =================================================

        if result["prediction"] == "ATTACK":

            self.network_ml_alerts += 1

            print()
            print("=" * 70)
            print("🚨 ARGUS NETWORK ML ALERT")
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

            print(
                "Source:",
                source_ip
            )

            print(
                "Destination:",
                destination_ip
            )

            print(
                "Destination Port:",
                destination_port
            )

            print("=" * 70)


    # =====================================================
    # START NETWORK ENGINE
    # =====================================================

    def start(self, interface=None):

        print()
        print("=" * 70)
        print("ARGUS NETWORK DETECTION ENGINE STARTED")
        print("=" * 70)

        print()
        print("Active detectors:")
        print("  [1] Network ML")
        print("  [2] Port Scanning")
        print("  [3] Suspicious Outbound")
        print()

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

            self.print_summary()


    # =====================================================
    # SUMMARY
    # =====================================================

    def print_summary(self):

        print()
        print("=" * 70)
        print("ARGUS NETWORK DETECTION SUMMARY")
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
            "Network ML alerts:",
            self.network_ml_alerts
        )

        print(
            "Port scan alerts:",
            self.port_scan_alerts
        )

        print(
            "Outbound alerts:",
            self.outbound_alerts
        )

        print("=" * 70)