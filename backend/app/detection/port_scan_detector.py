from collections import defaultdict
from datetime import datetime, timezone


class PortScanDetector:

    def __init__(
        self,
        port_threshold=20,
        time_window_seconds=60
    ):

        self.port_threshold = port_threshold
        self.time_window_seconds = time_window_seconds

        # Store network connections by source IP
        self.connections = defaultdict(list)


    # =====================================================
    # PROCESS NETWORK CONNECTION
    # =====================================================

    def process_connection(
        self,
        source_ip,
        destination_ip,
        destination_port,
        timestamp=None
    ):

        # -------------------------------------------------
        # Timestamp
        # -------------------------------------------------

        if timestamp is None:

            timestamp = datetime.now(
                timezone.utc
            )


        # -------------------------------------------------
        # Store connection
        # -------------------------------------------------

        self.connections[source_ip].append({

            "timestamp": timestamp,

            "destination_ip": destination_ip,

            "destination_port": destination_port

        })


        # -------------------------------------------------
        # Remove old connections
        # -------------------------------------------------

        current_events = []


        for event in self.connections[source_ip]:

            age = (
                timestamp -
                event["timestamp"]
            ).total_seconds()


            if age <= self.time_window_seconds:

                current_events.append(
                    event
                )


        self.connections[source_ip] = (
            current_events
        )


        # -------------------------------------------------
        # Count unique ports
        # -------------------------------------------------

        unique_ports = set(

            event["destination_port"]

            for event in current_events

            if event["destination_port"] is not None

        )


        # -------------------------------------------------
        # Count unique destination hosts
        # -------------------------------------------------

        unique_hosts = set(

            event["destination_ip"]

            for event in current_events

            if event["destination_ip"] is not None

        )


        # -------------------------------------------------
        # Port scan condition
        # -------------------------------------------------

        if len(unique_ports) >= self.port_threshold:

            return {

                "alert": True,

                "alert_type":
                    "Port Scanning",

                "source_ip":
                    source_ip,

                "unique_ports":
                    len(unique_ports),

                "unique_hosts":
                    len(unique_hosts),

                "severity":
                    "HIGH",

                "status":
                    "NEW"

            }


        # -------------------------------------------------
        # No port scan
        # -------------------------------------------------

        return {

            "alert": False,

            "alert_type":
                "Port Scanning",

            "source_ip":
                source_ip,

            "unique_ports":
                len(unique_ports),

            "unique_hosts":
                len(unique_hosts)

        }