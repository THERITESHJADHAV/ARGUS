from datetime import datetime, timezone


class OutboundDetector:

    def __init__(self):

        # -------------------------------------------------
        # IOC destination collection
        # -------------------------------------------------

        self.blocked_destinations = set()


    # =====================================================
    # ADD IOC
    # =====================================================

    def add_ioc(self, destination):

        if destination is None:
            return

        self.blocked_destinations.add(
            destination
        )


    # =====================================================
    # CHECK NETWORK CONNECTION
    # =====================================================

    def check_connection(
        self,
        source_ip,
        destination_ip,
        destination_port,
        process_name=None
    ):

        timestamp = datetime.now(
            timezone.utc
        ).isoformat()


        # -------------------------------------------------
        # Check whether destination is in IOC list
        # -------------------------------------------------

        if destination_ip in self.blocked_destinations:

            return {

                "alert": True,

                "alert_type":
                    "Suspicious Outbound Connection",

                "severity":
                    "HIGH",

                "source_ip":
                    source_ip,

                "destination_ip":
                    destination_ip,

                "destination_port":
                    destination_port,

                "process_name":
                    process_name,

                "reason":
                    "Destination matched IOC",

                "timestamp":
                    timestamp,

                "status":
                    "NEW"
            }


        # -------------------------------------------------
        # No IOC match
        # -------------------------------------------------

        return {

            "alert": False,

            "alert_type":
                "Suspicious Outbound Connection",

            "source_ip":
                source_ip,

            "destination_ip":
                destination_ip,

            "destination_port":
                destination_port,

            "process_name":
                process_name,

            "status":
                "NORMAL",

            "timestamp":
                timestamp
        }