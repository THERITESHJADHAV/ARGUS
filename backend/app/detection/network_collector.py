from scapy.all import sniff, IP, TCP, UDP
from datetime import datetime, timezone


class NetworkCollector:

    def __init__(self, callback=None):

        self.callback = callback

        print(
            "[ARGUS] Network collector initialized."
        )

    # ---------------------------------------------------------
    # PROCESS PACKET
    # ---------------------------------------------------------

    def process_packet(self, packet):

        # Ignore packets without an IP layer
        if not packet.haslayer(IP):

            return

        source_ip = packet[IP].src

        destination_ip = packet[IP].dst

        protocol = packet[IP].proto

        source_port = None

        destination_port = None

        tcp_flags = ""

        # -----------------------------------------------------
        # TCP
        # -----------------------------------------------------

        if packet.haslayer(TCP):

            source_port = packet[TCP].sport

            destination_port = packet[TCP].dport

            tcp_flags = str(
                packet[TCP].flags
            )

            protocol_name = "TCP"

        # -----------------------------------------------------
        # UDP
        # -----------------------------------------------------

        elif packet.haslayer(UDP):

            source_port = packet[UDP].sport

            destination_port = packet[UDP].dport

            protocol_name = "UDP"

        # -----------------------------------------------------
        # OTHER IP PROTOCOL
        # -----------------------------------------------------

        else:

            protocol_name = str(protocol)

        # -----------------------------------------------------
        # PACKET SIZE
        # -----------------------------------------------------

        packet_size = len(packet)

        # -----------------------------------------------------
        # CREATE EVENT
        # -----------------------------------------------------

        event = {

            "timestamp":
                datetime.now(
                    timezone.utc
                ).isoformat(),

            "source_ip":
                source_ip,

            "destination_ip":
                destination_ip,

            "source_port":
                source_port,

            "destination_port":
                destination_port,

            "protocol":
                protocol_name,

            "packet_size":
                packet_size,

            "tcp_flags":
                tcp_flags
        }

        # -----------------------------------------------------
        # SEND EVENT TO CALLBACK
        # -----------------------------------------------------

        if self.callback:

            self.callback(event)

        else:

            print(event)

    # ---------------------------------------------------------
    # START CAPTURE
    # ---------------------------------------------------------

    def start(self, interface=None):

        print("=" * 60)

        print(
            "ARGUS LIVE NETWORK COLLECTOR"
        )

        print("=" * 60)

        print(
            "[ARGUS] Starting packet capture..."
        )

        print(
            "[ARGUS] Press CTRL+C to stop."
        )

        print()

        try:

            sniff(
                iface=interface,
                prn=self.process_packet,
                store=False
            )

        except KeyboardInterrupt:

            print()
            print(
                "[ARGUS] Network capture stopped."
            )