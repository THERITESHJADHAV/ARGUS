from app.detection.network_collector import NetworkCollector


def handle_event(event):

    print("\n[ARGUS NETWORK EVENT]")

    print("Source IP:",
          event["source_ip"])

    print("Destination IP:",
          event["destination_ip"])

    print("Source Port:",
          event["source_port"])

    print("Destination Port:",
          event["destination_port"])

    print("Protocol:",
          event["protocol"])

    print("Packet Size:",
          event["packet_size"])

    print("Timestamp:",
          event["timestamp"])


collector = NetworkCollector(
    callback=handle_event
)

collector.start()