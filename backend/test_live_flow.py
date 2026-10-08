from app.detection.network_collector import NetworkCollector
from app.detection.flow_feature_extractor import (
    FlowFeatureExtractor
)


extractor = FlowFeatureExtractor()


packet_counter = 0


def handle_event(event):

    global packet_counter

    packet_counter += 1

    print(
        f"\n[PACKET {packet_counter}]"
    )

    print(
        event["source_ip"],
        "→",
        event["destination_ip"]
    )

    print(
        event["protocol"],
        event["source_port"],
        "→",
        event["destination_port"]
    )

    print(
        "Size:",
        event["packet_size"]
    )

    features = extractor.add_packet(
        event
    )

    if features is not None:

        print(
            "\n[ARGUS FLOW CREATED]"
        )

        print(
            "Flow duration:",
            features["flow_duration"]
        )

        print(
            "Flow IAT mean:",
            features["flow_iat_mean"]
        )

        print(
            "Forward IAT mean:",
            features["fwd_iat_mean"]
        )

        print(
            "Backward IAT mean:",
            features["bwd_iat_mean"]
        )

        print(
            "Down/Up ratio:",
            features["down_up_ratio"]
        )


collector = NetworkCollector(
    callback=handle_event
)


collector.start()