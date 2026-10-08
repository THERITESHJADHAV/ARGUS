from app.detection.sysmon_event_collector import SysmonEventCollector
from app.detection.sysmon_event_parser import SysmonEventParser


def main():

    print("=" * 70)
    print("ARGUS SYSMON EVENT 1 PARSER TEST")
    print("=" * 70)

    collector = SysmonEventCollector()
    parser = SysmonEventParser()

    events = collector.get_process_events(
        max_events=10
    )

    print()
    print("Raw events found:", len(events))
    print()

    for index, event in enumerate(events, start=1):

        parsed = parser.parse(event)

        print("-" * 70)
        print(f"PROCESS EVENT {index}")
        print("-" * 70)

        if parsed is None:
            print("Could not parse event.")
            continue

        print("Event Type:", parsed["event_type"])
        print("Event ID:", parsed["event_id"])
        print("Record ID:", parsed["record_id"])
        print("Timestamp:", parsed["timestamp"])
        print("Process ID:", parsed["process_id"])
        print("Image:", parsed["image"])
        print("Command Line:", parsed["command_line"])
        print("User:", parsed["user"])
        print("Integrity:", parsed["integrity_level"])
        print("SHA256:", parsed["sha256"])
        print("Parent Image:", parsed["parent_image"])
        print("Parent Command:", parsed["parent_command_line"])
        print("Parent User:", parsed["parent_user"])

    print()
    print("=" * 70)
    print("PARSER TEST COMPLETE")
    print("=" * 70)


if __name__ == "__main__":
    main()