from app.detection.sysmon_event_collector import (
    SysmonEventCollector
)


print("=" * 70)
print("ARGUS SYSMON EVENT COLLECTOR TEST")
print("=" * 70)


collector = SysmonEventCollector()


events = collector.get_process_events(
    max_events=10
)


print()
print(
    "Process events found:",
    len(events)
)


for index, event in enumerate(
    events,
    start=1
):

    print()
    print(
        f"========== EVENT {index} =========="
    )

    print(
        "Record ID:",
        event.get("RecordId")
    )

    print(
        "Time:",
        event.get("TimeCreated")
    )

    print(
        "Event ID:",
        event.get("Id")
    )

    message = event.get(
        "Message",
        ""
    )

    print(
        "Message:"
    )

    print(
        message[:3000]
    )


print()
print("=" * 70)
print("SYSMON EVENT TEST COMPLETE")
print("=" * 70)