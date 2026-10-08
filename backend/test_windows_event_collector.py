from app.detection.windows_event_collector import (
    WindowsEventCollector
)


print("=" * 70)
print("ARGUS WINDOWS EVENT COLLECTOR TEST")
print("=" * 70)


collector = WindowsEventCollector()


events = collector.get_failed_login_events(
    max_events=10
)


print()
print(
    "Failed login events found:",
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


    # Don't print an excessively large event
    print(
        "Message:"
    )

    print(
        message[:3000]
    )


print()
print("=" * 70)
print("WINDOWS EVENT TEST COMPLETE")
print("=" * 70)