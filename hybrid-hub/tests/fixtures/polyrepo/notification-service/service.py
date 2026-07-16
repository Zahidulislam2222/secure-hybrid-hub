def consume_cancellation(event: dict[str, str]) -> bool:
    return event.get("status") == "cancelled"
