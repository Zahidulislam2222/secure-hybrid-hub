def cancel(appointment_id: str) -> dict[str, str]:
    return {"appointment_id": appointment_id, "status": "cancelled"}
