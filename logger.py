import os
from datetime import datetime, UTC

LOG_FILE = "logs/events.log"


def log_event(event_type, message):
    os.makedirs("logs", exist_ok=True)

    timestamp = datetime.now(UTC).isoformat()

    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(f"[{timestamp}] {event_type}: {message}\n")