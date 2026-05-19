from datetime import datetime
import os

LOG_FILE = "logs/events.log"

def log_event(event_type, message):
    os.makedirs("logs", exist_ok=True)

    timestamp = datetime.utcnow().isoformat()

    with open(LOG_FILE, "a") as f:
        f.write(f"[{timestamp}] {event_type}: {message}\n")