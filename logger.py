import os
from datetime import datetime, timezone

LOG_DIR = "logs"
EVENT_LOG_FILE = os.path.join(LOG_DIR, "events.log")
ADMIN_DEBUG_LOG_FILE = os.path.join(LOG_DIR, "admin_debug.log")

DEBUG_MODE = True


def ensure_log_dir():
    os.makedirs(LOG_DIR, exist_ok=True)


def log_event(event_type, message):
    ensure_log_dir()

    timestamp = datetime.now(timezone.utc).isoformat()

    with open(EVENT_LOG_FILE, "a", encoding="utf-8") as f:
        f.write(f"[{timestamp}] {event_type}: {message}\n")

def log_admin_debug(event_type, message):
    if not DEBUG_MODE:
        return

    ensure_log_dir()

    timestamp = datetime.now(timezone.utc).isoformat()

    with open(ADMIN_DEBUG_LOG_FILE, "a", encoding="utf-8") as f:
        f.write(f"[{timestamp}] {event_type}: {message}\n")