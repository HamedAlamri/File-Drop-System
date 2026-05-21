import os
import json
from datetime import datetime, timezone

STORAGE_DIR = "storage"
FILES_DIR = os.path.join(STORAGE_DIR, "files")
METADATA_FILE = os.path.join(STORAGE_DIR, "metadata.json")


def init_storage():
    os.makedirs(FILES_DIR, exist_ok=True)

    if not os.path.exists(METADATA_FILE):
        with open(METADATA_FILE, "w", encoding="utf-8") as f:
            json.dump([], f, indent=4)

def list_all_metadata():
    return load_metadata()

def load_metadata():
    init_storage()

    with open(METADATA_FILE, "r", encoding="utf-8") as f:
        data = json.load(f)

    cleaned_data = []

    for item in data:
        if isinstance(item, dict):
            cleaned_data.append(item)

        elif isinstance(item, list):
            for sub_item in item:
                if isinstance(sub_item, dict):
                    cleaned_data.append(sub_item)

    return cleaned_data


def save_all_metadata(data):
    init_storage()

    with open(METADATA_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4)


def save_metadata(record):
    data = load_metadata()
    data.append(record)
    save_all_metadata(data)


def list_files_for_user(user_id):
    data = load_metadata()
    updated = False

    for item in data:
        expiration_time = item.get("expiration_time")

        if not expiration_time:
            continue

        try:
            expiration = datetime.fromisoformat(expiration_time)

            if expiration.tzinfo is None:
                now = datetime.now()
            else:
                now = datetime.now(timezone.utc)

        except ValueError:
            continue

        if now > expiration and item.get("status") == "pending":
            item["status"] = "expired"
            updated = True

    if updated:
        save_all_metadata(data)

    return [
        item for item in data
        if item.get("recipient_id") == user_id
    ]


def get_file_metadata(file_id):
    data = load_metadata()

    for item in data:
        if item.get("file_id") == file_id:
            return item

    return None


def update_file_status(file_id, new_status):
    data = load_metadata()

    for item in data:
        if item.get("file_id") == file_id:
            item["status"] = new_status
            save_all_metadata(data)
            return True

    return False


def save_encrypted_file(file_id, encrypted_data_base64):
    init_storage()

    file_path = os.path.join(FILES_DIR, f"{file_id}.enc")

    with open(file_path, "w", encoding="utf-8") as f:
        f.write(encrypted_data_base64)

    return file_path


def read_encrypted_file(file_id):
    file_path = os.path.join(FILES_DIR, f"{file_id}.enc")

    if not os.path.exists(file_path):
        return None

    with open(file_path, "r", encoding="utf-8") as f:
        return f.read()