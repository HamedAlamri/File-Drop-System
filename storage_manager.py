import os
import json

STORAGE_DIR = "storage"
FILES_DIR = os.path.join(STORAGE_DIR, "files")
METADATA_FILE = os.path.join(STORAGE_DIR, "metadata.json")


def init_storage():
    os.makedirs(FILES_DIR, exist_ok=True)

    if not os.path.exists(METADATA_FILE):
        with open(METADATA_FILE, "w", encoding="utf-8") as f:
            json.dump([], f, indent=4)


def load_metadata():
    init_storage()

    with open(METADATA_FILE, "r", encoding="utf-8") as f:
        return json.load(f)


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

    return [
        item for item in data
        if item.get("recipient_id") == user_id
        and item.get("status") == "pending"
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