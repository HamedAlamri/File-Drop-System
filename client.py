import socket
import json
import time
import base64
import os
import uuid
import sys

HOST = "127.0.0.1"
PORT = 9090


def generate_nonce():
    return base64.b64encode(os.urandom(16)).decode()


def fake_encrypt_file_content(text):
    return base64.b64encode(text.encode()).decode()


def send_message(message):
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((HOST, PORT))

    client.sendall(json.dumps(message).encode())

    response = client.recv(8192)

    print("[SERVER RESPONSE]")
    print(json.dumps(json.loads(response.decode()), indent=4))

    client.close()


def upload(sender_id, recipient_id):
    file_id = str(uuid.uuid4())

    message = {
        "type": "UPLOAD_REQUEST",
        "session_id": "test-session",
        "seq": 4,
        "timestamp": int(time.time()),
        "nonce": generate_nonce(),
        "payload": {
            "file_id": file_id,
            "sender_id": sender_id,
            "recipient_id": recipient_id,
            "upload_time": "2026-05-19T10:00:00",
            "expiration_time": "2026-05-25T10:00:00",
            "encrypted_file": fake_encrypt_file_content(
                "This is a test encrypted file"
            )
        }
    }

    send_message(message)


def list_files(user_id):
    message = {
        "type": "LIST_REQUEST",
        "session_id": "test-session",
        "seq": 2,
        "timestamp": int(time.time()),
        "nonce": generate_nonce(),
        "payload": {
            "user_id": user_id
        }
    }

    send_message(message)


def download(file_id, user_id):
    message = {
        "type": "DOWNLOAD_REQUEST",
        "session_id": "test-session",
        "seq": 6,
        "timestamp": int(time.time()),
        "nonce": generate_nonce(),
        "payload": {
            "file_id": file_id,
            "user_id": user_id
        }
    }

    send_message(message)


def hello():
    message = {
        "type": "CLIENT_HELLO",
        "session_id": None,
        "seq": 1,
        "timestamp": int(time.time()),
        "nonce": generate_nonce(),
        "payload": {
            "client_id": "clientA"
        }
    }

    send_message(message)


def print_usage():
    print("Usage:")
    print("  python client.py hello")
    print("  python client.py upload <sender_id> <recipient_id>")
    print("  python client.py list <user_id>")
    print("  python client.py download <file_id> <user_id>")


def main():
    if len(sys.argv) < 2:
        print_usage()
        return

    command = sys.argv[1]

    if command == "hello":
        hello()

    elif command == "upload":
        if len(sys.argv) != 4:
            print("Usage: python client.py upload <sender_id> <recipient_id>")
            return

        sender_id = sys.argv[2]
        recipient_id = sys.argv[3]

        upload(sender_id, recipient_id)

    elif command == "list":
        if len(sys.argv) != 3:
            print("Usage: python client.py list <user_id>")
            return

        user_id = sys.argv[2]

        list_files(user_id)

    elif command == "download":
        if len(sys.argv) != 4:
            print("Usage: python client.py download <file_id> <user_id>")
            return

        file_id = sys.argv[2]
        user_id = sys.argv[3]

        download(file_id, user_id)

    else:
        print("Unknown command")
        print_usage()


if __name__ == "__main__":
    main()