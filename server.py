import socket
import threading
import json
import time
import uuid
import base64
import os
from datetime import datetime, UTC

from storage_manager import (
    list_files_for_user,
    save_metadata,
    save_encrypted_file,
    get_file_metadata,
    read_encrypted_file,
    update_file_status
)

HOST = "127.0.0.1"
PORT = 9090


def log_event(event_type, message):
    os.makedirs("logs", exist_ok=True)
    timestamp = datetime.now(UTC).isoformat()

    with open("logs/events.log", "a", encoding="utf-8") as f:
        f.write(f"[{timestamp}] {event_type}: {message}\n")


def generate_nonce():
    return base64.b64encode(os.urandom(16)).decode()


def is_expired(expiration_time):
    expiration = datetime.fromisoformat(expiration_time)
    now = datetime.now()
    return now > expiration


def create_error(message, session_id=None, seq=1):
    return {
        "type": "ERROR",
        "session_id": session_id,
        "seq": seq,
        "timestamp": int(time.time()),
        "nonce": generate_nonce(),
        "payload": {
            "error": message
        }
    }


def create_server_hello():
    return {
        "type": "SERVER_HELLO",
        "session_id": str(uuid.uuid4()),
        "seq": 1,
        "timestamp": int(time.time()),
        "nonce": generate_nonce(),
        "payload": {
            "server_id": "server1",
            "message": "hello from server"
        }
    }


def handle_client(conn, addr):
    print(f"[+] Connected: {addr}")
    log_event("CONNECTION", f"Client connected: {addr}")

    try:
        while True:
            data = conn.recv(8192)

            if not data:
                break

            message_text = data.decode()
            print(f"[CLIENT {addr}] {message_text}")
            log_event("MESSAGE_RECEIVED", f"From {addr}: {message_text}")

            try:
                message = json.loads(message_text)
            except json.JSONDecodeError:
                response = create_error("Invalid JSON format")
                conn.sendall(json.dumps(response).encode())
                continue

            msg_type = message.get("type")

            if msg_type == "CLIENT_HELLO":
                response = create_server_hello()
                conn.sendall(json.dumps(response).encode())

                print(f"[SERVER -> {addr}] SERVER_HELLO sent")
                log_event("SERVER_HELLO", f"SERVER_HELLO sent to {addr}")

            elif msg_type == "LIST_REQUEST":
                user_id = message["payload"]["user_id"]
                files = list_files_for_user(user_id)

                response = {
                    "type": "LIST_RESPONSE",
                    "session_id": message.get("session_id"),
                    "seq": message.get("seq", 0) + 1,
                    "timestamp": int(time.time()),
                    "nonce": generate_nonce(),
                    "payload": {
                        "files": files
                    }
                }

                conn.sendall(json.dumps(response).encode())

                print(f"[SERVER -> {addr}] LIST_RESPONSE sent")
                log_event("LIST_REQUEST", f"{user_id} requested file list")

            elif msg_type == "UPLOAD_REQUEST":
                payload = message["payload"]

                file_id = payload["file_id"]
                sender_id = payload["sender_id"]
                recipient_id = payload["recipient_id"]
                encrypted_file = payload["encrypted_file"]

                save_encrypted_file(file_id, encrypted_file)

                metadata = {
                    "file_id": file_id,
                    "sender_id": sender_id,
                    "recipient_id": recipient_id,
                    "upload_time": payload["upload_time"],
                    "expiration_time": payload["expiration_time"],
                    "status": "pending"
                }

                save_metadata(metadata)

                response = {
                    "type": "UPLOAD_ACK",
                    "session_id": message.get("session_id"),
                    "seq": message.get("seq", 0) + 1,
                    "timestamp": int(time.time()),
                    "nonce": generate_nonce(),
                    "payload": {
                        "message": "File uploaded successfully",
                        "file_id": file_id
                    }
                }

                conn.sendall(json.dumps(response).encode())

                print(f"[SERVER -> {addr}] UPLOAD_ACK sent")
                log_event("UPLOAD", f"{sender_id} uploaded {file_id} for {recipient_id}")

            elif msg_type == "DOWNLOAD_REQUEST":
                payload = message["payload"]

                file_id = payload["file_id"]
                user_id = payload["user_id"]

                metadata = get_file_metadata(file_id)

                if metadata is None:
                    response = create_error(
                        "File not found",
                        session_id=message.get("session_id"),
                        seq=message.get("seq", 0) + 1
                    )
                    conn.sendall(json.dumps(response).encode())
                    log_event("DOWNLOAD_FAILED", f"{user_id} requested missing file {file_id}")
                    continue

                if metadata["recipient_id"] != user_id:
                    response = create_error(
                        "Unauthorized access: this file is not for you",
                        session_id=message.get("session_id"),
                        seq=message.get("seq", 0) + 1
                    )
                    conn.sendall(json.dumps(response).encode())
                    log_event("UNAUTHORIZED_DOWNLOAD", f"{user_id} tried to download {file_id}")
                    continue

                if metadata["status"] == "downloaded":
                    response = create_error(
                        "File already downloaded",
                        session_id=message.get("session_id"),
                        seq=message.get("seq", 0) + 1
                    )
                    conn.sendall(json.dumps(response).encode())
                    log_event("REPEATED_DOWNLOAD", f"{user_id} tried to download already downloaded file {file_id}")
                    continue

                if is_expired(metadata["expiration_time"]):
                    response = create_error(
                        "File expired and cannot be downloaded",
                        session_id=message.get("session_id"),
                        seq=message.get("seq", 0) + 1
                    )
                    conn.sendall(json.dumps(response).encode())
                    log_event("EXPIRED_FILE_ACCESS", f"{user_id} tried to download expired file {file_id}")
                    continue

                encrypted_file = read_encrypted_file(file_id)

                if encrypted_file is None:
                    response = create_error(
                        "Encrypted file content not found",
                        session_id=message.get("session_id"),
                        seq=message.get("seq", 0) + 1
                    )
                    conn.sendall(json.dumps(response).encode())
                    log_event("DOWNLOAD_FAILED", f"Encrypted content missing for {file_id}")
                    continue

                response = {
                    "type": "DOWNLOAD_RESPONSE",
                    "session_id": message.get("session_id"),
                    "seq": message.get("seq", 0) + 1,
                    "timestamp": int(time.time()),
                    "nonce": generate_nonce(),
                    "payload": {
                        "file_id": file_id,
                        "metadata": metadata,
                        "encrypted_file": encrypted_file
                    }
                }

                conn.sendall(json.dumps(response).encode())

                update_file_status(file_id, "downloaded")

                print(f"[SERVER -> {addr}] DOWNLOAD_RESPONSE sent")
                log_event("DOWNLOAD", f"{user_id} downloaded {file_id}")

            else:
                response = create_error(
                    "Unknown message type",
                    session_id=message.get("session_id"),
                    seq=message.get("seq", 0) + 1
                )

                conn.sendall(json.dumps(response).encode())
                log_event("ERROR", f"Unknown message type from {addr}")

    except ConnectionResetError:
        log_event("DISCONNECTION", f"Client disconnected unexpectedly: {addr}")

    finally:
        conn.close()
        print(f"[-] Disconnected: {addr}")
        log_event("DISCONNECTION", f"Client disconnected: {addr}")


def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    server.bind((HOST, PORT))
    server.listen()

    print(f"[SERVER] Listening on {HOST}:{PORT}")
    log_event("SERVER_START", f"Server started on {HOST}:{PORT}")

    while True:
        conn, addr = server.accept()

        thread = threading.Thread(
            target=handle_client,
            args=(conn, addr),
            daemon=True
        )
        thread.start()


if __name__ == "__main__":
    main()