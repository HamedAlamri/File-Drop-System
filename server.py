import socket
import threading
import json
import time
import uuid
import base64
import os
from datetime import datetime

from logger import log_event, log_admin_debug
from crypto_utils import (
    verify_signature,
    sign_message,
    generate_ecdh_keypair,
    compute_ecdh_shared_secret,
    derive_session_keys
)

from cert_manager import verify_certificate_json, load_certificate, certificate_to_json

from protocol import (
    CLIENT_HELLO,
    SERVER_HELLO,
    UPLOAD_REQUEST,
    UPLOAD_ACK,
    LIST_REQUEST,
    LIST_RESPONSE,
    DOWNLOAD_REQUEST,
    DOWNLOAD_RESPONSE,
    ERROR
)

from storage_manager import (
    save_encrypted_file,
    read_encrypted_file,
    save_metadata,
    get_file_metadata,
    list_files_for_user,
    update_file_status,
)

HOST = "127.0.0.1"
PORT = 9090
USED_NONCES = set()
MAX_TIME_DIFF = 300


def generate_nonce():
    return base64.b64encode(os.urandom(16)).decode()

def validate_freshness(message):
    nonce = message.get("nonce")
    timestamp = message.get("timestamp")

    if nonce is None or timestamp is None:
        return False, "Missing nonce or timestamp"

    if nonce in USED_NONCES:
        return False, "Replay detected: nonce already used"

    now = int(time.time())

    if abs(now - int(timestamp)) > MAX_TIME_DIFF:
        return False, "Replay detected: timestamp too old or invalid"

    USED_NONCES.add(nonce)

    return True, "Fresh request"

def is_expired(expiration_time):
    expiration = datetime.fromisoformat(expiration_time)
    now = datetime.now()
    return now > expiration


def create_error(message, session_id=None, seq=1):
    return {
        "type": ERROR,
        "session_id": session_id,
        "seq": seq,
        "timestamp": int(time.time()),
        "nonce": generate_nonce(),
        "payload": {
            "error": message
        }
    }


def create_server_hello(client_nonce, client_ecdh_public_key_b64):
    server_certificate = load_certificate("server")
    server_private_key = load_server_private_key()

    server_ecdh_private_key, server_ecdh_public_key = generate_ecdh_keypair()

    client_ecdh_public_key = base64.b64decode(client_ecdh_public_key_b64)

    shared_secret = compute_ecdh_shared_secret(
        server_ecdh_private_key,
        client_ecdh_public_key
    )

    session_keys = derive_session_keys(shared_secret)

    print("[ECDH + HKDF] Shared secret established")
    print("[ECDH + HKDF] Session keys derived")

    server_signature = sign_message(
        server_private_key,
        client_nonce.encode()
    )

    return {
        "type": SERVER_HELLO,
        "session_id": str(uuid.uuid4()),
        "seq": 1,
        "timestamp": int(time.time()),
        "nonce": generate_nonce(),
        "payload": {
            "server_id": "server",
            "server_certificate": certificate_to_json(server_certificate),
            "server_signature": base64.b64encode(server_signature).decode(),
            "server_ecdh_public_key": base64.b64encode(
                server_ecdh_public_key
            ).decode()
        }
    }


def send_json(conn, response):
    conn.sendall(json.dumps(response).encode())


def build_signature_data(
    file_id,
    sender_id,
    recipient_id,
    expiration_time,
    encrypted_file,
    wrapped_file_key
):
    data = {
        "file_id": file_id,
        "sender_id": sender_id,
        "recipient_id": recipient_id,
        "expiration_time": expiration_time,
        "encrypted_file": encrypted_file,
        "wrapped_file_key": wrapped_file_key
    }

    return json.dumps(data, sort_keys=True).encode()

def load_server_private_key():
    key_path = "keys/server_private.pem"

    if not os.path.exists(key_path):
        raise FileNotFoundError(
            "Server private key not found. Run: python client.py setup-server"
        )

    with open(key_path, "rb") as f:
        return f.read()

def short_file_id(file_id):
    if not file_id:
        return "N/A"
    return file_id[:8] + "..."


def print_server_event(event, message):
    print(f"[{event}] {message}")


def log_safe_message(message, addr):
    msg_type = message.get("type")
    payload = message.get("payload", {})

    if msg_type == CLIENT_HELLO:
        user = payload.get("client_id", "unknown")
        print_server_event("HANDSHAKE", f"user={user} from={addr}")

    elif msg_type == UPLOAD_REQUEST:

        print_server_event(
            "UPLOAD_REQUEST",
            f"file={short_file_id(payload.get('file_id'))} "
            f"sender={payload.get('sender_id')} "
            f"recipient={payload.get('recipient_id')}"
        )

    elif msg_type == LIST_REQUEST:
        print_server_event(
            "LIST_REQUEST",
            f"user={payload.get('user_id')}"
        )

    elif msg_type == DOWNLOAD_REQUEST:
        print_server_event(
            "DOWNLOAD_REQUEST",
            f"file={short_file_id(payload.get('file_id'))} "
            f"user={payload.get('user_id')}"
        )

    else:
        print_server_event("MESSAGE", f"type={msg_type} from={addr}")

def handle_client(conn, addr):
    print_server_event("CONNECT", f"{addr}")
    log_event("CONNECTION", f"Client connected: {addr}")
    authenticated_user = None

    try:
        while True:
            data = conn.recv(16384)

            if not data:
                break

            message_text = data.decode()

            try:
                message = json.loads(message_text)
            except json.JSONDecodeError:
                send_json(conn, create_error("Invalid JSON format"))
                continue

            log_safe_message(message, addr)
            log_event("MESSAGE_RECEIVED", f"type={message.get('type')} from={addr}")
            log_admin_debug("RAW_MESSAGE", message_text)

            msg_type = message.get("type")
            is_fresh, freshness_message = validate_freshness(message)

            if not is_fresh:
                send_json(
                    conn,
                    create_error(
                        freshness_message,
                        session_id=message.get("session_id"),
                        seq=message.get("seq", 0) + 1
                    )
                )

                log_event(
                    "REPLAY_DETECTED",
                    f"{freshness_message} from {addr}"
                )

                continue

            if msg_type == CLIENT_HELLO:
                client_id = message["payload"]["client_id"]
                client_certificate = message["payload"].get("client_certificate")

                if client_certificate is None:
                    send_json(
                        conn,
                        create_error(
                            "Missing client certificate",
                            session_id=message.get("session_id"),
                            seq=message.get("seq", 0) + 1
                        )
                    )
                    log_event("CLIENT_CERTIFICATE_FAILED", f"Missing certificate from {client_id}")
                    continue

                if not verify_certificate_json(client_certificate):
                    send_json(
                        conn,
                        create_error(
                            "Invalid client certificate",
                            session_id=message.get("session_id"),
                            seq=message.get("seq", 0) + 1
                        )
                    )
                    log_event("CLIENT_CERTIFICATE_FAILED", f"Invalid certificate from {client_id}")
                    continue

                if client_certificate.get("subject") != client_id:
                    send_json(
                        conn,
                        create_error(
                            "Client certificate subject mismatch",
                            session_id=message.get("session_id"),
                            seq=message.get("seq", 0) + 1
                        )
                    )
                    log_event(
                        "CLIENT_CERTIFICATE_FAILED",
                        f"Certificate subject does not match client_id {client_id}"
                    )
                    continue

                print(f"[CLIENT CERTIFICATE] Valid certificate for {client_id}")
                log_event("CLIENT_CERTIFICATE_OK", f"Valid certificate for {client_id}")

                client_signature_b64 = message["payload"].get("client_signature")

                if client_signature_b64 is None:
                    send_json(
                        conn,
                        create_error(
                            "Missing client proof-of-possession signature",
                            session_id=message.get("session_id"),
                            seq=message.get("seq", 0) + 1
                        )
                    )
                    log_event("CLIENT_PROOF_FAILED", f"Missing proof-of-possession from {client_id}")
                    continue

                client_public_key = base64.b64decode(client_certificate["public_key"])
                client_signature = base64.b64decode(client_signature_b64)
                client_nonce = message["payload"]["client_nonce"]

                if not verify_signature(
                    client_public_key,
                    client_nonce.encode(),
                    client_signature
                ):
                    send_json(
                        conn,
                        create_error(
                            "Invalid client proof-of-possession signature",
                            session_id=message.get("session_id"),
                            seq=message.get("seq", 0) + 1
                        )
                    )
                    log_event("CLIENT_PROOF_FAILED", f"Invalid proof-of-possession from {client_id}")
                    continue

                print(f"[CLIENT PROOF] {client_id} owns the private key")
                log_event("CLIENT_PROOF_OK", f"{client_id} proved private key possession")
                authenticated_user = client_id

                client_ecdh_public_key = message["payload"]["client_ecdh_public_key"]

                response = create_server_hello(
                    client_nonce,
                    client_ecdh_public_key
                )

                send_json(conn, response)

                print(f"[SERVER -> {addr}] SERVER_HELLO sent")
                log_event("SERVER_HELLO", f"SERVER_HELLO sent to {addr}")

            elif msg_type == LIST_REQUEST:
                user_id = message["payload"]["user_id"]
                if authenticated_user != user_id:
                    send_json(
                        conn,
                        create_error(
                            "Authenticated user does not match requested user",
                            session_id=message.get("session_id"),
                            seq=message.get("seq", 0) + 1
                        )
                    )
                    log_event(
                        "AUTHORIZATION_FAILED",
                        f"authenticated_user={authenticated_user} tried LIST as user_id={user_id}"
                    )
                    continue

                files = list_files_for_user(user_id)

                response = {
                    "type": LIST_RESPONSE,
                    "session_id": message.get("session_id"),
                    "seq": message.get("seq", 0) + 1,
                    "timestamp": int(time.time()),
                    "nonce": generate_nonce(),
                    "payload": {
                        "files": files
                    }
                }

                send_json(conn, response)

                print(f"[SERVER -> {addr}] LIST_RESPONSE sent")
                log_event("LIST_REQUEST", f"{user_id} requested file list")

            elif msg_type == UPLOAD_REQUEST:
                payload = message["payload"]

                file_id = payload["file_id"]
                sender_id = payload["sender_id"]
                if authenticated_user != sender_id:
                    send_json(
                        conn,
                        create_error(
                            "Authenticated user does not match sender",
                            session_id=message.get("session_id"),
                            seq=message.get("seq", 0) + 1
                        )
                    )
                    log_event(
                        "AUTHORIZATION_FAILED",
                        f"authenticated_user={authenticated_user} tried UPLOAD as sender_id={sender_id}"
                    )
                    continue

                recipient_id = payload["recipient_id"]
                encrypted_file = payload["encrypted_file"]
                wrapped_file_key = payload["wrapped_file_key"]

                sender_certificate = payload.get("sender_certificate")

                if sender_certificate is None:
                    send_json(
                        conn,
                        create_error(
                            "Missing sender certificate",
                            session_id=message.get("session_id"),
                            seq=message.get("seq", 0) + 1
                        )
                    )
                    log_event("CERTIFICATE_FAILED", f"Missing certificate from {sender_id}")
                    continue

                if not verify_certificate_json(sender_certificate):
                    send_json(
                        conn,
                        create_error(
                            "Invalid sender certificate",
                            session_id=message.get("session_id"),
                            seq=message.get("seq", 0) + 1
                        )
                    )
                    log_event("CERTIFICATE_FAILED", f"Invalid certificate from {sender_id}")
                    continue

                certificate_subject = sender_certificate.get("subject")
                if certificate_subject != sender_id:
                    send_json(
                        conn,
                        create_error(
                            "Certificate subject does not match sender",
                            session_id=message.get("session_id"),
                            seq=message.get("seq", 0) + 1
                        )
                    )
                    log_event(
                        "CERTIFICATE_FAILED",
                        f"Certificate subject {certificate_subject} does not match sender {sender_id}"
                    )
                    continue

                sender_public_key_from_cert = sender_certificate.get("public_key")
                sender_public_key = base64.b64decode(payload["sender_public_key"])

                if sender_public_key_from_cert != payload["sender_public_key"]:
                    send_json(
                        conn,
                        create_error(
                            "Sender public key does not match certificate",
                            session_id=message.get("session_id"),
                            seq=message.get("seq", 0) + 1
                        )
                    )
                    log_event(
                        "CERTIFICATE_FAILED",
                        f"Public key mismatch for sender {sender_id}"
                    )
                    continue

                signature = base64.b64decode(payload["signature"])

                signature_data = build_signature_data(
                    file_id,
                    sender_id,
                    recipient_id,
                    payload["expiration_time"],
                    encrypted_file,
                    wrapped_file_key
                )

                if not verify_signature(sender_public_key, signature_data, signature):
                    send_json(
                        conn,
                        create_error(
                            "Invalid digital signature",
                            session_id=message.get("session_id"),
                            seq=message.get("seq", 0) + 1
                        )
                    )
                    log_event("SIGNATURE_FAILED", f"Invalid signature from {sender_id}")
                    continue

                save_encrypted_file(file_id, encrypted_file)

                metadata = {
                    "file_id": file_id,
                    "sender_id": sender_id,
                    "recipient_id": recipient_id,
                    "upload_time": payload["upload_time"],
                    "expiration_time": payload["expiration_time"],
                    "filename": payload.get("filename", "downloaded_file.bin"),
                    "file_size": payload.get("file_size", 0),
                    "status": "pending",
                    "wrapped_file_key": wrapped_file_key,
                    "sender_public_key": payload.get("sender_public_key"),
                    "signature": payload.get("signature"),
                    "sender_certificate": sender_certificate
                }

                save_metadata(metadata)

                response = {
                    "type": UPLOAD_ACK,
                    "session_id": message.get("session_id"),
                    "seq": message.get("seq", 0) + 1,
                    "timestamp": int(time.time()),
                    "nonce": generate_nonce(),
                    "payload": {
                        "message": "File uploaded successfully",
                        "file_id": file_id
                    }
                }

                send_json(conn, response)

                print(f"[SERVER -> {addr}] UPLOAD_ACK sent")
                log_event(
                    "UPLOAD",
                    f"{sender_id} uploaded {file_id} for {recipient_id}"
                )

            elif msg_type == DOWNLOAD_REQUEST:
                payload = message["payload"]

                file_id = payload["file_id"]
                user_id = payload["user_id"]
                if authenticated_user != user_id:
                    send_json(
                        conn,
                        create_error(
                            "Authenticated user does not match download user",
                            session_id=message.get("session_id"),
                            seq=message.get("seq", 0) + 1
                        )
                    )
                    log_event(
                        "AUTHORIZATION_FAILED",
                        f"authenticated_user={authenticated_user} tried DOWNLOAD as user_id={user_id}"
                    )
                    continue

                metadata = get_file_metadata(file_id)

                if metadata is None:
                    send_json(
                        conn,
                        create_error(
                            "File not found",
                            session_id=message.get("session_id"),
                            seq=message.get("seq", 0) + 1
                        )
                    )
                    log_event(
                        "DOWNLOAD_FAILED",
                        f"{user_id} requested missing file {file_id}"
                    )
                    continue

                if metadata["recipient_id"] != user_id:
                    send_json(
                        conn,
                        create_error(
                            "Unauthorized access: this file is not for you",
                            session_id=message.get("session_id"),
                            seq=message.get("seq", 0) + 1
                        )
                    )
                    log_event(
                        "UNAUTHORIZED_DOWNLOAD",
                        f"{user_id} tried to download {file_id}"
                    )
                    print(
                        f"[DOWNLOAD_REJECTED] "
                        f"file={file_id[:8]}... "
                        f"user={user_id} "
                        f"reason=unauthorized"
                    )
                    continue

                if metadata["status"] == "downloaded":
                    send_json(
                        conn,
                        create_error(
                            "File already downloaded",
                            session_id=message.get("session_id"),
                            seq=message.get("seq", 0) + 1
                        )
                    )
                    log_event(
                        "REPEATED_DOWNLOAD",
                        f"{user_id} tried to download already downloaded file {file_id}"
                    )
                    print(
                        f"[DOWNLOAD_REJECTED] "
                        f"file={file_id[:8]}... "
                        f"user={user_id} "
                        f"reason=already_downloaded"
                    )
                    continue

                if metadata["status"] == "expired" or is_expired(metadata["expiration_time"]):
                    send_json(
                        conn,
                        create_error(
                            "File expired and cannot be downloaded",
                            session_id=message.get("session_id"),
                            seq=message.get("seq", 0) + 1
                        )
                    )
                    log_event(
                        "EXPIRED_FILE_ACCESS",
                        f"{user_id} tried to download expired file {file_id}"
                    )
                    print(
                        f"[DOWNLOAD_REJECTED] "
                        f"file={file_id[:8]}... "
                        f"user={user_id} "
                        f"reason=expired"
                    )
                    continue

                encrypted_file = read_encrypted_file(file_id)

                if encrypted_file is None:
                    send_json(
                        conn,
                        create_error(
                            "Encrypted file content not found",
                            session_id=message.get("session_id"),
                            seq=message.get("seq", 0) + 1
                        )
                    )
                    log_event(
                        "DOWNLOAD_FAILED",
                        f"Encrypted content missing for {file_id}"
                    )
                    print(
                        f"[DOWNLOAD_REJECTED] "
                        f"file={file_id[:8]}... "
                        f"user={user_id} "
                        f"reason=file_not_found"
                    )
                    continue

                response = {
                    "type": DOWNLOAD_RESPONSE,
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

                send_json(conn, response)

                update_file_status(file_id, "downloaded")

                print(f"[SERVER -> {addr}] DOWNLOAD_RESPONSE sent")
                log_event("DOWNLOAD", f"{user_id} downloaded {file_id}")

            else:
                send_json(
                    conn,
                    create_error(
                        "Unknown message type",
                        session_id=message.get("session_id"),
                        seq=message.get("seq", 0) + 1
                    )
                )
                log_event("ERROR", f"Unknown message type from {addr}")

    except ConnectionResetError:
        log_event("DISCONNECTION", f"Client disconnected unexpectedly: {addr}")

    finally:
        conn.close()
        print_server_event("DISCONNECT", f"{addr}")
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