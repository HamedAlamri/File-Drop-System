import socket
import json
import time
import base64
import os
import uuid
import sys
import re

from datetime import datetime, timedelta

from crypto_utils import (
    aes_gcm_encrypt,
    aes_gcm_decrypt,
    rsa_encrypt,
    rsa_decrypt,
    generate_rsa_keypair,
    sign_message,
    verify_signature,
    generate_ecdh_keypair,
    compute_ecdh_shared_secret,
    derive_session_keys
)

from cert_manager import (
    ensure_certificate,
    certificate_to_json,
    verify_certificate_json
)

HOST = "127.0.0.1"
PORT = 9090
DOWNLOADS_DIR = "downloads"
KEYS_DIR = "keys"
SESSION = {
    "socket": None,
    "user_id": None,
    "session_id": None,
    "active": False
}

def ensure_downloads_dir():
    os.makedirs(DOWNLOADS_DIR, exist_ok=True)


def read_file_bytes(file_path):
    with open(file_path, "rb") as f:
        return f.read()


def safe_filename(filename):
    return os.path.basename(filename)


def save_downloaded_file(filename, data):
    ensure_downloads_dir()

    filename = safe_filename(filename)
    output_path = os.path.join(DOWNLOADS_DIR, filename)

    with open(output_path, "wb") as f:
        f.write(data)

    return output_path


def ensure_keys_dir():
    os.makedirs(KEYS_DIR, exist_ok=True)


def generate_nonce():
    return base64.b64encode(os.urandom(16)).decode()

def is_valid_user_id(user_id):
    return re.match(r"^[A-Za-z0-9_]+$", user_id) is not None

def get_private_key_path(user_id):
    return os.path.join(KEYS_DIR, f"{user_id}_private.pem")


def get_public_key_path(user_id):
    return os.path.join(KEYS_DIR, f"{user_id}_public.pem")


def ensure_user_keys(user_id):
    ensure_keys_dir()

    private_path = get_private_key_path(user_id)
    public_path = get_public_key_path(user_id)

    if not os.path.exists(private_path) or not os.path.exists(public_path):
        private_key, public_key = generate_rsa_keypair()

        with open(private_path, "wb") as f:
            f.write(private_key)

        with open(public_path, "wb") as f:
            f.write(public_key)

        print(f"[KEYGEN] Generated RSA keys for {user_id}")

    with open(private_path, "rb") as f:
        private_key = f.read()

    with open(public_path, "rb") as f:
        public_key = f.read()

    return private_key, public_key


def load_public_key(user_id):
    ensure_user_keys(user_id)

    with open(get_public_key_path(user_id), "rb") as f:
        return f.read()


def load_private_key(user_id):
    ensure_user_keys(user_id)

    with open(get_private_key_path(user_id), "rb") as f:
        return f.read()


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


def encrypt_file_for_recipient(file_bytes, recipient_id):
    file_key = os.urandom(32)

    encrypted_file = aes_gcm_encrypt(
        file_key,
        file_bytes
    )

    recipient_public_key = load_public_key(recipient_id)

    wrapped_file_key = rsa_encrypt(
        recipient_public_key,
        file_key
    )

    return {
        "encrypted_file": base64.b64encode(encrypted_file).decode(),
        "wrapped_file_key": base64.b64encode(wrapped_file_key).decode()
    }


def decrypt_downloaded_file(payload, user_id):
    metadata = payload["metadata"]

    wrapped_file_key_b64 = metadata.get("wrapped_file_key")
    encrypted_file_b64 = payload.get("encrypted_file")

    if not wrapped_file_key_b64:
        print("\n[DECRYPTION FAILED] wrapped_file_key not found")
        return

    if not encrypted_file_b64:
        print("\n[DECRYPTION FAILED] encrypted_file not found")
        return

    user_private_key = load_private_key(user_id)

    wrapped_file_key = base64.b64decode(wrapped_file_key_b64)
    encrypted_file = base64.b64decode(encrypted_file_b64)

    try:
        file_key = rsa_decrypt(user_private_key, wrapped_file_key)
        plaintext = aes_gcm_decrypt(file_key, encrypted_file)

        filename = metadata.get("filename", f"downloaded_{metadata['file_id']}.bin")
        output_path = save_downloaded_file(filename, plaintext)

        print("\n[DECRYPTION]")
        print("File decrypted successfully ✅")
        print(f"Saved to: {output_path}")

        verify_download_signature(payload)

    except Exception as e:
        print("\n[DECRYPTION FAILED]")
        print(str(e))


def verify_download_signature(payload):
    metadata = payload["metadata"]

    sender_public_key_b64 = metadata.get("sender_public_key")
    signature_b64 = metadata.get("signature")

    if not sender_public_key_b64 or not signature_b64:
        print("\n[SIGNATURE CHECK] Missing signature or sender public key")
        return

    sender_public_key = base64.b64decode(sender_public_key_b64)
    signature = base64.b64decode(signature_b64)

    signature_data = build_signature_data(
        metadata["file_id"],
        metadata["sender_id"],
        metadata["recipient_id"],
        metadata["expiration_time"],
        payload["encrypted_file"],
        metadata["wrapped_file_key"]
    )

    if verify_signature(sender_public_key, signature_data, signature):
        print("\n[SIGNATURE CHECK]")
        print("Valid sender signature ✅")
    else:
        print("\n[SIGNATURE CHECK]")
        print("Invalid sender signature ❌")

def revoke_file(file_id, user_id):
    perform_handshake(user_id)

    message = {
        "type": "REVOKE_REQUEST",
        "session_id": "test-session",
        "seq": 8,
        "timestamp": int(time.time()),
        "nonce": generate_nonce(),
        "payload": {
            "file_id": file_id,
            "user_id": user_id
        }
    }

    send_message(message)

def send_message(message, client_ecdh_private_key=None, keep_open=False):
    use_existing_session = SESSION["active"] and SESSION["socket"] is not None

    client = SESSION["socket"] if use_existing_session else socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    if not use_existing_session:
        client.connect((HOST, PORT))

    client.sendall(json.dumps(message).encode())

    response = client.recv(65536)
    decoded_response = json.loads(response.decode())

    if decoded_response.get("type") == "SERVER_HELLO":
        SESSION["session_id"] = decoded_response.get("session_id")

        server_cert = decoded_response["payload"].get("server_certificate")

        if server_cert and verify_certificate_json(server_cert):
            print("[SERVER CERTIFICATE] Valid ✅")
        else:
            print("[SERVER CERTIFICATE] Invalid ❌")
            client.close()
            SESSION["active"] = False
            raise Exception("Server authentication failed: invalid server certificate")

        server_signature_b64 = decoded_response["payload"].get("server_signature")

        if server_signature_b64:
            server_public_key = base64.b64decode(server_cert["public_key"])
            server_signature = base64.b64decode(server_signature_b64)
            original_client_nonce = message["payload"]["client_nonce"]

            if verify_signature(
                server_public_key,
                original_client_nonce.encode(),
                server_signature
            ):
                print("[SERVER PROOF] Valid ✅")
            else:
                print("[SERVER PROOF] Invalid ❌")
                client.close()
                SESSION["active"] = False
                raise Exception("Server authentication failed: invalid server proof")

        server_ecdh_public_key_b64 = decoded_response["payload"].get(
            "server_ecdh_public_key"
        )

        if client_ecdh_private_key and server_ecdh_public_key_b64:
            server_ecdh_public_key = base64.b64decode(server_ecdh_public_key_b64)

            shared_secret = compute_ecdh_shared_secret(
                client_ecdh_private_key,
                server_ecdh_public_key
            )

            derive_session_keys(shared_secret)

            print("[ECDH + HKDF] Session keys derived ✅")

    elif decoded_response.get("type") == "DOWNLOAD_RESPONSE":
        print("[DOWNLOAD] File received ✅")
        user_id = message["payload"]["user_id"]
        decrypt_downloaded_file(decoded_response["payload"], user_id)

    elif decoded_response.get("type") == "UPLOAD_ACK":
        print("[UPLOAD] File uploaded successfully ✅")
        print(f"File ID: {decoded_response['payload']['file_id']}")

    elif decoded_response.get("type") == "REVOKE_ACK":
        print("[REVOKE] File revoked successfully ✅")
        print(f"File ID: {decoded_response['payload']['file_id']}")

    elif decoded_response.get("type") == "LIST_RESPONSE":
        files = decoded_response["payload"]["files"]

        if not files:
            print("[LIST] No pending files.")
        else:
            print("[LIST] My files:")
            for f in files:
                print(
                    f"- File ID: {f['file_id']} | "
                    f"Name: {f.get('filename', 'unknown')} | "
                    f"From: {f['sender_id']} | "
                    f"Status: {f['status']} | "
                    f"Expires: {f['expiration_time']}"
                )

    elif decoded_response.get("type") == "ERROR":
        print(f"[ERROR] {decoded_response['payload']['error']}")

    else:
        print("[SERVER RESPONSE]")
        print(json.dumps(decoded_response, indent=4))

    if keep_open:
        SESSION["socket"] = client
        SESSION["active"] = True
    elif not use_existing_session:
        client.close()

    return decoded_response


def hello():
    perform_handshake("clientA")

    client_id = "clientA"
    
    client_private_key, client_public_key = ensure_user_keys(client_id)
    client_certificate = ensure_certificate(client_id, client_public_key)

    client_nonce = generate_nonce()
    client_ecdh_private_key, client_ecdh_public_key = generate_ecdh_keypair()

    message = {
        "type": "CLIENT_HELLO",
        "session_id": None,
        "seq": 1,
        "timestamp": int(time.time()),
        "nonce": client_nonce,
        "payload": {
            "client_id": client_id,
            "client_nonce": client_nonce,
            "client_certificate": certificate_to_json(client_certificate),
            "client_ecdh_public_key": base64.b64encode(
                client_ecdh_public_key
            ).decode()
        }
    }

    send_message(message, client_ecdh_private_key)

def perform_handshake(user_id):
    if SESSION["active"] and SESSION["user_id"] == user_id:
        return

    print(f"\n[HANDSHAKE] Starting secure handshake for {user_id}...")

    client_private_key, client_public_key = ensure_user_keys(user_id)
    client_certificate = ensure_certificate(user_id, client_public_key)

    client_nonce = generate_nonce()
    client_signature = sign_message(
        client_private_key,
        client_nonce.encode()
    )
    client_ecdh_private_key, client_ecdh_public_key = generate_ecdh_keypair()

    message = {
        "type": "CLIENT_HELLO",
        "session_id": None,
        "seq": 1,
        "timestamp": int(time.time()),
        "nonce": client_nonce,
        "payload": {
            "client_id": user_id,
            "client_nonce": client_nonce,
            "client_certificate": certificate_to_json(client_certificate),
            "client_signature": base64.b64encode(client_signature).decode(),
            "client_ecdh_public_key": base64.b64encode(
                client_ecdh_public_key
            ).decode()
        }
    }

    SESSION["user_id"] = user_id

    send_message(
        message,
        client_ecdh_private_key=client_ecdh_private_key,
        keep_open=True
    )

    print("[HANDSHAKE] Secure session established ✅\n")


def upload(sender_id, recipient_id, file_path=None):
    perform_handshake(sender_id)
    
    if file_path is None:
        file_path = input("Enter file path to upload: ").strip().strip('"')

    if not os.path.exists(file_path):
        print("[UPLOAD ERROR] File not found.")
        return

    file_bytes = read_file_bytes(file_path)
    filename = safe_filename(file_path)
    file_size = len(file_bytes)

    sender_private_key, sender_public_key = ensure_user_keys(sender_id)
    ensure_user_keys(recipient_id)

    sender_certificate = ensure_certificate(sender_id, sender_public_key)

    file_id = f"FILE-{time.strftime('%Y%m%d-%H%M%S')}"
    
    hours = input("Enter expiration time in hours: ").strip()

    try:
        hours = int(hours)

        if hours <= 0:
            print("[UPLOAD ERROR] Expiration hours must be greater than 0.")
            return

    except ValueError:
        print("[UPLOAD ERROR] Invalid number.")
        return

    upload_time_obj = datetime.now()
    expiration_time_obj = upload_time_obj + timedelta(hours=hours)

    upload_time = upload_time_obj.isoformat()
    expiration_time = expiration_time_obj.isoformat()

    encrypted_package = encrypt_file_for_recipient(
        file_bytes,
        recipient_id
    )

    signature_data = build_signature_data(
        file_id,
        sender_id,
        recipient_id,
        expiration_time,
        encrypted_package["encrypted_file"],
        encrypted_package["wrapped_file_key"]
    )

    signature = sign_message(sender_private_key, signature_data)

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
            "upload_time": upload_time,
            "expiration_time": expiration_time,
            "filename": filename,
            "file_size": file_size,
            "encrypted_file": encrypted_package["encrypted_file"],
            "wrapped_file_key": encrypted_package["wrapped_file_key"],
            "sender_public_key": base64.b64encode(sender_public_key).decode(),
            "signature": base64.b64encode(signature).decode(),
            "sender_certificate": certificate_to_json(sender_certificate)
        }
    }

    send_message(message)


def list_files(user_id):
    perform_handshake(user_id)

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

    perform_handshake(user_id)
    ensure_user_keys(user_id)

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


def print_usage():
    print("Usage:")
    print("  python client.py hello")
    print("  python client.py upload <sender_id> <recipient_id>")
    print("  python client.py list <user_id>")
    print("  python client.py download <file_id> <user_id>")
    print("  python client.py setup-server")


def main():
    if len(sys.argv) < 2:
        interactive_menu()
        return

    command = sys.argv[1]

    if command == "hello":
        hello()

    elif command == "upload":
        if len(sys.argv) != 4:
            print("Usage: python client.py upload <sender_id> <recipient_id>")
            return
        
        if not is_valid_user_id(sys.argv[2]) or not is_valid_user_id(sys.argv[3]):
            print("Invalid user ID. Use only letters, numbers, and underscore.")
            return

        upload(sys.argv[2], sys.argv[3])

    elif command == "list":
        if len(sys.argv) != 3:
            print("Usage: python client.py list <user_id>")
            return
        
        if not is_valid_user_id(sys.argv[2]):
            print("Invalid user ID. Use only letters, numbers, and underscore.")
            return

        list_files(sys.argv[2])

    elif command == "download":
        if len(sys.argv) != 4:
            print("Usage: python client.py download <file_id> <user_id>")
            return
        
        if not is_valid_user_id(sys.argv[3]):
            print("Invalid user ID. Use only letters, numbers, and underscore.")
            return

        download(sys.argv[2], sys.argv[3])

    elif command == "setup-server":
        ensure_user_keys("server")
        server_public_key = load_public_key("server")
        ensure_certificate("server", server_public_key)
        print("[SETUP] Server keys and certificate created")

    else:
        print("Unknown command")
        print_usage()


def interactive_menu():
    print()
    print("-------------------------------------------------------------")
    print("======\\ Welcome to Secure Zero-Trust File Drop System /======")
    print("-------------------------------------------------------------")
    print()
    user_id = input("Enter your user ID: ").strip()

    if not is_valid_user_id(user_id):
        print("Invalid user ID. Use only letters, numbers, and underscore.")
        return

    if not user_id:
        print("User ID cannot be empty.")
        return

    print(f"\n[INFO] User ID selected: {user_id}")
    print("[INFO] Real authentication will be done using certificates and private keys.\n")

    perform_handshake(user_id)

    while True:
        print("\n===== Secure Zero-Trust File Drop System Menu =====")
        print("1. Upload file")
        print("2. List my files")
        print("3. Download file")
        print("4. Revoke uploaded file")
        print("5. Exit")
        print()
        choice = input("Choose an option: ").strip()

        if choice == "1":
            recipient_id = input("Enter recipient user ID: ").strip()

            if not is_valid_user_id(recipient_id):
                print("Invalid recipient ID. Use only letters, numbers, and underscore.")
                continue

            if not recipient_id:
                print("Recipient ID cannot be empty.")
                continue

            file_path = input("Enter file path to upload: ").strip().strip('"')

            if not os.path.exists(file_path):
                print("File not found.")
                continue

            upload(user_id, recipient_id, file_path)

        elif choice == "2":
            list_files(user_id)

        elif choice == "3":
            file_id = input("Enter file ID to download: ").strip()

            if not file_id:
                print("File ID cannot be empty.")
                continue

            download(file_id, user_id)

        elif choice == "4":
            file_id = input("Enter file ID to revoke: ").strip()

            if not file_id:
                print("File ID cannot be empty.")
                continue

            revoke_file(file_id, user_id)

        elif choice == "5":
            close_session()
            print("Exiting Secure Zero-Trust File Drop System...")
            break

        else:
            print("Invalid option. Please choose 1, 2, 3, 4, or 5.")

def close_session():
    if SESSION["socket"] is not None:
        SESSION["socket"].close()

    SESSION["socket"] = None
    SESSION["user_id"] = None
    SESSION["session_id"] = None
    SESSION["active"] = False

if __name__ == "__main__":
    main()