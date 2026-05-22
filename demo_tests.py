import socket
import json
import time
import base64
import os
from datetime import datetime, timedelta

from crypto_utils import (
    sign_message,
    verify_signature,
    generate_ecdh_keypair,
    compute_ecdh_shared_secret,
    derive_session_keys,
    rsa_encrypt,
    aes_gcm_encrypt,
)

from cert_manager import (
    ensure_certificate,
    certificate_to_json,
    verify_certificate_json,
)

from client import (
    ensure_user_keys,
    load_public_key,
    build_signature_data,
    generate_nonce,
)

HOST = "127.0.0.1"
PORT = 9090


def send_recv(sock, message):
    sock.sendall(json.dumps(message).encode())
    response = sock.recv(65536)

    if not response:
        return {"type": "ERROR", "payload": {"error": "No response from server"}}

    return json.loads(response.decode())


def print_response(response):
    print(json.dumps(response, indent=4))


def pass_fail(condition):
    print("\nResult:", "PASS ✅" if condition else "FAIL ❌")
    print("-" * 60)


def open_handshake(user_id, bad_proof=False, fixed_nonce=None):
    private_key, public_key = ensure_user_keys(user_id)
    certificate = ensure_certificate(user_id, public_key)

    client_nonce = fixed_nonce or generate_nonce()
    ecdh_private, ecdh_public = generate_ecdh_keypair()

    if bad_proof:
        signature = b"bad-signature"
    else:
        signature = sign_message(private_key, client_nonce.encode())

    message = {
        "type": "CLIENT_HELLO",
        "session_id": None,
        "seq": 1,
        "timestamp": int(time.time()),
        "nonce": client_nonce,
        "payload": {
            "client_id": user_id,
            "client_nonce": client_nonce,
            "client_certificate": certificate_to_json(certificate),
            "client_signature": base64.b64encode(signature).decode(),
            "client_ecdh_public_key": base64.b64encode(ecdh_public).decode()
        }
    }

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((HOST, PORT))

    response = send_recv(sock, message)

    if response.get("type") == "SERVER_HELLO":
        server_cert = response["payload"]["server_certificate"]
        server_signature = base64.b64decode(response["payload"]["server_signature"])
        server_public_key = base64.b64decode(server_cert["public_key"])

        cert_ok = verify_certificate_json(server_cert)
        proof_ok = verify_signature(
            server_public_key,
            client_nonce.encode(),
            server_signature
        )

        server_ecdh_public = base64.b64decode(
            response["payload"]["server_ecdh_public_key"]
        )

        shared_secret = compute_ecdh_shared_secret(
            ecdh_private,
            server_ecdh_public
        )
        derive_session_keys(shared_secret)

        print(f"Server certificate valid: {cert_ok}")
        print(f"Server proof valid: {proof_ok}")
        print("ECDH/HKDF derived ✅")

    return sock, response


def make_file_package(sender_id, recipient_id, content, filename, hours=1, expired=False):
    sender_private, sender_public = ensure_user_keys(sender_id)
    ensure_user_keys(recipient_id)

    sender_cert = ensure_certificate(sender_id, sender_public)

    file_id = f"TEST-FILE-{int(time.time() * 1000)}"

    upload_time_obj = datetime.now()

    if expired:
        expiration_time_obj = upload_time_obj - timedelta(hours=1)
    else:
        expiration_time_obj = upload_time_obj + timedelta(hours=hours)

    upload_time = upload_time_obj.isoformat()
    expiration_time = expiration_time_obj.isoformat()

    file_key = os.urandom(32)
    encrypted_file = aes_gcm_encrypt(file_key, content)

    recipient_public_key = load_public_key(recipient_id)
    wrapped_file_key = rsa_encrypt(recipient_public_key, file_key)

    encrypted_file_b64 = base64.b64encode(encrypted_file).decode()
    wrapped_file_key_b64 = base64.b64encode(wrapped_file_key).decode()

    signature_data = build_signature_data(
        file_id,
        sender_id,
        recipient_id,
        expiration_time,
        encrypted_file_b64,
        wrapped_file_key_b64
    )

    signature = sign_message(sender_private, signature_data)

    return {
        "file_id": file_id,
        "sender_id": sender_id,
        "recipient_id": recipient_id,
        "upload_time": upload_time,
        "expiration_time": expiration_time,
        "filename": filename,
        "file_size": len(content),
        "encrypted_file": encrypted_file_b64,
        "wrapped_file_key": wrapped_file_key_b64,
        "sender_public_key": base64.b64encode(sender_public).decode(),
        "signature": base64.b64encode(signature).decode(),
        "sender_certificate": certificate_to_json(sender_cert)
    }


def upload_package(sock, package):
    message = {
        "type": "UPLOAD_REQUEST",
        "session_id": "demo-session",
        "seq": 4,
        "timestamp": int(time.time()),
        "nonce": generate_nonce(),
        "payload": package
    }

    return send_recv(sock, message)


def download_request(sock, file_id, user_id):
    message = {
        "type": "DOWNLOAD_REQUEST",
        "session_id": "demo-session",
        "seq": 6,
        "timestamp": int(time.time()),
        "nonce": generate_nonce(),
        "payload": {
            "file_id": file_id,
            "user_id": user_id
        }
    }

    return send_recv(sock, message)


def list_request(sock, user_id):
    message = {
        "type": "LIST_REQUEST",
        "session_id": "demo-session",
        "seq": 2,
        "timestamp": int(time.time()),
        "nonce": generate_nonce(),
        "payload": {
            "user_id": user_id
        }
    }

    return send_recv(sock, message)


def test_valid_handshake():
    print("\n=== Test 1: Valid Handshake ===")
    sock, response = open_handshake("DemoAlice")
    print_response(response)
    ok = response.get("type") == "SERVER_HELLO"
    sock.close()
    pass_fail(ok)


def test_bad_client_proof():
    print("\n=== Test 2: Bad Client Proof-of-Possession ===")
    sock, response = open_handshake("BadProofUser", bad_proof=True)
    print_response(response)
    ok = (
        response.get("type") == "ERROR"
        and "proof" in response.get("payload", {}).get("error", "").lower()
    )
    sock.close()
    pass_fail(ok)


def test_replay_attack():
    print("\n=== Test 3: Replay Attack ===")
    fixed_nonce = f"DEMO_REPLAY_NONCE_{int(time.time() * 1000)}"

    sock1, response1 = open_handshake("DemoAlice", fixed_nonce=fixed_nonce)
    print("\nFirst response:")
    print_response(response1)
    sock1.close()

    sock2, response2 = open_handshake("DemoAlice", fixed_nonce=fixed_nonce)
    print("\nSecond response using same nonce:")
    print_response(response2)
    sock2.close()

    ok = (
        response2.get("type") == "ERROR"
        and "replay" in response2.get("payload", {}).get("error", "").lower()
    )
    pass_fail(ok)


def test_spoofed_list():
    print("\n=== Test 4: Spoofed LIST Request ===")
    print("Handshake as DemoAlice, then try LIST as DemoBob")

    sock, hello = open_handshake("DemoAlice")
    print("\nHandshake response:")
    print_response(hello)

    response = list_request(sock, "DemoBob")
    print("\nSpoofed LIST response:")
    print_response(response)

    ok = (
        response.get("type") == "ERROR"
        and "authenticated user" in response.get("payload", {}).get("error", "").lower()
    )

    sock.close()
    pass_fail(ok)


def test_tampered_signature():
    print("\n=== Test 5: Tampered Upload Signature ===")
    print("Create valid package, then modify encrypted_file after signing.")

    sock, hello = open_handshake("TamperSender")
    package = make_file_package(
        "TamperSender",
        "TamperReceiver",
        b"This file will be tampered.",
        "tampered.txt"
    )

    package["encrypted_file"] = package["encrypted_file"][:-4] + "AAAA"

    response = upload_package(sock, package)
    print_response(response)

    ok = (
        response.get("type") == "ERROR"
        and "signature" in response.get("payload", {}).get("error", "").lower()
    )

    sock.close()
    pass_fail(ok)


def test_unauthorized_download():
    print("\n=== Test 6: Unauthorized Download ===")
    print("Sender uploads for recipient, then sender tries to download.")

    sock_sender, _ = open_handshake("UnauthSender")

    package = make_file_package(
        "UnauthSender",
        "UnauthReceiver",
        b"Secret file for receiver only.",
        "secret.txt"
    )

    upload_response = upload_package(sock_sender, package)
    print("\nUpload response:")
    print_response(upload_response)

    response = download_request(sock_sender, package["file_id"], "UnauthSender")
    print("\nUnauthorized download response:")
    print_response(response)

    ok = (
        response.get("type") == "ERROR"
        and "unauthorized" in response.get("payload", {}).get("error", "").lower()
    )

    sock_sender.close()
    pass_fail(ok)


def test_one_time_download():
    print("\n=== Test 7: One-Time Download ===")

    sock_sender, _ = open_handshake("OnceSender")

    package = make_file_package(
        "OnceSender",
        "OnceReceiver",
        b"Download me only once.",
        "once.txt"
    )

    upload_response = upload_package(sock_sender, package)
    print("\nUpload response:")
    print_response(upload_response)
    sock_sender.close()

    sock_receiver, _ = open_handshake("OnceReceiver")

    first = download_request(sock_receiver, package["file_id"], "OnceReceiver")
    print("\nFirst download:")
    print_response(first)

    second = download_request(sock_receiver, package["file_id"], "OnceReceiver")
    print("\nSecond download:")
    print_response(second)

    ok = (
        first.get("type") == "DOWNLOAD_RESPONSE"
        and second.get("type") == "ERROR"
        and "already downloaded" in second.get("payload", {}).get("error", "").lower()
    )

    sock_receiver.close()
    pass_fail(ok)


def test_expired_file():
    print("\n=== Test 8: Expired File Rejection ===")

    sock_sender, _ = open_handshake("ExpiredSender")

    package = make_file_package(
        "ExpiredSender",
        "ExpiredReceiver",
        b"This file is already expired.",
        "expired.txt",
        expired=True
    )

    upload_response = upload_package(sock_sender, package)
    print("\nUpload response:")
    print_response(upload_response)
    sock_sender.close()

    sock_receiver, _ = open_handshake("ExpiredReceiver")
    response = download_request(sock_receiver, package["file_id"], "ExpiredReceiver")

    print("\nExpired download response:")
    print_response(response)

    ok = (
        response.get("type") == "ERROR"
        and "expired" in response.get("payload", {}).get("error", "").lower()
    )

    sock_receiver.close()
    pass_fail(ok)


def run_all():
    test_valid_handshake()
    test_bad_client_proof()
    test_replay_attack()
    test_spoofed_list()
    test_tampered_signature()
    test_unauthorized_download()
    test_one_time_download()
    test_expired_file()


def menu():
    while True:
        print("\n===== Security Demo Tests =====")
        print("1. Valid handshake")
        print("2. Bad client proof-of-possession")
        print("3. Replay attack")
        print("4. Spoofed LIST request")
        print("5. Tampered upload signature")
        print("6. Unauthorized download")
        print("7. One-time download")
        print("8. Expired file")
        print("9. Run all tests")
        print("0. Exit")

        choice = input("Choose test: ").strip()

        if choice == "1":
            test_valid_handshake()
        elif choice == "2":
            test_bad_client_proof()
        elif choice == "3":
            test_replay_attack()
        elif choice == "4":
            test_spoofed_list()
        elif choice == "5":
            test_tampered_signature()
        elif choice == "6":
            test_unauthorized_download()
        elif choice == "7":
            test_one_time_download()
        elif choice == "8":
            test_expired_file()
        elif choice == "9":
            run_all()
        elif choice == "0":
            break
        else:
            print("Invalid choice.")


if __name__ == "__main__":
    menu()