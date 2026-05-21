import socket
import json
import time

HOST = "127.0.0.1"
PORT = 9090

fixed_message = {
    "type": "CLIENT_HELLO",
    "session_id": None,
    "seq": 1,
    "timestamp": int(time.time()),
    "nonce": "REPLAY_NONCE_TEST",
    "payload": {
        "client_id": "clientA"
    }
}


def send_message(message):
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((HOST, PORT))

    client.sendall(json.dumps(message).encode())

    response = client.recv(16384)
    print(json.dumps(json.loads(response.decode()), indent=4))

    client.close()


print("First request:")
send_message(fixed_message)

print("\nSecond request with same nonce:")
send_message(fixed_message)