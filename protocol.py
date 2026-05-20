
# all this are availabe bello
# CLIENT_HELLO = "CLIENT_HELLO"
# SERVER_HELLO = "SERVER_HELLO"

# UPLOAD_REQUEST = "UPLOAD_REQUEST"
# UPLOAD_ACK = "UPLOAD_ACK"

# LIST_REQUEST = "LIST_REQUEST"
# LIST_RESPONSE = "LIST_RESPONSE"

# DOWNLOAD_REQUEST = "DOWNLOAD_REQUEST"
# DOWNLOAD_RESPONSE = "DOWNLOAD_RESPONSE"

# ERROR = "ERROR"


# protocol.py
# Protocol handling for Secure File Drop System


from crypto_utils import (
    generate_nonce, sign_message, verify_signature,
    aes_gcm_encrypt, aes_gcm_decrypt,
    serialize_dict, deserialize_dict
)
import time
import struct

# ========== Message Types (Constants) ==========
# Handshake messages
CLIENT_HELLO = "CLIENT_HELLO"
SERVER_HELLO = "SERVER_HELLO"
CLIENT_AUTH_PROOF = "CLIENT_AUTH_PROOF"
SERVER_AUTH_PROOF = "SERVER_AUTH_PROOF"
SESSION_READY = "SESSION_READY"

# File operation messages
UPLOAD_REQUEST = "UPLOAD_REQUEST"
UPLOAD_ACK = "UPLOAD_ACK"
LIST_REQUEST = "LIST_REQUEST"
LIST_RESPONSE = "LIST_RESPONSE"
DOWNLOAD_REQUEST = "DOWNLOAD_REQUEST"
DOWNLOAD_RESPONSE = "DOWNLOAD_RESPONSE"
ERROR = "ERROR"

# Additional message types
ACK = "ACK"
EXPIRED = "EXPIRED"


# ========== Handshake Message Builders ==========

def build_client_hello(certificate, nonce, ecdh_public_key):
    """
    Build CLIENT_HELLO message.
    
    Args:
        certificate (dict): Client's certificate from CA
        nonce (bytes): Random nonce (16 bytes)
        ecdh_public_key (bytes): ECDH public key raw bytes
    
    Returns:
        bytes: Serialized message
    """
    message = {
        'type': CLIENT_HELLO,
        'certificate': certificate,
        'nonce': nonce.hex(),
        'ecdh_public_key': ecdh_public_key.hex(),
        'timestamp': time.time()
    }
    return serialize_dict(message)


def parse_client_hello(data):
    """
    Parse CLIENT_HELLO message.
    
    Args:
        data (bytes): Received message
    
    Returns:
        tuple: (certificate, nonce_bytes, ecdh_public_key_bytes)
    """
    message = deserialize_dict(data)
    
    if message.get('type') != CLIENT_HELLO:
        raise ValueError(f"Expected CLIENT_HELLO, got {message.get('type')}")
    
    certificate = message['certificate']
    nonce = bytes.fromhex(message['nonce'])
    ecdh_public_key = bytes.fromhex(message['ecdh_public_key'])
    
    return certificate, nonce, ecdh_public_key


def build_server_hello(certificate, nonce, ecdh_public_key):
    """
    Build SERVER_HELLO message.
    
    Args:
        certificate (dict): Server's certificate from CA
        nonce (bytes): Random nonce (16 bytes)
        ecdh_public_key (bytes): ECDH public key raw bytes
    
    Returns:
        bytes: Serialized message
    """
    message = {
        'type': SERVER_HELLO,
        'certificate': certificate,
        'nonce': nonce.hex(),
        'ecdh_public_key': ecdh_public_key.hex(),
        'timestamp': time.time()
    }
    return serialize_dict(message)


def parse_server_hello(data):
    """
    Parse SERVER_HELLO message.
    
    Args:
        data (bytes): Received message
    
    Returns:
        tuple: (certificate, nonce_bytes, ecdh_public_key_bytes)
    """
    message = deserialize_dict(data)
    
    if message.get('type') != SERVER_HELLO:
        raise ValueError(f"Expected SERVER_HELLO, got {message.get('type')}")
    
    certificate = message['certificate']
    nonce = bytes.fromhex(message['nonce'])
    ecdh_public_key = bytes.fromhex(message['ecdh_public_key'])
    
    return certificate, nonce, ecdh_public_key


def build_client_auth_proof(signature):
    """
    Build CLIENT_AUTH_PROOF message.
    
    Args:
        signature (bytes): Signature of server_nonce + seq_num
    
    Returns:
        bytes: Serialized message
    """
    message = {
        'type': CLIENT_AUTH_PROOF,
        'signature': signature.hex(),
        'timestamp': time.time()
    }
    return serialize_dict(message)


def parse_client_auth_proof(data):
    """
    Parse CLIENT_AUTH_PROOF message.
    
    Args:
        data (bytes): Received message
    
    Returns:
        bytes: Signature
    """
    message = deserialize_dict(data)
    
    if message.get('type') != CLIENT_AUTH_PROOF:
        raise ValueError(f"Expected CLIENT_AUTH_PROOF, got {message.get('type')}")
    
    return bytes.fromhex(message['signature'])


def build_server_auth_proof(signature):
    """
    Build SERVER_AUTH_PROOF message.
    
    Args:
        signature (bytes): Signature of client_nonce + seq_num
    
    Returns:
        bytes: Serialized message
    """
    message = {
        'type': SERVER_AUTH_PROOF,
        'signature': signature.hex(),
        'timestamp': time.time()
    }
    return serialize_dict(message)


def parse_server_auth_proof(data):
    """
    Parse SERVER_AUTH_PROOF message.
    
    Args:
        data (bytes): Received message
    
    Returns:
        bytes: Signature
    """
    message = deserialize_dict(data)
    
    if message.get('type') != SERVER_AUTH_PROOF:
        raise ValueError(f"Expected SERVER_AUTH_PROOF, got {message.get('type')}")
    
    return bytes.fromhex(message['signature'])


def build_session_ready():
    """
    Build SESSION_READY message.
    
    Returns:
        bytes: Serialized message
    """
    message = {
        'type': SESSION_READY,
        'timestamp': time.time()
    }
    return serialize_dict(message)


def parse_session_ready(data):
    """
    Parse SESSION_READY message.
    
    Args:
        data (bytes): Received message
    
    Returns:
        bool: True if message is valid SESSION_READY
    """
    message = deserialize_dict(data)
    return message.get('type') == SESSION_READY


# ========== File Operation Message Builders ==========

def build_upload_request(file_id, sender, recipient, filename, encrypted_file_key, 
                          encrypted_file_data, signature, expiration_time):
    """
    Build UPLOAD_REQUEST message.
    
    Args:
        file_id (str): Unique file identifier
        sender (str): Sender username
        recipient (str): Recipient username
        filename (str): Original filename (encrypted)
        encrypted_file_key (bytes): File key encrypted with recipient's public key
        encrypted_file_data (bytes): Encrypted file content
        signature (bytes): Digital signature of file metadata
        expiration_time (float): Expiration timestamp
    
    Returns:
        bytes: Serialized message
    """
    message = {
        'type': UPLOAD_REQUEST,
        'file_id': file_id,
        'sender': sender,
        'recipient': recipient,
        'filename': filename.hex() if isinstance(filename, bytes) else filename,
        'encrypted_file_key': encrypted_file_key.hex(),
        'encrypted_file_data': encrypted_file_data.hex(),
        'signature': signature.hex(),
        'expiration_time': expiration_time,
        'timestamp': time.time()
    }
    return serialize_dict(message)


def parse_upload_request(data):
    """
    Parse UPLOAD_REQUEST message.
    
    Args:
        data (bytes): Received message
    
    Returns:
        tuple: (file_id, sender, recipient, filename_bytes, encrypted_file_key,
                encrypted_file_data, signature, expiration_time)
    """
    message = deserialize_dict(data)
    
    if message.get('type') != UPLOAD_REQUEST:
        raise ValueError(f"Expected UPLOAD_REQUEST, got {message.get('type')}")
    
    file_id = message['file_id']
    sender = message['sender']
    recipient = message['recipient']
    filename = bytes.fromhex(message['filename'])
    encrypted_file_key = bytes.fromhex(message['encrypted_file_key'])
    encrypted_file_data = bytes.fromhex(message['encrypted_file_data'])
    signature = bytes.fromhex(message['signature'])
    expiration_time = message['expiration_time']
    
    return (file_id, sender, recipient, filename, encrypted_file_key,
            encrypted_file_data, signature, expiration_time)


def build_upload_ack(file_id, status, message_text=""):
    """
    Build UPLOAD_ACK message.
    
    Args:
        file_id (str): File identifier
        status (str): "success" or "failure"
        message_text (str): Optional message
    
    Returns:
        bytes: Serialized message
    """
    ack_message = {
        'type': UPLOAD_ACK,
        'file_id': file_id,
        'status': status,
        'message': message_text,
        'timestamp': time.time()
    }
    return serialize_dict(ack_message)


def parse_upload_ack(data):
    """
    Parse UPLOAD_ACK message.
    
    Args:
        data (bytes): Received message
    
    Returns:
        tuple: (file_id, status, message)
    """
    message = deserialize_dict(data)
    
    if message.get('type') != UPLOAD_ACK:
        raise ValueError(f"Expected UPLOAD_ACK, got {message.get('type')}")
    
    return message['file_id'], message['status'], message['message']


def build_list_request(username):
    """
    Build LIST_REQUEST message.
    
    Args:
        username (str): Username requesting file list
    
    Returns:
        bytes: Serialized message
    """
    message = {
        'type': LIST_REQUEST,
        'username': username,
        'timestamp': time.time()
    }
    return serialize_dict(message)


def parse_list_request(data):
    """
    Parse LIST_REQUEST message.
    
    Args:
        data (bytes): Received message
    
    Returns:
        str: Username
    """
    message = deserialize_dict(data)
    
    if message.get('type') != LIST_REQUEST:
        raise ValueError(f"Expected LIST_REQUEST, got {message.get('type')}")
    
    return message['username']


def build_list_response(files):
    """
    Build LIST_RESPONSE message.
    
    Args:
        files (list): List of file info dicts, each containing:
                     - file_id, sender, filename, size, upload_time, expiration_time
    
    Returns:
        bytes: Serialized message
    """
    # Convert bytes to hex for serialization
    serializable_files = []
    for file_info in files:
        serializable_file = file_info.copy()
        if 'filename' in serializable_file and isinstance(serializable_file['filename'], bytes):
            serializable_file['filename'] = serializable_file['filename'].hex()
        serializable_files.append(serializable_file)
    
    message = {
        'type': LIST_RESPONSE,
        'files': serializable_files,
        'timestamp': time.time()
    }
    return serialize_dict(message)


def parse_list_response(data):
    """
    Parse LIST_RESPONSE message.
    
    Args:
        data (bytes): Received message
    
    Returns:
        list: List of file info dicts
    """
    message = deserialize_dict(data)
    
    if message.get('type') != LIST_RESPONSE:
        raise ValueError(f"Expected LIST_RESPONSE, got {message.get('type')}")
    
    # Convert hex back to bytes
    files = []
    for file_info in message['files']:
        file_copy = file_info.copy()
        if 'filename' in file_copy and isinstance(file_copy['filename'], str):
            try:
                file_copy['filename'] = bytes.fromhex(file_copy['filename'])
            except:
                pass  # Keep as is if not hex
        files.append(file_copy)
    
    return files


def build_download_request(file_id, username):
    """
    Build DOWNLOAD_REQUEST message.
    
    Args:
        file_id (str): File identifier to download
        username (str): Username requesting download
    
    Returns:
        bytes: Serialized message
    """
    message = {
        'type': DOWNLOAD_REQUEST,
        'file_id': file_id,
        'username': username,
        'timestamp': time.time()
    }
    return serialize_dict(message)


def parse_download_request(data):
    """
    Parse DOWNLOAD_REQUEST message.
    
    Args:
        data (bytes): Received message
    
    Returns:
        tuple: (file_id, username)
    """
    message = deserialize_dict(data)
    
    if message.get('type') != DOWNLOAD_REQUEST:
        raise ValueError(f"Expected DOWNLOAD_REQUEST, got {message.get('type')}")
    
    return message['file_id'], message['username']


def build_download_response(status, file_data=None, error_message=""):
    """
    Build DOWNLOAD_RESPONSE message.
    
    Args:
        status (str): "success" or "failure" or "expired"
        file_data (dict, optional): File data if successful
        error_message (str, optional): Error message if failed
    
    Returns:
        bytes: Serialized message
    """
    response = {
        'type': DOWNLOAD_RESPONSE,
        'status': status,
        'error_message': error_message,
        'timestamp': time.time()
    }
    
    if file_data and status == "success":
        # Convert hex for serialization
        response['file_id'] = file_data.get('file_id', '')
        response['sender'] = file_data.get('sender', '')
        response['filename'] = file_data.get('filename', b'').hex() if isinstance(file_data.get('filename'), bytes) else ''
        response['encrypted_file_key'] = file_data.get('encrypted_file_key', b'').hex()
        response['encrypted_file_data'] = file_data.get('encrypted_file_data', b'').hex()
        response['signature'] = file_data.get('signature', b'').hex()
    
    return serialize_dict(response)


def parse_download_response(data):
    """
    Parse DOWNLOAD_RESPONSE message.
    
    Args:
        data (bytes): Received message
    
    Returns:
        tuple: (status, file_data_dict, error_message)
    """
    message = deserialize_dict(data)
    
    if message.get('type') != DOWNLOAD_RESPONSE:
        raise ValueError(f"Expected DOWNLOAD_RESPONSE, got {message.get('type')}")
    
    status = message['status']
    error_message = message.get('error_message', '')
    
    file_data = None
    if status == "success" and 'file_id' in message:
        file_data = {
            'file_id': message['file_id'],
            'sender': message['sender'],
            'filename': bytes.fromhex(message['filename']) if message['filename'] else b'',
            'encrypted_file_key': bytes.fromhex(message['encrypted_file_key']),
            'encrypted_file_data': bytes.fromhex(message['encrypted_file_data']),
            'signature': bytes.fromhex(message['signature'])
        }
    
    return status, file_data, error_message


def build_error_message(error_code, error_message):
    """
    Build ERROR message.
    
    Args:
        error_code (str): Error code (e.g., "AUTH_FAILED", "FILE_NOT_FOUND")
        error_message (str): Human readable error description
    
    Returns:
        bytes: Serialized message
    """
    message = {
        'type': ERROR,
        'error_code': error_code,
        'error_message': error_message,
        'timestamp': time.time()
    }
    return serialize_dict(message)


def parse_error_message(data):
    """
    Parse ERROR message.
    
    Args:
        data (bytes): Received message
    
    Returns:
        tuple: (error_code, error_message)
    """
    message = deserialize_dict(data)
    
    if message.get('type') != ERROR:
        raise ValueError(f"Expected ERROR, got {message.get('type')}")
    
    return message['error_code'], message['error_message']


# ========== Replay Protection Class ==========

class ReplayProtection:
    """
    Replay protection using sequence numbers, nonces, and timestamps.
    """
    
    def __init__(self):
        self.expected_seq_num = 0
        self.received_nonces = set()  # Store used nonces
        self.received_timestamps = set()  # Store recent timestamps
        self.sent_nonces = set()  # Store nonces we've sent
        self.max_time_diff = 300  # 5 minutes maximum time difference
        
    def get_next_seq_num(self):
        """
        Get next sequence number and increment.
        
        Returns:
            int: Next sequence number
        """
        seq = self.expected_seq_num
        self.expected_seq_num += 1
        return seq
    
    def get_current_timestamp(self):
        """
        Get current timestamp.
        
        Returns:
            float: Current Unix timestamp
        """
        return time.time()
    
    def generate_nonce(self):
        """
        Generate a new nonce and store it as sent.
        
        Returns:
            bytes: Random nonce
        """
        nonce = generate_nonce(16)
        self.sent_nonces.add(nonce)
        return nonce
    
    def validate_request(self, seq_num, nonce, timestamp):
        """
        Validate a request for replay attacks.
        
        Args:
            seq_num (int): Sequence number
            nonce (bytes): Nonce from request
            timestamp (float): Timestamp from request
        
        Returns:
            bool: True if valid, False if replay detected
        """
        # Check sequence number
        if seq_num != self.expected_seq_num:
            print(f"[ReplayProtection] Invalid sequence number: expected {self.expected_seq_num}, got {seq_num}")
            return False
        
        # Check if nonce was already used
        if nonce in self.received_nonces:
            print(f"[ReplayProtection] Replay detected: nonce already used")
            return False
        
        # Check if timestamp is fresh (not too old or in the future)
        now = time.time()
        if abs(now - timestamp) > self.max_time_diff:
            print(f"[ReplayProtection] Timestamp too old/future: {timestamp} vs {now}")
            return False
        
        # Check if timestamp was already used (simple replay detection)
        # Round to nearest second to avoid floating point issues
        rounded_timestamp = round(timestamp, 1)
        if rounded_timestamp in self.received_timestamps:
            print(f"[ReplayProtection] Replay detected: timestamp already used")
            return False
        
        # All checks passed, store used values
        self.received_nonces.add(nonce)
        self.received_timestamps.add(rounded_timestamp)
        self.expected_seq_num += 1
        
        # Clean up old nonces/timestamps to prevent memory growth
        self._cleanup_old_entries(now)
        
        return True
    
    def _cleanup_old_entries(self, current_time):
        """
        Clean up old timestamp entries.
        
        Args:
            current_time (float): Current timestamp
        """
        # Remove timestamps older than max_time_diff
        to_remove = []
        for ts in self.received_timestamps:
            if current_time - ts > self.max_time_diff:
                to_remove.append(ts)
        for ts in to_remove:
            self.received_timestamps.remove(ts)
        
        # Limit nonces set size (basic cleanup)
        if len(self.received_nonces) > 1000:
            self.received_nonces.clear()
    
    def validate_client_hello(self, nonce):
        """
        Validate nonce from CLIENT_HELLO (check if it's one we sent).
        
        Args:
            nonce (bytes): Nonce to validate
        
        Returns:
            bool: True if valid (nonce was sent by us)
        """
        if nonce in self.sent_nonces:
            self.sent_nonces.discard(nonce)
            return True
        return False
    
    def reset(self):
        """
        Reset replay protection state for a new session.
        """
        self.expected_seq_num = 0
        self.received_nonces.clear()
        self.received_timestamps.clear()
        self.sent_nonces.clear()


# ========== Session Encryption Class ==========

class SessionEncryption:
    """
    Handle session encryption/decryption using AES-GCM.
    """
    
    def __init__(self, client_to_server_key, server_to_client_key,
                 client_to_server_nonce, server_to_client_nonce):
        """
        Initialize session encryption with derived keys.
        
        Args:
            client_to_server_key (bytes): AES key for client->server messages
            server_to_client_key (bytes): AES key for server->client messages
            client_to_server_nonce (bytes): Initial nonce for client->server
            server_to_client_nonce (bytes): Initial nonce for server->client
        """
        self.c2s_key = client_to_server_key
        self.s2c_key = server_to_client_key
        self.c2s_nonce_counter = 0
        self.s2c_nonce_counter = 0
        self.c2s_base_nonce = client_to_server_nonce
        self.s2c_base_nonce = server_to_client_nonce
    
    def _increment_nonce(self, base_nonce, counter):
        """
        Increment nonce for each message.
        
        Args:
            base_nonce (bytes): Base 12-byte nonce
            counter (int): Counter value
        
        Returns:
            bytes: New nonce (base_nonce XOR counter)
        """
        # Simple nonce increment
        nonce = bytearray(base_nonce)
        for i in range(8):  # Increment as 64-bit integer
            nonce[11 - i] ^= ((counter >> (i * 8)) & 0xFF)
        return bytes(nonce)
    
    def encrypt_c2s(self, plaintext):
        """
        Encrypt message from client to server.
        
        Args:
            plaintext (bytes): Message to encrypt
        
        Returns:
            bytes: Encrypted message with nonce + ciphertext
        """
        nonce = self._increment_nonce(self.c2s_base_nonce, self.c2s_nonce_counter)
        self.c2s_nonce_counter += 1
        
        # Use AES-GCM with associated data (optional)
        ciphertext = aes_gcm_encrypt(self.c2s_key, plaintext, associated_data=None)
        # Note: aes_gcm_encrypt already includes nonce at the beginning
        
        return ciphertext
    
    def decrypt_c2s(self, ciphertext):
        """
        Decrypt message from client to server.
        
        Args:
            ciphertext (bytes): Encrypted message
        
        Returns:
            bytes: Decrypted plaintext
        """
        return aes_gcm_decrypt(self.c2s_key, ciphertext, associated_data=None)
    
    def encrypt_s2c(self, plaintext):
        """
        Encrypt message from server to client.
        
        Args:
            plaintext (bytes): Message to encrypt
        
        Returns:
            bytes: Encrypted message with nonce + ciphertext
        """
        nonce = self._increment_nonce(self.s2c_base_nonce, self.s2c_nonce_counter)
        self.s2c_nonce_counter += 1
        
        ciphertext = aes_gcm_encrypt(self.s2c_key, plaintext, associated_data=None)
        return ciphertext
    
    def decrypt_s2c(self, ciphertext):
        """
        Decrypt message from server to client.
        
        Args:
            ciphertext (bytes): Encrypted message
        
        Returns:
            bytes: Decrypted plaintext
        """
        return aes_gcm_decrypt(self.s2c_key, ciphertext, associated_data=None)


# ========== Signature Helper Functions ==========

def sign_message_wrapper(private_key_pem, message):
    """
    Wrapper for signing messages.
    
    Args:
        private_key_pem (bytes): RSA private key in PEM format
        message (bytes): Message to sign
    
    Returns:
        bytes: Signature
    """
    return sign_message(private_key_pem, message)


def verify_signature_wrapper(public_key_pem, message, signature):
    """
    Wrapper for verifying signatures.
    
    Args:
        public_key_pem (bytes): RSA public key in PEM format
        message (bytes): Original message
        signature (bytes): Signature to verify
    
    Returns:
        bool: True if valid
    """
    return verify_signature(public_key_pem, message, signature)


# ========== Test Functions ==========

def test_protocol():
    """
    Test protocol message building and parsing.
    """
    print("=" * 60)
    print("Testing Protocol Functions")
    print("=" * 60)
    
    # Test handshake messages
    print("\n[1] Testing handshake messages...")
    
    # CLIENT_HELLO
    cert = {"subject": "test_client", "public_key": b"fake_key"}
    nonce = generate_nonce(16)
    ecdh_pub = generate_nonce(65)  # 65 bytes for uncompressed point
    client_hello = build_client_hello(cert, nonce, ecdh_pub)
    parsed_cert, parsed_nonce, parsed_ecdh = parse_client_hello(client_hello)
    assert parsed_nonce == nonce
    assert parsed_ecdh == ecdh_pub
    print("    ✓ CLIENT_HELLO works")
    
    # SERVER_HELLO
    server_hello = build_server_hello(cert, nonce, ecdh_pub)
    parsed_cert, parsed_nonce, parsed_ecdh = parse_server_hello(server_hello)
    assert parsed_nonce == nonce
    print("    ✓ SERVER_HELLO works")
    
    # AUTH PROOFS
    sig = generate_nonce(256)
    client_auth = build_client_auth_proof(sig)
    parsed_sig = parse_client_auth_proof(client_auth)
    assert parsed_sig == sig
    print("    ✓ AUTH_PROOF messages work")
    
    # SESSION_READY
    session_ready = build_session_ready()
    assert parse_session_ready(session_ready) is True
    print("    ✓ SESSION_READY works")
    
    # Test file operation messages
    print("\n[2] Testing file operation messages...")
    
    # UPLOAD_REQUEST
    upload_req = build_upload_request(
        file_id="file123",
        sender="alice",
        recipient="bob",
        filename=b"secret.txt",
        encrypted_file_key=b"encrypted_key_123",
        encrypted_file_data=b"encrypted_data_456",
        signature=b"signature_789",
        expiration_time=time.time() + 3600
    )
    parsed = parse_upload_request(upload_req)
    assert parsed[0] == "file123"
    assert parsed[1] == "alice"
    assert parsed[2] == "bob"
    print("    ✓ UPLOAD_REQUEST works")
    
    # LIST_REQUEST/RESPONSE
    list_req = build_list_request("alice")
    username = parse_list_request(list_req)
    assert username == "alice"
    
    files = [{"file_id": "f1", "sender": "bob", "filename": b"doc.txt", "size": 100}]
    list_resp = build_list_response(files)
    parsed_files = parse_list_response(list_resp)
    assert len(parsed_files) == 1
    print("    ✓ LIST messages work")
    
    # DOWNLOAD messages
    download_req = build_download_request("file123", "bob")
    file_id, username = parse_download_request(download_req)
    assert file_id == "file123"
    assert username == "bob"
    
    file_data = {
        "file_id": "file123",
        "sender": "alice",
        "filename": b"secret.txt",
        "encrypted_file_key": b"key",
        "encrypted_file_data": b"data",
        "signature": b"sig"
    }
    download_resp = build_download_response("success", file_data)
    status, data, error = parse_download_response(download_resp)
    assert status == "success"
    print("    ✓ DOWNLOAD messages work")
    
    # ERROR message
    error_msg = build_error_message("AUTH_FAILED", "Authentication failed")
    code, msg = parse_error_message(error_msg)
    assert code == "AUTH_FAILED"
    print("    ✓ ERROR message works")
    
    # Test ReplayProtection
    print("\n[3] Testing ReplayProtection...")
    rp = ReplayProtection()
    
    # Valid request
    seq = rp.get_next_seq_num()
    nonce = generate_nonce(16)
    ts = time.time()
    assert rp.validate_request(seq, nonce, ts) is True
    
    # Replay same request (should fail)
    assert rp.validate_request(seq, nonce, ts) is False
    print("    ✓ Replay detection works")
    
    # Test SessionEncryption
    print("\n[4] Testing SessionEncryption...")
    from crypto_utils import generate_file_encryption_key
    
    c2s_key = generate_file_encryption_key()
    s2c_key = generate_file_encryption_key()
    c2s_nonce = generate_nonce(12)
    s2c_nonce = generate_nonce(12)
    
    session = SessionEncryption(c2s_key, s2c_key, c2s_nonce, s2c_nonce)
    
    test_msg = b"Hello, this is a secret session message!"
    encrypted = session.encrypt_c2s(test_msg)
    decrypted = session.decrypt_c2s(encrypted)
    assert test_msg == decrypted
    
    encrypted_s2c = session.encrypt_s2c(test_msg)
    decrypted_s2c = session.decrypt_s2c(encrypted_s2c)
    assert test_msg == decrypted_s2c
    print("    ✓ SessionEncryption works")
    
    print("\n" + "=" * 60)
    print("All protocol tests passed! ✓")
    print("=" * 60)


if __name__ == "__main__":
    test_protocol()