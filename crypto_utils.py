# crypto_utils.py
# Cryptographic utilities for Secure File Drop System

from cryptography.hazmat.primitives.asymmetric import rsa, padding, ec
from cryptography.hazmat.primitives import hashes, serialization, hmac
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from cryptography.hazmat.backends import default_backend
import os
import struct

# ========== RSA Key Generation ==========

def generate_rsa_keypair():
    """
    Generate RSA public/private key pair.
    
    Returns:
        tuple: (private_key_pem, public_key_pem) both in PEM format as bytes
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    # Serialize private key to PEM
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    # Serialize public key to PEM
    public_key_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    return private_key_pem, public_key_pem


def rsa_encrypt(public_key_pem, data):
    """
    Encrypt data using RSA public key.
    
    Args:
        public_key_pem (bytes): RSA public key in PEM format
        data (bytes): Data to encrypt (must be <= 190 bytes for 2048-bit RSA)
    
    Returns:
        bytes: Encrypted data
    """
    public_key = serialization.load_pem_public_key(
        public_key_pem,
        backend=default_backend()
    )
    
    ciphertext = public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext


def rsa_decrypt(private_key_pem, ciphertext):
    """
    Decrypt data using RSA private key.
    
    Args:
        private_key_pem (bytes): RSA private key in PEM format
        ciphertext (bytes): Data to decrypt
    
    Returns:
        bytes: Decrypted data
    """
    private_key = serialization.load_pem_private_key(
        private_key_pem,
        password=None,
        backend=default_backend()
    )
    
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext


# ========== ECDH Key Exchange ==========

def generate_ecdh_keypair():
    """
    Generate ECDH key pair using secp256r1 curve.
    
    Returns:
        tuple: (private_key_pem, public_key_bytes)
            private_key_pem: PEM format bytes
            public_key_bytes: raw uncompressed bytes (65 bytes: 0x04 + x + y)
    """
    private_key = ec.generate_private_key(
        ec.SECP256R1(),
        backend=default_backend()
    )
    
    # Serialize private key to PEM
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    # Get public key in uncompressed bytes format
    public_key = private_key.public_key()
    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint
    )
    
    return private_key_pem, public_key_bytes


def compute_ecdh_shared_secret(private_key_pem, peer_public_key_bytes):
    """
    Compute shared secret using ECDH.
    
    Args:
        private_key_pem (bytes): Our ECDH private key in PEM format
        peer_public_key_bytes (bytes): Peer's public key in uncompressed bytes format
    
    Returns:
        bytes: Shared secret (32 bytes for secp256r1)
    """
    private_key = serialization.load_pem_private_key(
        private_key_pem,
        password=None,
        backend=default_backend()
    )
    
    # Reconstruct peer's public key from bytes
    peer_public_key = ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP256R1(),
        peer_public_key_bytes
    )
    
    # Compute shared secret
    shared_secret = private_key.exchange(ec.ECDH(), peer_public_key)
    
    return shared_secret


# ========== HKDF Key Derivation ==========

def derive_session_keys(shared_secret, salt=None):
    """
    Derive session keys from ECDH shared secret using HKDF.
    
    Args:
        shared_secret (bytes): ECDH shared secret (32 bytes)
        salt (bytes, optional): Salt for HKDF. If None, uses 16 zero bytes.
    
    Returns:
        dict: Contains 4 keys (each 32 bytes):
            - 'client_to_server_key': AES key for client -> server
            - 'server_to_client_key': AES key for server -> client
            - 'client_to_server_nonce': initial nonce (12 bytes) for client -> server
            - 'server_to_client_nonce': initial nonce (12 bytes) for server -> client
    """
    if salt is None:
        salt = b'\x00' * 16
    
    # Derive 32+32+12+12 = 88 bytes of key material
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=88,  # 32 + 32 + 12 + 12
        salt=salt,
        info=b"secure-file-drop-session-keys-v1",
        backend=default_backend()
    )
    
    key_material = hkdf.derive(shared_secret)
    
    # Split into individual keys
    return {
        'client_to_server_key': key_material[0:32],
        'server_to_client_key': key_material[32:64],
        'client_to_server_nonce': key_material[64:76],
        'server_to_client_nonce': key_material[76:88]
    }


# ========== AES-GCM Encryption ==========

def aes_gcm_encrypt(key, plaintext, associated_data=None):
    """
    Encrypt plaintext using AES-GCM.
    
    Args:
        key (bytes): 32-byte AES-256 key
        plaintext (bytes): Data to encrypt
        associated_data (bytes, optional): Additional authenticated data
    
    Returns:
        bytes: Combined ciphertext + nonce + tag
            Format: [nonce (12 bytes)] + [ciphertext] + [tag (16 bytes)]
    """
    if associated_data is None:
        associated_data = b''
    
    # Generate random nonce (12 bytes recommended for GCM)
    nonce = os.urandom(12)
    
    aesgcm = AESGCM(key)
    
    # Encrypt (GCM automatically appends tag at the end)
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data)
    
    # Format: nonce + ciphertext (which includes tag at the end)
    return nonce + ciphertext


def aes_gcm_decrypt(key, ciphertext_with_nonce, associated_data=None):
    """
    Decrypt ciphertext using AES-GCM.
    
    Args:
        key (bytes): 32-byte AES-256 key
        ciphertext_with_nonce (bytes): Combined nonce + ciphertext + tag from encrypt
        associated_data (bytes, optional): Additional authenticated data (must match encryption)
    
    Returns:
        bytes: Decrypted plaintext
    
    Raises:
        Exception: If authentication fails
    """
    if associated_data is None:
        associated_data = b''
    
    # Extract nonce (first 12 bytes)
    nonce = ciphertext_with_nonce[:12]
    ciphertext = ciphertext_with_nonce[12:]
    
    aesgcm = AESGCM(key)
    
    # Decrypt (will raise exception if tag doesn't verify)
    plaintext = aesgcm.decrypt(nonce, ciphertext, associated_data)
    
    return plaintext


# ========== RSA-PSS Signatures ==========

def sign_message(private_key_pem, message):
    """
    Sign a message using RSA-PSS.
    
    Args:
        private_key_pem (bytes): RSA private key in PEM format
        message (bytes): Message to sign
    
    Returns:
        bytes: Digital signature
    """
    private_key = serialization.load_pem_private_key(
        private_key_pem,
        password=None,
        backend=default_backend()
    )
    
    signature = private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    
    return signature


def verify_signature(public_key_pem, message, signature):
    """
    Verify an RSA-PSS signature.
    
    Args:
        public_key_pem (bytes): RSA public key in PEM format
        message (bytes): Original message
        signature (bytes): Signature to verify
    
    Returns:
        bool: True if signature is valid, False otherwise
    """
    try:
        public_key = serialization.load_pem_public_key(
            public_key_pem,
            backend=default_backend()
        )
        
        public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False


# ========== Utility Functions ==========

def generate_nonce(size=16):
    """
    Generate a random nonce.
    
    Args:
        size (int): Size of nonce in bytes
    
    Returns:
        bytes: Random nonce
    """
    return os.urandom(size)


def serialize_dict(data_dict):
    """
    Serialize a dictionary to bytes for sending over network.
    Simple JSON-based serialization.
    
    Args:
        data_dict (dict): Dictionary to serialize
    
    Returns:
        bytes: Serialized data
    """
    import json
    json_str = json.dumps(data_dict, default=str)
    json_bytes = json_str.encode('utf-8')
    
    # Prefix with length (4 bytes) for easy parsing
    length = len(json_bytes)
    return struct.pack('!I', length) + json_bytes


def deserialize_dict(data_bytes):
    """
    Deserialize bytes back to dictionary.
    
    Args:
        data_bytes (bytes): Serialized data from serialize_dict
    
    Returns:
        dict: Deserialized dictionary
    """
    import json
    
    # Extract length (first 4 bytes)
    length = struct.unpack('!I', data_bytes[:4])[0]
    json_bytes = data_bytes[4:4+length]
    
    json_str = json_bytes.decode('utf-8')
    return json.loads(json_str)


# ========== Test Functions ==========

def test_rsa():
    """Test RSA encryption/decryption and signatures."""
    print("\n[TEST] RSA Operations")
    
    # Generate keypair
    priv, pub = generate_rsa_keypair()
    print("  ✓ RSA keypair generated")
    
    # Encrypt/decrypt
    plaintext = b"Hello Secure File Drop!"
    ciphertext = rsa_encrypt(pub, plaintext)
    decrypted = rsa_decrypt(priv, ciphertext)
    assert plaintext == decrypted
    print("  ✓ RSA encryption/decryption working")
    
    # Sign/verify
    signature = sign_message(priv, plaintext)
    valid = verify_signature(pub, plaintext, signature)
    assert valid == True
    print("  ✓ RSA-PSS signature working")
    
    # Test invalid signature
    invalid = verify_signature(pub, b"Wrong message", signature)
    assert invalid == False
    print("  ✓ Invalid signature rejected")


def test_ecdh():
    """Test ECDH key exchange."""
    print("\n[TEST] ECDH Key Exchange")
    
    # Generate keypairs for Alice and Bob
    alice_priv, alice_pub = generate_ecdh_keypair()
    bob_priv, bob_pub = generate_ecdh_keypair()
    print("  ✓ ECDH keypairs generated")
    
    # Compute shared secrets
    alice_secret = compute_ecdh_shared_secret(alice_priv, bob_pub)
    bob_secret = compute_ecdh_shared_secret(bob_priv, alice_pub)
    
    assert alice_secret == bob_secret
    print(f"  ✓ Shared secret matches (length: {len(alice_secret)} bytes)")


def test_hkdf():
    """Test HKDF key derivation."""
    print("\n[TEST] HKDF Key Derivation")
    
    shared_secret = b"test_shared_secret_32_bytes_long____"[:32]
    keys = derive_session_keys(shared_secret)
    
    assert 'client_to_server_key' in keys
    assert 'server_to_client_key' in keys
    assert 'client_to_server_nonce' in keys
    assert 'server_to_client_nonce' in keys
    
    print(f"  ✓ Derived 4 keys (each {len(keys['client_to_server_key'])} bytes)")
    
    # Different salt gives different keys
    keys2 = derive_session_keys(shared_secret, salt=b"different_salt")
    assert keys['client_to_server_key'] != keys2['client_to_server_key']
    print("  ✓ Different salt produces different keys")


def test_aes_gcm():
    """Test AES-GCM encryption/decryption."""
    print("\n[TEST] AES-GCM")
    
    key = os.urandom(32)
    plaintext = b"This is a secret file content!"
    associated_data = b"metadata: filename.txt"
    
    # Encrypt
    ciphertext = aes_gcm_encrypt(key, plaintext, associated_data)
    print(f"  ✓ Encrypted (ciphertext length: {len(ciphertext)} bytes)")
    
    # Decrypt
    decrypted = aes_gcm_decrypt(key, ciphertext, associated_data)
    assert plaintext == decrypted
    print("  ✓ Decryption successful")
    
    # Test authentication failure
    try:
        wrong_key = os.urandom(32)
        aes_gcm_decrypt(wrong_key, ciphertext, associated_data)
        print("  ✗ Authentication should have failed!")
    except Exception:
        print("  ✓ Authentication failure detected (invalid key)")
    
    # Test tampered ciphertext
    tampered = ciphertext[:20] + b'\x00' + ciphertext[21:]
    try:
        aes_gcm_decrypt(key, tampered, associated_data)
        print("  ✗ Tampered data should be detected!")
    except Exception:
        print("  ✓ Tampered data detected")


def test_serialization():
    """Test dictionary serialization."""
    print("\n[TEST] Serialization")
    
    original = {
        'type': 'UPLOAD',
        'file_id': '12345',
        'sender': 'alice',
        'recipient': 'bob',
        'timestamp': 1234567890.5
    }
    
    serialized = serialize_dict(original)
    deserialized = deserialize_dict(serialized)
    
    assert original == deserialized
    print(f"  ✓ Serialization working (size: {len(serialized)} bytes)")


def run_all_tests():
    """Run all crypto tests."""
    print("=" * 50)
    print("Testing crypto_utils.py")
    print("=" * 50)
    
    test_rsa()
    test_ecdh()
    test_hkdf()
    test_aes_gcm()
    test_serialization()
    
    print("\n" + "=" * 50)
    print("All tests passed! ✓")
    print("=" * 50)


if __name__ == "__main__":
    run_all_tests()