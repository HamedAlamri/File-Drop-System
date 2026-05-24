# modules
from cryptography.hazmat.primitives.asymmetric import rsa, padding, ec
from cryptography.hazmat.primitives import hashes, serialization, hmac
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from cryptography.hazmat.backends import default_backend
import os
import struct


# ========== RSA Key Generation ==========

# Generate RSA public/private key pair.
# Returns:
# tuple: (private_key_pem, public_key_pem) both in PEM format as bytes
def generate_rsa_keypair():

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




# Encrypt data using RSA public key.
# Args:
#     public_key_pem (bytes): RSA public key in PEM format
#     data (bytes): Data to encrypt (must be <= 190 bytes for 2048-bit RSA)

# Returns:
#     bytes: Encrypted data
def rsa_encrypt(public_key_pem, data):
   
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


# Decrypt data using RSA private key.
# Args:
#     private_key_pem (bytes): RSA private key in PEM format
#     ciphertext (bytes): Data to decrypt
# Returns:
#     bytes: Decrypted data
def rsa_decrypt(private_key_pem, ciphertext):

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
#  Generate ECDH key pair using secp256r1 curve.
#     Returns:
#         tuple: (private_key_pem, public_key_bytes)
#             private_key_pem: PEM format bytes
#             public_key_bytes: raw uncompressed bytes (65 bytes: 0x04 + x + y)
def generate_ecdh_keypair():
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



# Compute shared secret using ECDH.   
#     Args:
#         private_key_pem (bytes): Our ECDH private key in PEM format
#         peer_public_key_bytes (bytes): Peer's public key in uncompressed bytes format    
#     Returns:
        # bytes: Shared secret (32 bytes for secp256r1)
def compute_ecdh_shared_secret(private_key_pem, peer_public_key_bytes):

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
def derive_session_keys(shared_secret, salt=None):
    
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

def aes_gcm_encrypt(key, plaintext, associated_data=None):
    
    if associated_data is None:
        associated_data = b''
    
    # Generate random nonce (12 bytes recommended for GCM)
    nonce = os.urandom(12)
    
    aesgcm = AESGCM(key)
    
    # Encrypt (GCM automatically appends tag at the end)
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data)
    
    # Format: nonce + ciphertext (which includes tag at the end)
    return nonce + ciphertext


    

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
def aes_gcm_decrypt(key, ciphertext_with_nonce, associated_data=None):

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

"""
    Sign a message using RSA-PSS.
    
    Args:
        private_key_pem (bytes): RSA private key in PEM format
        message (bytes): Message to sign
    
    Returns:
        bytes: Digital signature
"""
def sign_message(private_key_pem, message):
    
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


"""
    Verify an RSA-PSS signature.
    
    Args:
        public_key_pem (bytes): RSA public key in PEM format
        message (bytes): Original message
        signature (bytes): Signature to verify
    
    Returns:
        bool: True if signature is valid, False otherwise
    """
def verify_signature(public_key_pem, message, signature):
    
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
