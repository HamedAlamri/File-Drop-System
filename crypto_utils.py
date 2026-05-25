"""
This python file contain all funciton for encryption and decryption.
"""


# Modules
from cryptography.hazmat.primitives.asymmetric import rsa, padding, ec
from cryptography.hazmat.primitives import hashes, serialization, hmac
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from cryptography.hazmat.backends import default_backend
import os



# RSA key generation
# create public and private key pair
# return keys in PEM format
def generate_rsa_keypair():

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size = 2048,
        backend= default_backend()
    )

    # Serialize private key to PEM
    private_key_pem = private_key.private_bytes(
        encoding= serialization.Encoding.PEM,
        format= serialization.PrivateFormat.PKCS8,
        encryption_algorithm= serialization.NoEncryption()
    )

    # Serialize public key to PEM
    public_key_pem = private_key.public_key().public_bytes(
        encoding= serialization.Encoding.PEM,
        format= serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return private_key_pem, public_key_pem


# Encrypt data using RSA public key
# returns: encrypted data
def rsa_encrypt(public_key_pem, data):

    # extract public key from pem format
    public_key = serialization.load_pem_public_key (
        public_key_pem,
        backend= default_backend()
    )

    # encrypt the plaintext data to cipthertext
    ciphertext = public_key.encrypt (
        data,
        padding.OAEP(
            mgf = padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label= None
        )
    )

    return ciphertext



# decrypt the ciphertext to plaintext (opsite of previse function)
# returns: data in plaintext 
def rsa_decrypt(private_key_pem, ciphertext):

    # extract the private key, from pem format
    private_key = serialization.load_pem_private_key(
        private_key_pem,
        password= None,
        backend= default_backend()
    )

    # decrypt the ciphertext
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf= padding.MGF1(algorithm=hashes.SHA256()),
            algorithm= hashes.SHA256(),
            label= None
        )
    )
    
    return plaintext



# Generate ECDH key pair using secp256r1 curve
# returns: 
#         private_key_pem --> Pem format
#         public_key_bytes --> raw uncompressed bytes
def generate_ecdh_keypair():

    private_key = ec.generate_private_key(
        ec.SECP256R1(),
        backend= default_backend()
    )

    # same of generate_rsa_keypair function
    # Serialize private key to PEM
    private_key_pem = private_key.private_bytes(
        encoding= serialization.Encoding.PEM,
        format= serialization.PrivateFormat.PKCS8,
        encryption_algorithm= serialization.NoEncryption()
    )
    ###
    
    # Get public key in uncompressed bytes format
    public_key = private_key.public_key()
    public_key_bytes = public_key.public_bytes(
        encoding= serialization.Encoding.X962,
        format= serialization.PublicFormat.UncompressedPoint
    )
    
    return private_key_pem, public_key_bytes


# compute shared secret using ECDH
# returns: shared secret in bytes
def compute_ecdh_shared_secret(private_key_pem, peer_public_key_bytes):

    # extract the private key from pem format
    private_key = serialization.load_pem_private_key(
        private_key_pem,
        password= None,
        backend= default_backend()
    )

    # get peer public key from bytes format 
    peer_public_key = ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP256R1(),
        peer_public_key_bytes
    )

    # compute shared secert
    shared_secret = private_key.exchange(ec.ECDH(), peer_public_key)

    return shared_secret


# derive session key from ECDH shared secret using HKDF
# returns: 
# for client --> AES key for client and initial nonce
# for server --> AES key for server and initial nonce
def derive_session_keys(shared_secret, salt = None):
    
    # if salt is None, then let the salt equal the empty salt sign 
    if salt is None:
        salt = b'\x00' * 16

    
    # why length = 88?
    # 32 --> client to server encrption key
    # 32 --> server to client encrption key
    # 12 --> client to server nonce
    # 12 --> server to client nonce
    hkdf = HKDF(
        algorithm= hashes.SHA256(),
        length= 88,
        salt= salt,
        info= b"secure-file-drop-session-keys-v1",
        backend= default_backend()
    )


    # derive the matirial from shared secret key
    key_material = hkdf.derive(shared_secret)


    # split the key in individual keys
    return {
        'client_to_server_key': key_material[0:32],
        'server_to_client_key': key_material[32:64],
        'client_to_server_nonce': key_material[64:76],
        'server_to_client_nonce': key_material[76:88] 
    }



# Encrtpt plain text using AES-GCM
# returns: nonce + ciphertext
def aes_gcm_encrypt(key, plaintext, associated_data =None):
    
    # if the assoiated_data is None, then make it empty
    if associated_data is None:
        associated_data = b''


    # generate random nonce with 12 bytes
    nonce = os.urandom(12)


    # create an AES-GCM object by using the key
    aesgcm = AESGCM(key)

    # encrpt by using GCM , notes: this will append tag at the end
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data)


    return nonce + ciphertext



# decrypt ciphertext by using AES-GCM (opesite of pervious function)
# returns: data in plaintext 
def aes_gcm_decrypt(key, ciphertext_with_nonce, associated_data = None):

    # if the assoiated_data is None, then make it empty
    if associated_data is None:
        associated_data = b''

    
    # extract the nonce and ciphertext
    nonce = ciphertext_with_nonce[:12]
    ciphertext = ciphertext_with_nonce[12:]

    # create object for AES-GCM by using the key
    aesgcm = AESGCM(key)

    # decrypt the ciphertext
    plaintext = aesgcm.decrypt(nonce, ciphertext, associated_data)

    return plaintext


# sign the message using RSA-PSS
# returns: digital signature in bytes
def sign_message(private_key_pem, message):

    # extract the private key from pem format
    private_key = serialization.load_pem_private_key(
        private_key_pem,
        password= None,
        backend= default_backend()
    )

    # sign the message 
    signature = private_key.sign(
        message,
        padding.PSS(
            mgf= padding.MGF1(hashes.SHA256()),
            salt_length= padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    return signature


# verify the signature by using RSA-PSS
# returns: True / False
def verify_signature(public_key_pem, message, signature):

    try:
        public_key = serialization.load_pem_public_key(
            public_key_pem,
            backend= default_backend()
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

        # than, everything is correct...
        return True
    
    # if something wrong, then the signature is not valid
    except Exception:
        return False