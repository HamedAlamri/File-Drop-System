# Modules
import os
import time
import uuid 
import json 
from crypto_utils import generate_rsa_keypair, sign_message, verify_signature


# ca_store --> folder, which we store our ca key on it.
CA_DIR = "ca_store"
# create files inside our ca_store folder  
CA_PRIVATE_KEY_FILE = os.path.join(CA_DIR, "ca_private.pem")
CA_PUBLIC_KEY_FILE = os.path.join(CA_DIR, "ca_public.pem")


# this fucntion is ensure that the ca director is exitst, if not create one
def ensure_ca_dir():
    os.makedirs(CA_DIR, exist_ok= True)


def build_certificate_data(subject, public_key, issuer, valid_from, valid_to, serial_number):

    data = {
        "subject": subject,
        "public_key": public_key.decode() if isinstance(public_key, bytes) else public_key,
        "issuer": issuer,
        "valid_from": valid_from,
        "valid_to": valid_to,
        "serial_number": serial_number
    }

    return json.dumps(data, sort_keys=True).encode()



class CertificateAuthority:
    def __init__(self):
        ensure_ca_dir()

        #  we write and read the private and public keyies
        if not os.path.exists(CA_PRIVATE_KEY_FILE) or not os.path.exists(CA_PUBLIC_KEY_FILE):
            private_key, public_key = generate_rsa_keypair()

            # wb --> write in binary
            with open(CA_PRIVATE_KEY_FILE, "wb") as f:
                f.write(private_key)
 
            with open(CA_PUBLIC_KEY_FILE, "wb") as f:
                f.write(public_key)
        
        # rb --> read in binary
        with open(CA_PRIVATE_KEY_FILE, "rb") as f:
            self.private_key = f.read()
            
        with open(CA_PUBLIC_KEY_FILE, "rb") as f:
            self.public_key = f.read()
            

    # create certificate
    def issue_certificate(self, subject_name, subject_public_key_pem, validity_days=365):
        valid_from = time.time() # now time
        valid_to = valid_from + (validity_days * 24 * 60 * 60) # by seconds
        serial_number = str(uuid.uuid4()) # get unique number
        issuer = "SecureFileDropCA"

        # Creat the certificate structure
        certificate_data = build_certificate_data (
            subject_name,
            subject_public_key_pem,
            issuer,
            valid_from,
            valid_to,
            serial_number
        )
                    
        # private key + certificate data = signature
        signature = sign_message(self.private_key, certificate_data)
        
        
        # return the certificate
        return {
            "subject": subject_name,
            "public_key": subject_public_key_pem,
            "issuer": issuer,
            "valid_from": valid_from,
            "valid_to": valid_to,
            "serial_number": serial_number,
            "signature": signature
        }
    

    # check if the certificate is valid
    def verify_certificate(self, certificate):

        try:
            now = time.time()

            # check the issure
            if certificate["issuer"] != "SecureFileDropCA":
                return False


            # check the if the time is valid
            if now < certificate["valid_from"] or now > certificate["valid_to"]:
                return False
            
            
            # bulid new certificate, for checking
            certificate_data = build_certificate_data(
                certificate["subject"],
                certificate["public_key"],
                certificate["issuer"],
                certificate["valid_from"],
                certificate["valid_to"],
                certificate["serial_number"]
            )

            
            # this will return true/false   
            # it give us the final result
            return verify_signature(
                self.public_key,
                certificate_data,
                certificate["signature"]
            )

        # if any error happend than we consider the certificate is not valid
        except Exception:
            return False