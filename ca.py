import os
import time
import uuid
import json

from crypto_utils import generate_rsa_keypair, sign_message, verify_signature

CA_DIR = "ca_store"
CA_PRIVATE_KEY_FILE = os.path.join(CA_DIR, "ca_private.pem")
CA_PUBLIC_KEY_FILE = os.path.join(CA_DIR, "ca_public.pem")


def ensure_ca_dir():
    os.makedirs(CA_DIR, exist_ok=True)


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

        if not os.path.exists(CA_PRIVATE_KEY_FILE) or not os.path.exists(CA_PUBLIC_KEY_FILE):
            private_key, public_key = generate_rsa_keypair()

            with open(CA_PRIVATE_KEY_FILE, "wb") as f:
                f.write(private_key)

            with open(CA_PUBLIC_KEY_FILE, "wb") as f:
                f.write(public_key)

        with open(CA_PRIVATE_KEY_FILE, "rb") as f:
            self.private_key = f.read()

        with open(CA_PUBLIC_KEY_FILE, "rb") as f:
            self.public_key = f.read()

    def issue_certificate(self, subject_name, subject_public_key_pem, validity_days=365):
        valid_from = time.time()
        valid_to = valid_from + validity_days * 24 * 60 * 60
        serial_number = str(uuid.uuid4())
        issuer = "SecureFileDropCA"

        certificate_data = build_certificate_data(
            subject_name,
            subject_public_key_pem,
            issuer,
            valid_from,
            valid_to,
            serial_number
        )

        signature = sign_message(self.private_key, certificate_data)

        return {
            "subject": subject_name,
            "public_key": subject_public_key_pem,
            "issuer": issuer,
            "valid_from": valid_from,
            "valid_to": valid_to,
            "serial_number": serial_number,
            "signature": signature
        }

    def verify_certificate(self, certificate):
        try:
            now = time.time()

            if certificate["issuer"] != "SecureFileDropCA":
                return False

            if now < certificate["valid_from"] or now > certificate["valid_to"]:
                return False

            certificate_data = build_certificate_data(
                certificate["subject"],
                certificate["public_key"],
                certificate["issuer"],
                certificate["valid_from"],
                certificate["valid_to"],
                certificate["serial_number"]
            )

            return verify_signature(
                self.public_key,
                certificate_data,
                certificate["signature"]
            )

        except Exception:
            return False

    def get_ca_public_key(self):
        return self.public_key