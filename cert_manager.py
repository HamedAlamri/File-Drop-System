import os
import json
import base64

from ca import CertificateAuthority

CERTS_DIR = "certs"
CA = CertificateAuthority()


def ensure_certs_dir():
    os.makedirs(CERTS_DIR, exist_ok=True)


def cert_path(user_id):
    return os.path.join(CERTS_DIR, f"{user_id}_cert.json")


def bytes_to_b64(value):
    if isinstance(value, bytes):
        return base64.b64encode(value).decode()
    return value


def b64_to_bytes(value):
    return base64.b64decode(value.encode())


def save_certificate(user_id, certificate):
    ensure_certs_dir()

    serializable_cert = {
        "subject": certificate["subject"],
        "public_key": bytes_to_b64(certificate["public_key"]),
        "issuer": certificate["issuer"],
        "valid_from": certificate["valid_from"],
        "valid_to": certificate["valid_to"],
        "signature": bytes_to_b64(certificate["signature"]),
        "serial_number": certificate["serial_number"]
    }

    with open(cert_path(user_id), "w", encoding="utf-8") as f:
        json.dump(serializable_cert, f, indent=4)


def load_certificate(user_id):
    with open(cert_path(user_id), "r", encoding="utf-8") as f:
        cert = json.load(f)

    return {
        "subject": cert["subject"],
        "public_key": b64_to_bytes(cert["public_key"]),
        "issuer": cert["issuer"],
        "valid_from": cert["valid_from"],
        "valid_to": cert["valid_to"],
        "signature": b64_to_bytes(cert["signature"]),
        "serial_number": cert["serial_number"]
    }


def certificate_to_json(certificate):
    return {
        "subject": certificate["subject"],
        "public_key": bytes_to_b64(certificate["public_key"]),
        "issuer": certificate["issuer"],
        "valid_from": certificate["valid_from"],
        "valid_to": certificate["valid_to"],
        "signature": bytes_to_b64(certificate["signature"]),
        "serial_number": certificate["serial_number"]
    }


def certificate_from_json(cert):
    return {
        "subject": cert["subject"],
        "public_key": b64_to_bytes(cert["public_key"]),
        "issuer": cert["issuer"],
        "valid_from": cert["valid_from"],
        "valid_to": cert["valid_to"],
        "signature": b64_to_bytes(cert["signature"]),
        "serial_number": cert["serial_number"]
    }


def ensure_certificate(user_id, public_key_pem):
    ensure_certs_dir()

    if not os.path.exists(cert_path(user_id)):
        certificate = CA.issue_certificate(
            user_id,
            public_key_pem,
            validity_days=365
        )
        save_certificate(user_id, certificate)

    return load_certificate(user_id)


def verify_certificate_json(cert_json):
    import time

    try:
        required_fields = [
            "subject",
            "public_key",
            "issuer",
            "valid_from",
            "valid_to",
            "signature",
            "serial_number"
        ]

        for field in required_fields:
            if field not in cert_json:
                return False

        if cert_json["issuer"] != "SecureFileDropCA":
            return False

        now = time.time()

        if now < cert_json["valid_from"]:
            return False

        if now > cert_json["valid_to"]:
            return False

        # Ensure base64 fields are decodable
        b64_to_bytes(cert_json["public_key"])
        b64_to_bytes(cert_json["signature"])

        return True

    except Exception:
        return False