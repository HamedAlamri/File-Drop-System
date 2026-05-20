# ca.py
# Certificate Authority module for Secure File Drop System

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
import datetime

class CertificateAuthority:
    """
    Simple Certificate Authority for issuing and verifying certificates.
    """
    
    def __init__(self):
        """
        Initialize the Certificate Authority.
        Generates CA key pair and self-signed certificate.
        """
        # Generate CA key pair (2048-bit RSA)
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        
        # Create self-signed certificate for CA
        self.certificate = self._create_self_signed_certificate()
    
    def _create_self_signed_certificate(self):
        """
        Create a self-signed certificate for the CA.
        """
        # Create subject name
        subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, u"SecureFileDropCA"),
        ])
        
        # Build certificate
        cert = x509.CertificateBuilder()
        cert = cert.subject_name(subject)
        cert = cert.issuer_name(subject)  # Self-signed: issuer = subject
        cert = cert.public_key(self.private_key.public_key())
        cert = cert.serial_number(x509.random_serial_number())
        cert = cert.not_valid_before(datetime.datetime.utcnow())
        cert = cert.not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=3650))  # 10 years
        
        # Sign the certificate
        cert = cert.sign(self.private_key, hashes.SHA256(), default_backend())
        
        return cert
    
    def issue_certificate(self, subject_name, subject_public_key_pem, validity_days=365):
        """
        Issue a certificate for a client or server.
        
        Args:
            subject_name (str): Name of the client/server (e.g., "alice", "server")
            subject_public_key_pem (bytes): Subject's public key in PEM format
            validity_days (int): Number of days the certificate is valid
        
        Returns:
            dict: Certificate containing all necessary fields
        """
        # Load subject's public key
        subject_public_key = serialization.load_pem_public_key(
            subject_public_key_pem,
            backend=default_backend()
        )
        
        # Create subject name
        subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, u"User: " + subject_name),
        ])
        
        # Get CA's subject as issuer
        issuer = self.certificate.subject
        
        # Set validity period
        valid_from = datetime.datetime.utcnow()
        valid_to = valid_from + datetime.timedelta(days=validity_days)
        
        # Build certificate
        cert_builder = x509.CertificateBuilder()
        cert_builder = cert_builder.subject_name(subject)
        cert_builder = cert_builder.issuer_name(issuer)
        cert_builder = cert_builder.public_key(subject_public_key)
        cert_builder = cert_builder.serial_number(x509.random_serial_number())
        cert_builder = cert_builder.not_valid_before(valid_from)
        cert_builder = cert_builder.not_valid_after(valid_to)
        
        # Sign with CA's private key
        certificate = cert_builder.sign(self.private_key, hashes.SHA256(), default_backend())
        
        # Return certificate as dictionary (easy to serialize)
        return {
            'subject': subject_name,
            'public_key': subject_public_key_pem,
            'issuer': 'SecureFileDropCA',
            'valid_from': valid_from.timestamp(),
            'valid_to': valid_to.timestamp(),
            'signature': certificate.signature,
            'serial_number': certificate.serial_number
        }
    
    def verify_certificate(self, certificate):
        """
        Verify if a certificate is valid and signed by this CA.
        
        Args:
            certificate (dict): Certificate dictionary from issue_certificate()
        
        Returns:
            bool: True if certificate is valid, False otherwise
        """
        try:
            # Check expiration
            now = datetime.datetime.utcnow().timestamp()
            if now < certificate['valid_from'] or now > certificate['valid_to']:
                return False
            
            # Reconstruct certificate to verify signature
            subject_public_key = serialization.load_pem_public_key(
                certificate['public_key'],
                backend=default_backend()
            )
            
            # Create subject name
            subject = x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, u"User: " + certificate['subject']),
            ])
            
            # Get CA's subject as issuer
            issuer = self.certificate.subject
            
            # Rebuild certificate
            cert_builder = x509.CertificateBuilder()
            cert_builder = cert_builder.subject_name(subject)
            cert_builder = cert_builder.issuer_name(issuer)
            cert_builder = cert_builder.public_key(subject_public_key)
            cert_builder = cert_builder.serial_number(certificate['serial_number'])
            cert_builder = cert_builder.not_valid_before(datetime.datetime.fromtimestamp(certificate['valid_from']))
            cert_builder = cert_builder.not_valid_after(datetime.datetime.fromtimestamp(certificate['valid_to']))
            
            # Try to sign with CA's private key and compare
            test_cert = cert_builder.sign(self.private_key, hashes.SHA256(), default_backend())
            
            # Compare signatures
            return test_cert.signature == certificate['signature']
            
        except Exception as e:
            print(f"Verification error: {e}")
            return False
    
    def get_ca_public_key(self):
        """
        Get CA's public key in PEM format.
        
        Returns:
            bytes: CA public key in PEM format
        """
        return self.certificate.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    
    def get_ca_certificate(self):
        """
        Get CA's own certificate in PEM format.
        
        Returns:
            bytes: CA certificate in PEM format
        """
        return self.certificate.public_bytes(serialization.Encoding.PEM)


# Simple test function
if __name__ == "__main__":
    print("=" * 50)
    print("Testing Certificate Authority")
    print("=" * 50)
    
    # Create CA
    ca = CertificateAuthority()
    print("[✓] CA created successfully")
    
    # Generate a test client key pair
    client_private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    client_public_key_pem = client_private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    # Issue certificate for client
    cert = ca.issue_certificate("test_client", client_public_key_pem, validity_days=30)
    print("[✓] Certificate issued for test_client")
    print(f"    - Subject: {cert['subject']}")
    print(f"    - Valid from: {datetime.datetime.fromtimestamp(cert['valid_from'])}")
    print(f"    - Valid to: {datetime.datetime.fromtimestamp(cert['valid_to'])}")
    
    # Verify certificate
    is_valid = ca.verify_certificate(cert)
    print(f"[✓] Certificate verification: {'PASSED' if is_valid else 'FAILED'}")
    
    # Get CA public key
    ca_pub_key = ca.get_ca_public_key()
    print(f"[✓] CA public key obtained (length: {len(ca_pub_key)} bytes)")
    
    # Test with invalid certificate
    fake_cert = cert.copy()
    fake_cert['subject'] = "fake_user"
    is_valid_fake = ca.verify_certificate(fake_cert)
    print(f"[✓] Fake certificate rejected: {not is_valid_fake}")
    
    print("\n" + "=" * 50)
    print("All tests passed!")
    print("=" * 50)