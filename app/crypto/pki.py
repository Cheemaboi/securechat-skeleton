"""X.509 validation: signed-by-CA, validity window, CN/SAN."""

import datetime
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature
from cryptography.x509.oid import NameOID

def load_ca_cert(ca_cert_path: str) -> x509.Certificate:
    """Loads a CA certificate from a PEM file."""
    with open(ca_cert_path, "rb") as f:
        ca_cert_data = f.read()
    ca_cert = x509.load_pem_x509_certificate(ca_cert_data)
    return ca_cert

def load_cert_from_str(cert_pem: str) -> x509.Certificate:
    """Loads an X.509 certificate from a PEM-formatted string."""
    cert_data = cert_pem.encode('ascii')
    cert = x509.load_pem_x509_certificate(cert_data)
    return cert

def verify_certificate(
    cert_to_check: x509.Certificate,
    ca_cert: x509.Certificate,
    expected_cn: str
) -> bool:
    """
    Verifies a certificate against a CA and checks its validity.
    
    Returns True if valid, False otherwise.
    """
    
    # 1. Check Signature (Was it signed by this CA?)
    try:
        ca_public_key = ca_cert.public_key()
        
        # The CA's public key verifies the certificate's signature
        ca_public_key.verify(
            cert_to_check.signature,
            cert_to_check.tbs_certificate_bytes, # The "to be signed" part
            padding.PKCS1v15(),
            cert_to_check.signature_hash_algorithm
        )
        print(f"DEBUG: Signature check PASSED for CN={expected_cn}.")
    except InvalidSignature:
        print(f"ERROR: Certificate signature is INVALID.")
        return False
    except Exception as e:
        print(f"ERROR: An error occurred during signature verification: {e}")
        return False

    # 2. Check Expiry (Validity Window)
    now = datetime.datetime.utcnow()
    if now < cert_to_check.not_valid_before:
        print(f"ERROR: Certificate is not yet valid (valid from {cert_to_check.not_valid_before}).")
        return False
    if now > cert_to_check.not_valid_after:
        print(f"ERROR: Certificate is expired (expired on {cert_to_check.not_valid_after}).")
        return False
    
    print(f"DEBUG: Validity window check PASSED.")

    # 3. Check Common Name (CN)
    # Find the Common Name attribute in the certificate's subject
    try:
        subject_cn = cert_to_check.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    except IndexError:
        print("ERROR: Certificate subject does not have a Common Name (CN).")
        return False

    # --- THIS IS THE FIXED LINE ---
    if subject_cn != expected_cn:
        print(f"ERROR: Certificate CN mismatch. Expected '{expected_cn}', but got '{subject_cn}'.")
        return False

    print(f"DEBUG: Common Name check PASSED.")

    # If all checks pass, the certificate is valid
    print(f"SUCCESS: Certificate for '{expected_cn}' is fully valid.")
    return True