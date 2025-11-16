"""RSA PKCS#1 v1.5 SHA-256 sign/verify."""

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.exceptions import InvalidSignature

def load_private_key(key_pem_path: str) -> rsa.RSAPrivateKey:
    """Loads an RSA private key from a PEM file."""
    with open(key_pem_path, "rb") as f:
        key_data = f.read()
    
    private_key = serialization.load_pem_private_key(
        key_data,
        password=None  # Assuming no password
    )
    return private_key

def load_public_key_from_cert(cert_pem_path: str) -> rsa.RSAPublicKey:
    """Loads an RSA public key from a PEM certificate file."""
    with open(cert_pem_path, "rb") as f:
        cert_data = f.read()
    
    cert = x509.load_pem_x509_certificate(cert_data)
    public_key = cert.public_key()
    
    if not isinstance(public_key, rsa.RSAPublicKey):
        raise TypeError("Certificate does not contain an RSA public key")
        
    return public_key

def sign(private_key: rsa.RSAPrivateKey, data: bytes) -> bytes:
    """
    Signs data with a private key using RSA-SHA256 and PKCS#1 v1.5 padding.
    """
    signature = private_key.sign(
        data,
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    return signature

def verify(public_key: rsa.RSAPublicKey, data: bytes, signature: bytes) -> bool:
    """
    Verifies a signature with a public key using RSA-SHA256 and PKCS#1 v1.5.
    Returns True if valid, False otherwise.
    """
    try:
        public_key.verify(
            signature,
            data,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        # Signature is valid
        return True
    except InvalidSignature:
        # Signature is invalid
        return False
    except Exception as e:
        print(f"An error occurred during signature verification: {e}")
        return False