"""Create Root CA (RSA + self-signed X.509) using cryptography."""

import argparse
import datetime
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

def main():
    parser = argparse.ArgumentParser(description="Create Root CA")
    parser.add_argument("--name", required=True, help="Common Name (CN) for the Root CA")
    args = parser.parse_args()

    # Define output paths
    certs_dir = Path("certs")
    certs_dir.mkdir(exist_ok=True) # Create 'certs/' folder if it doesn't exist
    key_path = certs_dir / "ca_key.pem"
    cert_path = certs_dir / "ca_cert.pem"

    print(f"Generating Root CA private key: {key_path}")
    
    # 1. Generate a new RSA private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    # 2. Save the private key to a PEM file
    with open(key_path, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    # 3. Build the X.509 certificate (self-signed)
    public_key = private_key.public_key()
    
    # Define the certificate's subject and issuer
    # For a self-signed cert, the subject and issuer are the same.
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"PK"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Punjab"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Islamabad"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"FAST-NUCES"),
        x509.NameAttribute(NameOID.COMMON_NAME, args.name), # e.g., "FAST-NU Root CA"
    ])

    # Get the current time
    now = datetime.datetime.utcnow()

    # Create the certificate builder
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        public_key
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        now
    ).not_valid_after(
        # Valid for 10 years
        now + datetime.timedelta(days=3650)
    ).add_extension(
        # This extension marks the cert as a CA
        x509.BasicConstraints(ca=True, path_length=None), critical=True
    ).sign(private_key, hashes.SHA256()) # Sign the cert with its own private key

    # 4. Save the certificate to a PEM file
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    print(f"Root CA certificate saved: {cert_path}")
    print("Success! CA generation complete.")

if __name__ == "__main__":
    main()