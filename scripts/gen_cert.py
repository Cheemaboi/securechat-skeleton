"""Issue server/client cert signed by Root CA (SAN=DNSName(CN))."""

import argparse
import datetime
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

# --- Helper function to load the CA ---
def load_ca(ca_cert_path, ca_key_path):
    """Loads the CA's certificate and private key from PEM files."""
    try:
        with open(ca_cert_path, "rb") as f:
            ca_cert = x509.load_pem_x509_certificate(f.read())
        
        with open(ca_key_path, "rb") as f:
            ca_key = serialization.load_pem_private_key(f.read(), password=None)
            
        return ca_cert, ca_key
    except FileNotFoundError:
        print(f"Error: CA files not found. Did you run 'gen_ca.py' first?")
        print(f"Missing: {ca_cert_path} or {ca_key_path}")
        exit(1)

def main():
    parser = argparse.ArgumentParser(description="Issue client/server certificate")
    parser.add_argument("--cn", required=True, help="Common Name for the certificate (e.g., server.local)")
    parser.add_argument("--out", required=True, help="Output file basename (e.g., certs/server)")
    args = parser.parse_args()

    # Define CA paths
    certs_dir = Path("certs")
    ca_key_path = certs_dir / "ca_key.pem"
    ca_cert_path = certs_dir / "ca_cert.pem"

    # Define output paths for the new cert
    out_key_path = Path(f"{args.out}_key.pem")
    out_cert_path = Path(f"{args.out}_cert.pem")

    # 1. Load the Root CA certificate and private key
    print(f"Loading Root CA from: {ca_cert_path}")
    ca_cert, ca_key = load_ca(ca_cert_path, ca_key_path)

    # 2. Generate a new RSA private key for the entity (server or client)
    print(f"Generating new private key: {out_key_path}")
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    # 3. Save the new private key to a PEM file
    with open(out_key_path, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    # 4. Build the X.509 certificate
    public_key = private_key.public_key()

    # Define the certificate's subject
    # It's good practice to copy some fields from the CA
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, ca_cert.subject.get_attributes_for_oid(NameOID.COUNTRY_NAME)[0].value),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, ca_cert.subject.get_attributes_for_oid(NameOID.STATE_OR_PROVINCE_NAME)[0].value),
        x509.NameAttribute(NameOID.LOCALITY_NAME, ca_cert.subject.get_attributes_for_oid(NameOID.LOCALITY_NAME)[0].value),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, ca_cert.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)[0].value),
        x509.NameAttribute(NameOID.COMMON_NAME, args.cn), # The CN provided (e.g., "server.local")
    ])

    # Get the current time
    now = datetime.datetime.utcnow()

    # Create the certificate builder
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        ca_cert.subject  # The issuer is the CA's subject
    ).public_key(
        public_key
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        now
    ).not_valid_after(
        # Valid for 2 years
        now + datetime.timedelta(days=730)
    ).add_extension(
        # This is NOT a CA
        x509.BasicConstraints(ca=False, path_length=None), critical=True
    ).add_extension(
        # This extension is required for modern validation
        # It states what domain names this cert is valid for
        x509.SubjectAlternativeName([x509.DNSName(args.cn)]), critical=False
    ).sign(ca_key, hashes.SHA256()) # Sign the cert with the CA's private key

    # 5. Save the new certificate to a PEM file
    with open(out_cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    print(f"Certificate issued successfully: {out_cert_path}")
    print("Success! Certificate generation complete.")

if __name__ == "__main__":
    main()