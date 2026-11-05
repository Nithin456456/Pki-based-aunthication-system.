"""
PKI-Based Authentication System - Educational Mini Project
Local demonstration of a Certificate Authority (CA), X.509 certificates,
RSA key pairs, and challenge-response digital-signature authentication.

For classroom demonstration only. The user's private key is stored locally
in the project folder for simplicity; production systems must protect it.
"""
from pathlib import Path
import argparse
import os
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import NameOID

ROOT = Path(__file__).resolve().parent
CA_DIR = ROOT / "ca"
USERS_DIR = ROOT / "users"
CA_KEY_FILE = CA_DIR / "ca_private_key.pem"
CA_CERT_FILE = CA_DIR / "ca_certificate.pem"


def ensure_dirs():
    CA_DIR.mkdir(exist_ok=True)
    USERS_DIR.mkdir(exist_ok=True)


def load_private_key(path, password=None):
    return serialization.load_pem_private_key(
        path.read_bytes(), password=password
    )


def init_ca():
    ensure_dirs()
    if CA_KEY_FILE.exists() or CA_CERT_FILE.exists():
        print("CA already exists. Remove the ca folder to create a new CA.")
        return

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "IN"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Student PKI Demo"),
        x509.NameAttribute(NameOID.COMMON_NAME, "Student Demo Root CA"),
    ])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, content_commitment=False,
                key_encipherment=False, data_encipherment=False,
                key_agreement=False, key_cert_sign=True, crl_sign=True,
                encipher_only=False, decipher_only=False
            ),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )

    CA_KEY_FILE.write_bytes(key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()
    ))
    CA_CERT_FILE.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    try:
        os.chmod(CA_KEY_FILE, 0o600)
    except OSError:
        pass
    print("Certificate Authority created successfully.")
    print(f"CA certificate: {CA_CERT_FILE}")


def register_user(username):
    ensure_dirs()
    if not CA_KEY_FILE.exists() or not CA_CERT_FILE.exists():
        print("Initialize the CA first: python pki_auth.py init-ca")
        return

    if not username.replace("_", "").replace("-", "").isalnum():
        print("Use only letters, numbers, hyphens, and underscores in usernames.")
        return

    user_dir = USERS_DIR / username
    if user_dir.exists():
        print("This username is already registered.")
        return

    user_dir.mkdir(parents=True)
    user_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_key = load_private_key(CA_KEY_FILE)
    ca_cert = x509.load_pem_x509_certificate(CA_CERT_FILE.read_bytes())

    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "IN"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "PKI Demo Users"),
        x509.NameAttribute(NameOID.COMMON_NAME, username),
    ])
    now = datetime.now(timezone.utc)
    user_cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(user_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=90))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=False
        )
        .sign(ca_key, hashes.SHA256())
    )

    (user_dir / "private_key.pem").write_bytes(user_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()
    ))
    (user_dir / "certificate.pem").write_bytes(
        user_cert.public_bytes(serialization.Encoding.PEM)
    )
    try:
        os.chmod(user_dir / "private_key.pem", 0o600)
    except OSError:
        pass

    print(f"User '{username}' registered successfully.")
    print(f"Certificate: {user_dir / 'certificate.pem'}")
    print("A demo private key was saved locally. Keep it confidential.")


def verify_certificate(cert):
    if not CA_CERT_FILE.exists():
        raise FileNotFoundError("CA certificate not found. Run init-ca first.")
    ca_cert = x509.load_pem_x509_certificate(CA_CERT_FILE.read_bytes())

    now = datetime.now(timezone.utc)
    not_before = getattr(cert, "not_valid_before_utc", cert.not_valid_before.replace(tzinfo=timezone.utc))
    not_after = getattr(cert, "not_valid_after_utc", cert.not_valid_after.replace(tzinfo=timezone.utc))
    if not_before > now or not_after < now:
        raise ValueError("Certificate is outside its validity period.")
    if cert.issuer != ca_cert.subject:
        raise ValueError("Certificate was not issued by this CA.")

    ca_cert.public_key().verify(
        cert.signature,
        cert.tbs_certificate_bytes,
        padding.PKCS1v15(),
        cert.signature_hash_algorithm
    )
    return cert


def authenticate(username):
    user_dir = USERS_DIR / username
    key_file = user_dir / "private_key.pem"
    cert_file = user_dir / "certificate.pem"
    if not key_file.exists() or not cert_file.exists():
        print("User not found. Register the user first.")
        return

    try:
        cert = verify_certificate(x509.load_pem_x509_certificate(cert_file.read_bytes()))
        private_key = load_private_key(key_file)

        # A fresh random challenge proves possession of the matching private key.
        challenge = os.urandom(32)
        signature = private_key.sign(
            challenge,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        cert.public_key().verify(
            signature,
            challenge,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        print("Certificate verification: SUCCESS")
        print("Challenge-response signature: VALID")
        print(f"Authentication successful. Welcome, {username}!")
    except Exception as exc:
        print(f"Authentication failed: {exc}")


def main():
    parser = argparse.ArgumentParser(
        description="PKI-based authentication mini project (educational demo)"
    )
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("init-ca", help="Create the demo Certificate Authority")
    reg = sub.add_parser("register", help="Register a user and issue a certificate")
    reg.add_argument("username")
    auth = sub.add_parser("login", help="Authenticate a registered user")
    auth.add_argument("username")
    args = parser.parse_args()

    if args.command == "init-ca":
        init_ca()
    elif args.command == "register":
        register_user(args.username)
    elif args.command == "login":
        authenticate(args.username)


if __name__ == "__main__":
    main()
