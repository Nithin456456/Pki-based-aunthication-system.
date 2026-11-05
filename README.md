# PKI-Based Authentication System
## Mini Project - Network Security / Cryptography

### Abstract
This project demonstrates Public Key Infrastructure (PKI) based authentication.
A local Certificate Authority (CA) creates and signs X.509 user certificates.
During login, the application validates the certificate and verifies a fresh
challenge-response digital signature using the certificate's public key.

### Objectives
- Generate RSA public/private key pairs.
- Create a root Certificate Authority.
- Issue X.509 digital certificates to users.
- Verify certificate issuer, validity period, and CA signature.
- Demonstrate authentication using a digital signature.

### Technologies
- Python 3.10+
- RSA (2048-bit)
- SHA-256
- X.509 certificates
- `cryptography` Python package

### Project structure
```text
PKI_Based_Authentication_System/
├── pki_auth.py
├── requirements.txt
├── README.md
├── ca/       (created when the CA is initialized)
└── users/    (created when users are registered)
```

### Installation
1. Install Python 3.10 or later.
2. Open a terminal in this project folder.
3. Install the dependency:

   `python -m pip install -r requirements.txt`

### Execution
**Step 1 - Create the Certificate Authority**
```bash
python pki_auth.py init-ca
```

**Step 2 - Register a user and issue a certificate**
```bash
python pki_auth.py register nithin
```

**Step 3 - Authenticate the user**
```bash
python pki_auth.py login nithin
```

### Sample output
```text
Certificate Authority created successfully.
User 'nithin' registered successfully.
Certificate verification: SUCCESS
Challenge-response signature: VALID
Authentication successful. Welcome, nithin!
```

### Algorithm
1. Start the application.
2. Create an RSA key pair for the Certificate Authority.
3. Create a self-signed root CA certificate.
4. Generate an RSA key pair for a new user.
5. Create an X.509 certificate containing the user's public key.
6. Sign the user certificate with the CA private key.
7. During login, validate the certificate's issuer and validity period.
8. Verify the certificate signature using the CA public key.
9. Generate a random challenge and sign it using the user's private key.
10. Verify the signature using the public key in the certificate.
11. If verification succeeds, display authentication successful; otherwise reject login.

### Modules
- CA Creation
- User Registration
- RSA Key Generation
- X.509 Certificate Issuing
- Certificate Validation
- Digital Signature Authentication

### Security note / limitations
This is a local classroom demonstration, not a production authentication service.
For simplicity, the demo stores the user's private key unencrypted on the same
computer and performs signing locally. A real deployment must keep private keys
under the user's control in protected storage or a hardware-backed key store,
use encrypted transport, implement certificate revocation checking (CRL/OCSP),
and apply secure account and access controls. Do not use real passwords,
personal certificates, or sensitive data in this demo.

### Conclusion
The project demonstrates how PKI establishes trust through a Certificate
Authority and X.509 certificates. RSA digital signatures and challenge-response
verification help prove that a user possesses the private key corresponding to
the public key in the certificate.
