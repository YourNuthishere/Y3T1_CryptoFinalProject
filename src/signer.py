import os
import hashlib
import datetime
import json
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding

# ------------------------------
# Generate RSA keys
# ------------------------------
def generate_keys(key_size=2048, priv_path="private_key.pem", pub_path="public_key.pem"):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    public_key = private_key.public_key()

    with open(priv_path, "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

    with open(pub_path, "wb") as f:
        f.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )

    modulus = public_key.public_numbers().n
    exponent = public_key.public_numbers().e
    return {"private": priv_path, "public": pub_path, "modulus_bits": modulus.bit_length(), "exponent": exponent}


# ------------------------------
# Sign a file
# ------------------------------
def sign_file(private_key_path, file_path, sig_path="signature.sig"):
    if not os.path.exists(private_key_path) or not os.path.exists(file_path):
        raise FileNotFoundError("Private key or file not found.")

    # Load private key
    with open(private_key_path, "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)

    # Read file
    with open(file_path, "rb") as f:
        message = f.read()

    # Sign
    signature = private_key.sign(
        message,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )

    with open(sig_path, "wb") as f:
        f.write(signature)

    # SHA-256 hash
    file_hash = hashlib.sha256(message).hexdigest()
    return {"signature_path": sig_path, "sha256": file_hash}


# ------------------------------
# Verify signature
# ------------------------------
def verify_file(public_key_path, file_path, sig_path):
    if not os.path.exists(public_key_path) or not os.path.exists(file_path) or not os.path.exists(sig_path):
        raise FileNotFoundError("Public key, file, or signature not found.")

    # Load public key
    with open(public_key_path, "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())

    # Load message & signature
    with open(file_path, "rb") as f:
        message = f.read()
    with open(sig_path, "rb") as f:
        signature = f.read()

    # Verify
    try:
        public_key.verify(
            signature,
            message,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
        result = True
    except Exception:
        result = False

    # SHA-256 hash
    file_hash = hashlib.sha256(message).hexdigest()
    return {"valid": result, "sha256": file_hash}


# ------------------------------
# Export verification report
# ------------------------------
def export_report(file_name, public_key_name, signature_status, sha256_hash, report_path="report.json"):
    report = {
        "File": file_name,
        "Signature": "VALID" if signature_status else "INVALID",
        "Public Key": public_key_name,
        "SHA-256": sha256_hash,
        "Timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    }
    with open(report_path, "w") as f:
        json.dump(report, f, indent=4)
    return report_path
