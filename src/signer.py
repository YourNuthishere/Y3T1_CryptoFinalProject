from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding

def generate_keys(private_path="private_key.pem", public_path="public_key.pem", key_size=2048):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)

    with open(private_path, "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

    public_key = private_key.public_key()
    with open(public_path, "wb") as f:
        f.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )

    print("Keys generated successfully!")

def sign_message(private_key_path, message_path, signature_path="signature.sig"):
    with open(private_key_path, "rb") as key_file:
        private_key = serialization.load_pem_private_key(key_file.read(), password=None)

    with open(message_path, "rb") as f:
        message = f.read()

    signature = private_key.sign(
        message,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )

    with open(signature_path, "wb") as f:
        f.write(signature)

    print("Message signed successfully!")

def verify_signature(public_key_path, message_path, signature_path):
    with open(public_key_path, "rb") as key_file:
        public_key = serialization.load_pem_public_key(key_file.read())

    with open(message_path, "rb") as f:
        message = f.read()

    with open(signature_path, "rb") as f:
        signature = f.read()

    try:
        public_key.verify(
            signature,
            message,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
        print("Signature is VALID.")
        return True
    except Exception:
        print("Signature is INVALID.")
        return False
