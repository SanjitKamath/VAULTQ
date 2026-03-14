from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization

def generate_rsa_keys():
    """Generates a new RSA key pair."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    return private_key, public_key

def serialize_public_key(public_key):
    """Serializes a public key to PEM format."""
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def serialize_private_key(private_key):
    """Serializes a private key to PEM format."""
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

def load_public_key(pem_data):
    """Loads a public key from PEM data."""
    return serialization.load_pem_public_key(pem_data)

def load_private_key(pem_data):
    """Loads a private key from PEM data."""
    return serialization.load_pem_private_key(pem_data, password=None)

def rsa_encrypt(public_key, plaintext):
    """Encrypts plaintext using RSA-OAEP."""
    return public_key.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def rsa_decrypt(private_key, ciphertext):
    """Decrypts ciphertext using RSA-OAEP."""
    return private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def rsa_sign(private_key, message):
    """Signs a message using RSA-PSS."""
    return private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

def rsa_verify(public_key, message, signature):
    """Verifies a signature using RSA-PSS."""
    try:
        public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False

class RSAManager:
    def __init__(self, private_bytes=None):
        if private_bytes:
            self.private_key = load_private_key(private_bytes)
            self.public_key = self.private_key.public_key()
        else:
            self.private_key, self.public_key = generate_rsa_keys()

    def get_public_bytes(self):
        return serialize_public_key(self.public_key)

    def get_private_bytes(self):
        return serialize_private_key(self.private_key)

    def sign(self, message):
        return rsa_sign(self.private_key, message)

    def verify(self, message, signature, public_key_pem=None):
        key_to_use = self.public_key
        if public_key_pem:
            key_to_use = load_public_key(public_key_pem)
        return rsa_verify(key_to_use, message, signature)

    def decapsulate(self, ciphertext):
        return rsa_decrypt(self.private_key, ciphertext)
