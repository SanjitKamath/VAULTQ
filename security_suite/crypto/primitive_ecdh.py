from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

class ECDHManager:
    """
    Manages Classical ECDH (NIST P-256).
    """
    def __init__(self, private_key: ec.EllipticCurvePrivateKey = None):
        if private_key:
            self.private_key = private_key
        else:
            self.private_key = ec.generate_private_key(ec.SECP256R1())
        
        self.public_key = self.private_key.public_key()

    def get_public_bytes(self) -> bytes:
        # Returns the server's ECDH public key in raw uncompressed point format.
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint
        )

    def compute_shared_secret(self, peer_bytes: bytes) -> bytes:
        # Reconstruct the client's public key from received bytes.
        peer_key = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(), peer_bytes
        )
        # Perform ECDH key exchange.
        return self.private_key.exchange(ec.ECDH(), peer_key)