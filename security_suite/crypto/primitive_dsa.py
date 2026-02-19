import os
import hashlib
import hmac
from typing import Tuple
from dilithium_py.ml_dsa import ML_DSA_65

class DSAManager:
    """
    Manages Post-Quantum Digital Signatures (ML-DSA-65) via dilithium-py.
    Pure Python implementation, bypassing Windows C-compiler errors.
    """
    def __init__(self, private_bytes: bytes = None):
        self.sk = private_bytes
        self.pk = None
        self.container_key = None # Holds the X.509 ECDSA wrapper key

    @staticmethod
    def _proprietary_seed_modifier(raw_entropy: bytes) -> bytes:
        """
        [PROPRIETARY ALGORITHM]
        Applies HMAC-smoothing to derive the final deterministic seed.
        """
        prk = hmac.new(b"", raw_entropy, hashlib.sha256).digest()
        info = b"vault-dsa-keygen::v2"
        return hmac.new(prk, info, hashlib.sha256).digest()

    def generate_keypair(self) -> Tuple[bytes, bytes]:
        """
        Two-Stage Deterministic Key Generation:
        1. Harvests entropy from secure system randomness.
        2. Applies custom algorithm to smooth the entropy.
        3. Deterministically generates the final keys via Python RNG injection.
        """
        # Step 1: Harvest 32 bytes of raw system entropy
        raw_entropy = os.urandom(32)
        
        # Step 2: Execute your custom algorithm
        final_seed = self._proprietary_seed_modifier(raw_entropy)
        
        # Step 3: Inject the smoothed seed directly into Python's RNG stream
        original_urandom = os.urandom
        def custom_urandom(n: int) -> bytes:
            return (final_seed * (n // len(final_seed) + 1))[:n]
            
        try:
            # Intercept the system RNG that dilithium-py relies on
            os.urandom = custom_urandom
            self.pk, self.sk = ML_DSA_65.keygen()
        finally:
            # CRITICAL: Restore the secure system RNG immediately
            os.urandom = original_urandom
            
        return self.pk, self.sk

    def get_public_bytes(self) -> bytes:
        return self.pk

    def get_private_bytes(self) -> bytes:
        return self.sk

    def sign(self, message: bytes) -> bytes:
        if not self.sk:
            raise ValueError("Private key required for signing.")
        return ML_DSA_65.sign(self.sk, message)

    def verify(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        return ML_DSA_65.verify(public_key, message, signature)