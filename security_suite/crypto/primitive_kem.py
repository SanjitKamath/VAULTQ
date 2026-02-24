from typing import Tuple
from mlkem.ml_kem import ML_KEM
from mlkem.parameter_set import ML_KEM_768
import hmac
import hashlib

class KEMManager:
    """
    Manages Post-Quantum Key Encapsulation (ML-KEM-768) via mlkem.
    """
    def __init__(self, public_key: bytes = None, private_key: bytes = None):
        self.impl = ML_KEM(ML_KEM_768, fast=True)
        self.pk = public_key
        self.sk = private_key
        
        if not self.pk and not self.sk:
            self.pk, self.sk = self.impl.key_gen()

    def get_public_bytes(self) -> bytes:
        return self.pk

    def get_private_bytes(self) -> bytes:
        return self.sk

    def encapsulate(self, peer_public_key: bytes) -> Tuple[bytes, bytes]:
        """
        Client: Generates ciphertext & shared secret.
        Returns: (ciphertext, shared_secret)
        """
        res1, res2 = self.impl.encaps(peer_public_key)
        
        # The mlkem library returns (shared_secret, ciphertext).
        # We swap it here to strictly enforce the (ct, ss) VaultQ architecture standard.
        if len(res1) == 32:
            return res2, res1  
        
        return res1, res2

    def decapsulate(self, ciphertext: bytes, private_key: bytes) -> bytes:
        """
        Server: Recovers shared secret.
        Returns: raw_shared_secret
        """
        return self.impl.decaps(private_key, ciphertext)
    
    def harden_secret(self, raw_secret: bytes, counter: int = 1) -> bytes:
        """
        Applies entropy smoothing and domain separation to the raw KEM secret.
        This mirrors the logic from HybridSessionManager for local use.
        """
        # Step 1: Smoothing (Extract)
        prk = hmac.new(b"", raw_secret, hashlib.sha256).digest()
        
        # Step 2: Context Binding (Expand)
        ctr8 = counter.to_bytes(8, "big")
        info = b"pqc-stage::" + ctr8
        
        return hmac.new(prk, info, hashlib.sha256).digest()