from typing import Tuple
from mlkem.ml_kem import ML_KEM
from mlkem.parameter_set import ML_KEM_768

class KEMManager:
    """
    Manages Post-Quantum Key Encapsulation (ML-KEM-768) via mlkem.
    """
    def __init__(self, public_key: bytes = None, private_key: bytes = None):
        # fast=True ensures we are utilizing the C-compiled backend for high performance
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
        Returns: shared_secret
        """
        return self.impl.decaps(private_key, ciphertext)