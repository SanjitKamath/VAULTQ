import hashlib
import hmac
from typing import Tuple

class HybridSessionManager:
    """
    Manages the derivation of the final session key using the VaultQ
    proprietary hybrid logic.
    """

    @staticmethod
    def derive_seed_hybrid_fast(sk: bytes, counter: int) -> bytes:
        """
        [PROPRIETARY ALGORITHM]
        Hybrid key-derivation stage applied to the ML-KEM shared secret.
        """
        # 1. Smooth the entropy of the PQC secret (Extract)
        prk = hmac.new(b"", sk, hashlib.sha256).digest()

        # 2. Domain separation with counter and label (Expand)
        ctr8 = counter.to_bytes(8, "big")
        info = b"pqc-stage::" + ctr8

        return hmac.new(prk, info, hashlib.sha256).digest()

    @staticmethod
    def derive_final_session_key(pqc_shared_secret: bytes, ecdh_shared_secret: bytes, counter: int = 1) -> bytes:
        """
        Combines the Hardened PQC Stage Key with the Classical ECDH Secret.
        """
        # Apply the smoothing and hardening layer to ML-KEM output
        pqc_stage_key = HybridSessionManager.derive_seed_hybrid_fast(pqc_shared_secret, counter)

        # Mix the secrets. 
        # Using the PQC key as the HMAC 'key' (salt) provides high computational 
        # security even if the ECDH secret has lower entropy.
        final_key = hmac.new(pqc_stage_key, ecdh_shared_secret, hashlib.sha256).digest()
        
        return final_key
    @staticmethod
    def generate_session_proof(key: bytes) -> str:
        """
        Generates a proof-of-possession hash of the final session key.
        """
        return hashlib.sha256(key).hexdigest()