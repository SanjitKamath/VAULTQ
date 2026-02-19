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
        # Use HMAC-SHA256 with empty salt to "smooth" the entropy of the PQC secret.
        # This produces a pseudorandom key (PRK).
        prk = hmac.new(b"", sk, hashlib.sha256).digest()

        # Convert counter into 8-byte big-endian format.
        ctr8 = counter.to_bytes(8, "big")

        # Context label binds this derivation specifically to the PQC stage.
        info = b"pqc-stage::" + ctr8

        # Derive the final PQC stage key from the PRK and context label.
        return hmac.new(prk, info, hashlib.sha256).digest()

    @staticmethod
    def derive_final_session_key(pqc_shared_secret: bytes, ecdh_shared_secret: bytes) -> bytes:
        """
        Combines the Proprietary PQC Stage Key with the Classical ECDH Secret.
        """
        # Apply custom PQC hardening KDF layer.
        pqc_stage_key = HybridSessionManager.derive_seed_hybrid_fast(pqc_shared_secret, counter=1)

        # Combine PQC and ECDH secrets into one master session key.
        # pqc_stage_key is used as the HMAC key (acts like HKDF salt), while ecdh_secret is the input keying material.
        final_key = hmac.new(pqc_stage_key, ecdh_shared_secret, hashlib.sha256).digest()
        
        return final_key

    @staticmethod
    def generate_session_proof(key: bytes) -> str:
        """
        Generates a proof-of-possession hash of the final session key.
        """
        return hashlib.sha256(key).hexdigest()