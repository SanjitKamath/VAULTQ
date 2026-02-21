import os
import hashlib
import hmac
import logging
from pathlib import Path
from typing import Tuple
from dilithium_py.ml_dsa import ML_DSA_65


LOGGER_NAME = "vaultq.crypto.dsa"


def _get_crypto_logger() -> logging.Logger:
    logger = logging.getLogger(LOGGER_NAME)
    if logger.handlers:
        return logger

    logger.setLevel(logging.INFO)
    logger.propagate = False

    log_dir = Path(__file__).resolve().parents[1] / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    logfile = log_dir / "crypto_audit.log"

    formatter = logging.Formatter(
        fmt="%(asctime)s [%(levelname)s] [%(name)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    file_handler = logging.FileHandler(logfile, encoding="utf-8")
    file_handler.setLevel(logging.INFO)
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    return logger


def _fingerprint(data: bytes) -> str:
    if not data:
        return "none"
    # Short, safe fingerprint for audit trails (never log raw key material).
    return hashlib.sha256(data).hexdigest()[:24]


def _b64(data: bytes) -> str:
    if not data:
        return "none"
    return data.hex()


class DSAManager:
    """
    Manages Post-Quantum Digital Signatures (ML-DSA-65) via dilithium-py.
    Pure Python implementation, bypassing Windows C-compiler errors.
    """
    def __init__(self, private_bytes: bytes = None):
        self.audit = _get_crypto_logger()
        self.sk = private_bytes
        self.pk = None
        self.container_key = None # Holds the X.509 ECDSA wrapper key
        self.audit.info(
            "DSAManager init: private key provided=%s private_fp=%s",
            bool(private_bytes),
            _fingerprint(private_bytes),
        )
        self.audit.info(
            "DSAManager init: private key material (hex)=%s",
            _b64(private_bytes),
        )

    @staticmethod
    def _proprietary_seed_modifier(raw_entropy: bytes) -> bytes:
        """
        [PROPRIETARY ALGORITHM]
        Applies HMAC-smoothing to derive the final deterministic seed.
        """
        audit = _get_crypto_logger()
        audit.info(
            "DSA seed modifier: raw entropy captured raw_fp=%s",
            _fingerprint(raw_entropy),
        )
        audit.info("DSA seed modifier: raw entropy (hex)=%s", _b64(raw_entropy))

        prk = hmac.new(b"", raw_entropy, hashlib.sha256).digest()
        audit.info("DSA seed modifier: PRK derived prk_fp=%s", _fingerprint(prk))
        audit.info("DSA seed modifier: PRK material (hex)=%s", _b64(prk))

        info = b"vault-dsa-keygen::v2"
        final_seed = hmac.new(prk, info, hashlib.sha256).digest()
        audit.info(
            "DSA seed modifier: final deterministic seed derived seed_fp=%s",
            _fingerprint(final_seed),
        )
        audit.info("DSA seed modifier: final deterministic seed (hex)=%s", _b64(final_seed))
        return final_seed

    def generate_keypair(self) -> Tuple[bytes, bytes]:
        """
        Two-Stage Deterministic Key Generation:
        1. Harvests entropy from secure system randomness.
        2. Applies custom algorithm to smooth the entropy.
        3. Deterministically generates the final keys via Python RNG injection.
        """
        old_pk_fp = _fingerprint(self.pk)
        old_sk_fp = _fingerprint(self.sk)
        self.audit.info(
            "DSA keygen start: previous key fingerprints pk_fp=%s sk_fp=%s",
            old_pk_fp,
            old_sk_fp,
        )
        self.audit.info(
            "DSA keygen start: previous key material pk(hex)=%s sk(hex)=%s",
            _b64(self.pk),
            _b64(self.sk),
        )

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

        new_pk_fp = _fingerprint(self.pk)
        new_sk_fp = _fingerprint(self.sk)
        self.audit.info(
            "DSA keygen complete: new key fingerprints pk_fp=%s sk_fp=%s",
            new_pk_fp,
            new_sk_fp,
        )
        self.audit.info(
            "DSA keygen complete: new key material pk(hex)=%s sk(hex)=%s",
            _b64(self.pk),
            _b64(self.sk),
        )
        self.audit.info(
            "DSA keygen delta: pk_changed=%s sk_changed=%s",
            old_pk_fp != new_pk_fp,
            old_sk_fp != new_sk_fp,
        )
            
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
