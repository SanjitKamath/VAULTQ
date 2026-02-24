import hashlib
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
    log_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
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
        self.container_key = None 

    def generate_keypair(self) -> Tuple[bytes, bytes]:
        """
        Generate ML-DSA keypair using the cryptographic backend RNG.
        """
        old_pk_fp = _fingerprint(self.pk)
        old_sk_fp = _fingerprint(self.sk)
        self.audit.info(
            "DSA keygen start: previous key fingerprints pk_fp=%s sk_fp=%s",
            old_pk_fp,
            old_sk_fp,
        )
        self.audit.info(
            "DSA keygen start: previous key material present pk=%s sk=%s",
            bool(self.pk),
            bool(self.sk),
        )

        self.pk, self.sk = ML_DSA_65.keygen()

        new_pk_fp = _fingerprint(self.pk)
        new_sk_fp = _fingerprint(self.sk)
        self.audit.info(
            "DSA keygen complete: new key fingerprints pk_fp=%s sk_fp=%s",
            new_pk_fp,
            new_sk_fp,
        )
        self.audit.info(
            "DSA keygen complete: new key material generated pk=%s sk=%s",
            bool(self.pk),
            bool(self.sk),
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
