import base64
import binascii
import re
from typing import Literal
from pydantic import BaseModel, Field, field_validator

_SHA256_HEX_RE = re.compile(r"^[a-f0-9]{64}$")


def _decode_b64(value: str, field_name: str) -> bytes:
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError(f"{field_name} must be valid base64") from exc


def _require_sha256_hex(value: str, field_name: str) -> str:
    if not _SHA256_HEX_RE.fullmatch(value.lower()):
        raise ValueError(f"{field_name} must be 64 hex chars")
    return value.lower()

class KeyID(BaseModel):
    kid: str = Field(..., description="Hash of the public key acting as ID")
    alg: str = Field(..., description="Algorithm used (e.g., 'ML-DSA-65', 'Hybrid-KEM')")
    created_at: int

class ValidityCertificate(BaseModel):
    """
    Issued by Hospital (CA) to the Doctor.
    Verifies that a specific 'doctor_public_key' belongs to a valid doctor.
    """
    cert_id: str
    doctor_name: str
    doctor_public_key: str  
    issuer_id: str          
    valid_until: int
    signature: str          

class SecureEnvelope(BaseModel):
    """
    The standard container for ALL transmissions.
    """
    kid: str                # ID of the key used to sign/encrypt
    nonce: str              # Anti-replay
    timestamp: int          # Validity window check
    patient_id: str         # For routing and access control
    payload: str            # AES Encrypted Data (Base64)
    payload_hash: str       # SHA-256 hash of encrypted payload bytes
    signature: str          # ML-DSA Signature over canonical context (includes payload_hash + metadata)


class StoredVaultEnvelope(BaseModel):
    """
    Server-side envelope stored at rest with per-record envelope encryption.
    """
    master_kid: str
    timestamp: int
    patient_id: str
    payload: str
    payload_hash: str       # SHA-256 of decoded payload bytes (nonce||ciphertext)
    record_hash: str        # SHA-256 over canonical record metadata + payload
    hospital_signature: str # ML-DSA-65 signature over canonical record message
    hospital_pub: str       # Hospital public key at time of signing (rotation-safe)
    hospital_sig_alg: str   # Algorithm identifier (e.g. "ML-DSA-65")
