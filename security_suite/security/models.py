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
    master_kid: str = Field(..., description="Master encryption key identifier used for DEK wrapping.")
    timestamp: int = Field(..., description="Unix timestamp when the server stored this record.")
    doctor_id: str = Field(..., description="Doctor identifier bound to this stored record.")
    patient_id: str = Field(..., description="Patient identifier used for storage and access scope.")
    envelope_version: Literal["v2"] = Field(..., description="Stored envelope schema version.")
    payload_cipher_alg: Literal["AES-256-GCM"] = Field(..., description="Payload cipher algorithm.")
    key_wrap_alg: Literal["AES-256-GCM"] = Field(..., description="Key wrapping algorithm for DEK encryption.")
    payload_nonce_b64: str = Field(..., description="Base64-encoded 12-byte AES-GCM nonce for payload encryption.")
    payload_ciphertext_b64: str = Field(..., description="Base64-encoded payload ciphertext (includes GCM tag).")
    payload_hash: str = Field(..., description="SHA-256 hex of payload encrypted bytes (nonce||ciphertext).")
    encrypted_dek_nonce_b64: str = Field(..., description="Base64-encoded 12-byte AES-GCM nonce for wrapped DEK.")
    encrypted_dek_b64: str = Field(..., description="Base64-encoded encrypted DEK bytes (includes GCM tag).")
    encrypted_dek_hash: str = Field(..., description="SHA-256 hex of encrypted DEK bytes (nonce||ciphertext).")
    aad_hash: str = Field(..., description="SHA-256 hex of storage AAD bytes.")
    record_hash: str = Field(..., description="SHA-256 hex over canonical stored record metadata and encrypted fields.")

    @field_validator("payload_cipher_alg", "key_wrap_alg")
    @classmethod
    def _validate_algorithms(cls, value: str, info):
        if value != "AES-256-GCM":
            raise ValueError(f"{info.field_name} must be AES-256-GCM")
        return value

    @field_validator("payload_nonce_b64", "encrypted_dek_nonce_b64")
    @classmethod
    def _validate_nonce_b64(cls, value: str, info):
        decoded = _decode_b64(value, info.field_name)
        if len(decoded) != 12:
            raise ValueError(f"{info.field_name} must decode to 12 bytes")
        return value

    @field_validator("payload_ciphertext_b64", "encrypted_dek_b64")
    @classmethod
    def _validate_ciphertext_b64(cls, value: str, info):
        decoded = _decode_b64(value, info.field_name)
        min_len = 48 if info.field_name == "encrypted_dek_b64" else 16
        if len(decoded) < min_len:
            raise ValueError(f"{info.field_name} is too short")
        return value

    @field_validator("payload_hash", "encrypted_dek_hash", "aad_hash", "record_hash")
    @classmethod
    def _validate_hash_fields(cls, value: str, info):
        return _require_sha256_hex(value, info.field_name)
