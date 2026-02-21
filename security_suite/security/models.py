from pydantic import BaseModel, Field

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
    Server-side envelope stored at rest after master-key encryption.
    """
    master_kid: str
    timestamp: int
    patient_id: str
    payload: str
    payload_hash: str       # SHA-256 of decoded payload bytes (nonce||ciphertext)
    record_hash: str        # SHA-256 over canonical record metadata + payload
