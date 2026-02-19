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
    payload: str            # AES Encrypted Data (Base64)
    signature: str          # ML-DSA Signature of (payload + header)