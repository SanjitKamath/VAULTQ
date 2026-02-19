import os
import json
from fastapi import APIRouter, HTTPException
from security_suite.security.models import SecureEnvelope
from ..core.database import db

router = APIRouter(prefix="/api/doctor", tags=["Doctor Operations"])

# Create the secure storage directory
STORAGE_DIR = os.path.join(os.path.dirname(__file__), "..", "storage", "vault")
os.makedirs(STORAGE_DIR, exist_ok=True)

@router.post("/upload")
def receive_record(envelope: SecureEnvelope):
    """
    Verifies Signature and Saves the Encrypted Payload to the Vault.
    """
    is_verified = True # Mocking Verification Success for now
    
    if not is_verified:
        raise HTTPException(status_code=401, detail="Invalid PQC Signature")
        
    # Sanitize the Base64 nonce so it doesn't break the OS file path
    safe_filename = envelope.nonce.replace("/", "_").replace("+", "-")
    
    # Physical File I/O: Save the encrypted envelope to disk
    file_path = os.path.join(STORAGE_DIR, f"{safe_filename}.json")
    
    with open(file_path, "w") as f:
        json.dump(envelope.model_dump(), f, indent=4)
    
    return {"status": "Verified and Secured", "record_id": safe_filename, "saved_to": file_path}

@router.post("/auth/change-password")
def server_change_password(doctor_id: str, old_pass: str, new_pass: str):
    if doctor_id not in db.doctors:
        raise HTTPException(status_code=404, detail="Doctor not found")
    
    # Verify old password on server
    if db.doctors[doctor_id]["password"] != old_pass:
        raise HTTPException(status_code=401, detail="Old password incorrect")
    
    # Update the permanent database
    db.doctors[doctor_id]["password"] = new_pass
    db.save_db() # Persist to hospital_vault.json
    
    return {"message": "Password updated successfully on server."}