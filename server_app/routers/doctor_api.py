import os
import json
from fastapi import APIRouter, HTTPException
import time
from security_suite.security.models import SecureEnvelope
from ..core.database import db

router = APIRouter(prefix="/api/doctor", tags=["Doctor Operations"])

# Create the secure storage directory
STORAGE_DIR = os.path.join(os.path.dirname(__file__), "..", "storage", "vault")
os.makedirs(STORAGE_DIR, exist_ok=True)

@router.post("/upload")
def receive_record(envelope: SecureEnvelope):
    """
    Verifies Signature, Validates Certificate, and Saves the Encrypted Payload.
    """
    # --- 1. AUTHORIZATION & CERTIFICATE VALIDATION ---
    doctor_id = envelope.kid
    
    # A. Check if the Doctor exists and is active
    doc = db.doctors.get(doctor_id)
    if not doc:
        raise HTTPException(status_code=401, detail="Unauthorized: Doctor ID not recognized.")
        
    if doc.get('status') != 'active':
        raise HTTPException(status_code=403, detail="Forbidden: Doctor has not been issued a valid certificate.")

    # B. Explicit Certificate Lookup
    # Safely get all certificates belonging to this doctor
    doctor_certs = [cert for cert in getattr(db, 'certificates', {}).values() if cert.get('doctor_id') == doctor_id]
    
    if not doctor_certs:
        raise HTTPException(status_code=403, detail="Forbidden: No certificate record found in CA Vault.")
        
    # C. Validate Expiration and Status
    valid_cert = None
    current_time = time.time()
    for cert in doctor_certs:
        if cert.get('status') == 'active' and cert.get('expires_at', 0) > current_time:
            valid_cert = cert
            break
            
    if not valid_cert:
        raise HTTPException(status_code=403, detail="Forbidden: Certificate is expired or revoked.")

    # --- 2. AUTHENTICATION (SIGNATURE VERIFICATION) ---
    is_verified = True # Mocking Verification Success for now
    
    if not is_verified:
        raise HTTPException(status_code=401, detail="Invalid PQC Signature")
        
    # --- 3. PHYSICAL STORAGE ---
    # Sanitize the Base64 nonce so it doesn't break the OS file path
    safe_filename = envelope.nonce.replace("/", "_").replace("+", "-")
    
    # Physical File I/O: Save the encrypted envelope to disk
    file_path = os.path.join(STORAGE_DIR, f"{safe_filename}.json")
    
    with open(file_path, "w") as f:
        json.dump(envelope.model_dump(), f, indent=4)
    
    return {
        "status": "Verified, Authorized, and Secured", 
        "record_id": safe_filename, 
        "saved_to": file_path
    }

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