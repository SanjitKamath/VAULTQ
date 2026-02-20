import base64
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from cryptography.hazmat.primitives import serialization

from ..core.database import db, DoctorRecord, CertRecord
from ..core.server_state import state
from security_suite.security.certificates import CertificateAuthority

import secrets
import string

router = APIRouter(prefix="/api/admin", tags=["Admin Control"])

class OnboardRequest(BaseModel):
    id: str
    name: str = "Unknown Doctor"
    pqc_public_key_b64: str

class StatusUpdateRequest(BaseModel):
    status: str

@router.get("/stats")
def get_system_stats():
    docs = db.get_all_doctors()
    return {
        "total_doctors": len(docs),
        "active_certs": len(db.certificates),
        "ca_status": "Online",
        "ca_algorithm": "ML-DSA-65"
    }

@router.get("/doctors")
def list_doctors():
    return db.get_all_doctors()

@router.post("/doctors/onboard")
def onboard_doctor(payload: OnboardRequest):
    """Receives the generated ML-DSA public key from the Doctor App."""
    
    # Use .get() to safely access the dictionary
    doc = db.doctors.get(payload.id)
    if not doc:
        raise HTTPException(status_code=404, detail="Doctor ID not provisioned.")
    
    # Save the public key to the doctor's record
    doc['pqc_public_key_b64'] = payload.pqc_public_key_b64
    
    # Save immediately to hospital_vault.json
    db.save_db()
    
    return {"message": "PQC Key enrolled successfully"}

@router.post("/doctors/{doctor_id}/issue-cert")
def issue_certificate(doctor_id: str):
    """Hospital acts as CA: Issues an X.509 cert to the Doctor."""
    doc = db.doctors.get(doctor_id) # Fetches the dict
    if not doc:
        raise HTTPException(status_code=404, detail="Doctor not found")
    
    # Check if the doctor has actually performed the PQC enrollment
    pqc_pub_key = doc.get('pqc_public_key_b64')
    if not pqc_pub_key:
        raise HTTPException(
            status_code=400, 
            detail="Doctor has not enrolled. They must log in to the Doctor App first."
        )

    try:
        # Use bracket notation for dict access
        pk_bytes = base64.b64decode(pqc_pub_key)
        
        cert = CertificateAuthority.generate_doctor_certificate(
            doctor_public_key_bytes=pk_bytes,
            doctor_details={"name": doc['name'], "doctor_id": doc['id']},
            issuer_key=state.hospital_ca,
            issuer_cert=state.hospital_root_cert
        )
        
        pem_data = cert.public_bytes(serialization.Encoding.PEM).decode()
        
        # Save certificate and update status
        db.save_certificate_record(doc['id'], pem_data, cert.not_valid_after.timestamp())
        doc['status'] = 'active'
        db.save_db() # Persist changes immediately
        
        return {"message": "Certificate Issued", "status": "active"}
    except Exception as e:
        print(f"Cert Error: {e}")
        raise HTTPException(status_code=500, detail="Failed to generate PQC Certificate")
    
@router.put("/doctors/{doctor_id}/status")
def update_status(doctor_id: str, req: StatusUpdateRequest):
    """RBAC Control: Revoke or suspend doctors."""
    if req.status not in ["pending", "active", "revoked"]:
        raise HTTPException(status_code=400, detail="Invalid status")
    db.update_doctor_status(doctor_id, req.status)
    return {"message": f"Status updated to {req.status}"}

@router.delete("/doctors/{doctor_id}")
def delete_doctor(doctor_id: str):
    """Deletes the doctor and forces a database save."""
    success = db.delete_doctor(doctor_id)
    if not success:
        raise HTTPException(status_code=404, detail="Doctor not found")
    return {"message": "Doctor deleted successfully"}

@router.post("/doctors/provision")
def provision_doctor(name: str):
    """Generates random credentials and saves them to the persistent JSON."""
    doc_id = "doc_" + secrets.token_hex(3)
    temp_pass = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(10))
    
    # This method must call db.save_db() internally to reflect on disk immediately
    db.add_pre_authorized_doctor(doc_id, name, temp_pass)
    
    return {"id": doc_id, "password": temp_pass}