import base64
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from cryptography.hazmat.primitives import serialization

from ..core.database import db, DoctorRecord, CertRecord
from ..core.server_state import state
from ..core.audit_logger import get_audit_logger
from security_suite.security.certificates import CertificateAuthority

import secrets
import string

router = APIRouter(prefix="/api/admin", tags=["Admin Control"])
audit = get_audit_logger()

class OnboardRequest(BaseModel):
    id: str
    name: str = "Unknown Doctor"
    pqc_public_key_b64: str

class StatusUpdateRequest(BaseModel):
    status: str

class AdminPasswordUpdateRequest(BaseModel):
    password: str

@router.get("/stats")
def get_system_stats():
    audit.info("Admin stats requested")
    docs = db.get_all_doctors()
    return {
        "total_doctors": len(docs),
        "active_certs": len(db.certificates),
        "ca_status": "Online",
        "ca_algorithm": "ML-DSA-65"
    }

@router.get("/doctors")
def list_doctors():
    audit.info("Admin doctor list requested")
    return db.get_all_doctors()

@router.get("/doctors/{doctor_id}/password")
def get_doctor_password(doctor_id: str):
    audit.info("Admin password read requested for doctor_id=%s", doctor_id)
    doc = db.doctors.get(doctor_id)
    if not doc:
        audit.warning("Admin password read failed: doctor not found doctor_id=%s", doctor_id)
        raise HTTPException(status_code=404, detail="Doctor not found")
    return {"doctor_id": doctor_id, "password": doc.get("password", "")}

@router.put("/doctors/{doctor_id}/password")
def set_doctor_password(doctor_id: str, payload: AdminPasswordUpdateRequest):
    audit.info("Admin password update requested for doctor_id=%s", doctor_id)
    doc = db.doctors.get(doctor_id)
    if not doc:
        audit.warning("Admin password update failed: doctor not found doctor_id=%s", doctor_id)
        raise HTTPException(status_code=404, detail="Doctor not found")

    new_password = (payload.password or "").strip()
    if not new_password:
        audit.warning("Admin password update failed: empty password doctor_id=%s", doctor_id)
        raise HTTPException(status_code=400, detail="Password cannot be empty")

    doc["password"] = new_password
    db.save_db()
    audit.info("Admin password update succeeded for doctor_id=%s", doctor_id)
    return {"message": "Password updated", "doctor_id": doctor_id}

@router.post("/doctors/onboard")
def onboard_doctor(payload: OnboardRequest):
    """Receives the generated ML-DSA public key from the Doctor App."""
    audit.info("Doctor onboarding payload received for doctor_id=%s", payload.id)
    
    # Use .get() to safely access the dictionary
    doc = db.doctors.get(payload.id)
    if not doc:
        audit.warning("Doctor onboarding rejected: unprovisioned doctor_id=%s", payload.id)
        raise HTTPException(status_code=404, detail="Doctor ID not provisioned.")
    
    # Save the public key to the doctor's record
    doc['pqc_public_key_b64'] = payload.pqc_public_key_b64
    
    # Save immediately to hospital_vault.json
    db.save_db()
    audit.info("Doctor onboarding succeeded for doctor_id=%s (public key enrolled)", payload.id)
    
    return {"message": "PQC Key enrolled successfully"}

@router.post("/doctors/{doctor_id}/issue-cert")
def issue_certificate(doctor_id: str):
    """Hospital acts as CA: Issues an X.509 cert to the Doctor."""
    audit.info("Admin certificate issue requested for doctor_id=%s", doctor_id)
    doc = db.doctors.get(doctor_id) # Fetches the dict
    if not doc:
        audit.warning("Certificate issue failed: doctor not found doctor_id=%s", doctor_id)
        raise HTTPException(status_code=404, detail="Doctor not found")
    
    # Check if the doctor has actually performed the PQC enrollment
    pqc_pub_key = doc.get('pqc_public_key_b64')
    if not pqc_pub_key:
        audit.warning("Certificate issue blocked: doctor not onboarded doctor_id=%s", doctor_id)
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
        audit.info("Certificate issued successfully for doctor_id=%s", doctor_id)
        
        return {"message": "Certificate Issued", "status": "active"}
    except Exception as e:
        audit.exception("Certificate issuance failed for doctor_id=%s: %s", doctor_id, str(e))
        raise HTTPException(status_code=500, detail="Failed to generate PQC Certificate")
    
@router.put("/doctors/{doctor_id}/status")
def update_status(doctor_id: str, req: StatusUpdateRequest):
    """RBAC Control: Revoke or suspend doctors."""
    if req.status not in ["pending", "active", "revoked"]:
        audit.warning("Admin status update failed: invalid status=%s doctor_id=%s", req.status, doctor_id)
        raise HTTPException(status_code=400, detail="Invalid status")
    db.update_doctor_status(doctor_id, req.status)
    audit.info("Admin status update succeeded for doctor_id=%s new_status=%s", doctor_id, req.status)
    return {"message": f"Status updated to {req.status}"}

@router.delete("/doctors/{doctor_id}")
def delete_doctor(doctor_id: str):
    """Deletes the doctor and forces a database save."""
    audit.info("Admin doctor delete requested for doctor_id=%s", doctor_id)
    success = db.delete_doctor(doctor_id)
    if not success:
        audit.warning("Admin doctor delete failed: doctor not found doctor_id=%s", doctor_id)
        raise HTTPException(status_code=404, detail="Doctor not found")
    audit.info("Admin doctor delete succeeded for doctor_id=%s", doctor_id)
    return {"message": "Doctor deleted successfully"}

@router.post("/doctors/provision")
def provision_doctor(name: str):
    """Generates random credentials and saves them to the persistent JSON."""
    audit.info("Admin doctor provision requested for name=%s", name)
    doc_id = "doc_" + secrets.token_hex(3)
    temp_pass = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(10))
    
    # This method must call db.save_db() internally to reflect on disk immediately
    db.add_pre_authorized_doctor(doc_id, name, temp_pass)
    audit.info("Admin doctor provision succeeded for doctor_id=%s", doc_id)
    
    return {"id": doc_id, "password": temp_pass}
