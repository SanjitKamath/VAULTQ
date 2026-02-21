import base64
import secrets
import string
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from cryptography.hazmat.primitives import serialization

from ..core.database import db
from ..core.server_state import state
from ..core.audit_logger import get_audit_logger
from ..core.auth_utils import hash_password
from security_suite.security.certificates import CertificateAuthority

router = APIRouter(prefix="/api/admin", tags=["Admin Control"])
audit = get_audit_logger()

class OnboardRequest(BaseModel):
    id: str  # <--- CRITICAL FIX: Added id
    name: str = "Unknown Doctor"
    pqc_public_key_b64: str
    tls_public_key_pem: str  # <--- New field for mTLS

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
        "active_certs": len(getattr(db, 'certificates', {})),
        "ca_status": "Online",
        "ca_algorithm": "ML-DSA-65"
    }

@router.get("/doctors")
def list_doctors():
    audit.info("Admin doctor list requested")
    return db.get_all_doctors()

@router.put("/doctors/{doctor_id}/password")
def set_doctor_password(doctor_id: str, payload: AdminPasswordUpdateRequest):
    """Admin route to reset a doctor's password securely."""
    audit.info("Admin password reset requested for doctor_id=%s", doctor_id)
    doc = db.doctors.get(doctor_id)
    if not doc:
        audit.warning("Admin password reset failed: doctor not found doctor_id=%s", doctor_id)
        raise HTTPException(status_code=404, detail="Doctor not found")

    new_password = (payload.password or "").strip()
    if not new_password:
        raise HTTPException(status_code=400, detail="Password cannot be empty")

    # CRITICAL FIX: Hash the reset password
    doc["password"] = hash_password(new_password)
    db.save_db()
    audit.info("Admin password reset succeeded for doctor_id=%s", doctor_id)
    return {"message": "Password securely updated", "doctor_id": doctor_id}

@router.post("/doctors/onboard")
def onboard_doctor(payload: OnboardRequest):
    """Receives BOTH the generated ML-DSA public key and TLS public key from the Doctor App."""
    audit.info("Doctor onboarding payload received for doctor_id=%s", payload.id)
    
    doc = db.doctors.get(payload.id)
    if not doc:
        audit.warning("Doctor onboarding rejected: unprovisioned doctor_id=%s", payload.id)
        raise HTTPException(status_code=404, detail="Doctor ID not provisioned.")
    
    # Save both public keys to the doctor's record
    doc['pqc_public_key_b64'] = payload.pqc_public_key_b64
    doc['tls_public_key_pem'] = payload.tls_public_key_pem
    
    db.save_db()
    audit.info("Doctor onboarding succeeded for doctor_id=%s (public keys enrolled)", payload.id)
    
    return {"message": "Keys enrolled successfully"}

@router.post("/doctors/{doctor_id}/issue-cert")
def issue_certificate(doctor_id: str):
    """Hospital acts as CA: Issues an X.509 cert binding TLS and PQC identities."""
    audit.info("Admin certificate issue requested for doctor_id=%s", doctor_id)
    doc = db.doctors.get(doctor_id)
    if not doc:
        audit.warning("Certificate issue failed: doctor not found doctor_id=%s", doctor_id)
        raise HTTPException(status_code=404, detail="Doctor not found")
    
    # Validation checks
    pqc_pub_key = doc.get('pqc_public_key_b64')
    tls_pub_key_pem = doc.get('tls_public_key_pem')
    if not pqc_pub_key or not tls_pub_key_pem:
        audit.warning("Certificate issue blocked: missing keys for doctor_id=%s", doctor_id)
        raise HTTPException(
            status_code=400, 
            detail="Doctor has not fully enrolled. Missing PQC or TLS public keys."
        )

    try:
        # Load PQC Public Key bytes
        pk_bytes = base64.b64decode(pqc_pub_key)
        
        # Load Classical TLS Public Key
        tls_pub_key = serialization.load_pem_public_key(tls_pub_key_pem.encode())
        
        # Generate the standard X.509 Certificate embedding both keys
        cert = CertificateAuthority.generate_doctor_certificate(
            doctor_pqc_public_bytes=pk_bytes,
            doctor_tls_public_key=tls_pub_key, 
            doctor_details={"name": doc['name'], "doctor_id": doc['id']},
            issuer_key=state.hospital_ca,
            issuer_cert=state.hospital_root_cert
        )
        
        pem_data = cert.public_bytes(serialization.Encoding.PEM).decode()
        
        # Save certificate and update status
        db.save_certificate_record(doc['id'], pem_data, cert.not_valid_after.timestamp())
        doc['status'] = 'active'
        db.save_db()
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
    
    # Assuming db.update_doctor_status is implemented in database.py
    if hasattr(db, 'update_doctor_status'):
        db.update_doctor_status(doctor_id, req.status)
    else:
        doc = db.doctors.get(doctor_id)
        if doc:
            doc['status'] = req.status
            db.save_db()
            
    audit.info("Admin status update succeeded for doctor_id=%s new_status=%s", doctor_id, req.status)
    return {"message": f"Status updated to {req.status}"}

@router.delete("/doctors/{doctor_id}")
def delete_doctor(doctor_id: str):
    """Deletes the doctor and forces a database save."""
    audit.info("Admin doctor delete requested for doctor_id=%s", doctor_id)
    if doctor_id in db.doctors:
        del db.doctors[doctor_id]
        # Also clean up certs if db.delete_doctor isn't handling it
        db.certificates = {k: v for k, v in getattr(db, 'certificates', {}).items() if v.get("doctor_id") != doctor_id}
        db.save_db()
        audit.info("Admin doctor delete succeeded for doctor_id=%s", doctor_id)
        return {"message": "Doctor deleted successfully"}
    
    audit.warning("Admin doctor delete failed: doctor not found doctor_id=%s", doctor_id)
    raise HTTPException(status_code=404, detail="Doctor not found")

@router.post("/doctors/provision")
def provision_doctor(name: str):
    """Generates random credentials, securely hashes the password, and saves to the DB."""
    audit.info("Admin doctor provision requested for name=%s", name)
    doc_id = "doc_" + secrets.token_hex(3)
    temp_pass = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(12))
    
    # Store the HASHED password, not the plaintext
    hashed_pass = hash_password(temp_pass)
    db.add_pre_authorized_doctor(doc_id, name, hashed_pass)
    
    audit.info("Admin doctor provision succeeded for doctor_id=%s", doc_id)
    
    # Only return the plaintext password ONCE to the admin to give to the doctor
    return {"id": doc_id, "password": temp_pass}