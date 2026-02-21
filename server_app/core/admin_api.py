import secrets
import string
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization

from ..core.database import db
from ..core.server_state import state
from ..core.audit_logger import get_audit_logger
from ..core.auth_utils import hash_password
from ..core.ca_setup import load_hospital_ca_signer
from security_suite.security.certificates import (
    CertificateAuthority,
    load_pem_csr,
    verify_csr_signature,
    extract_pqc_public_key_from_csr,
)

router = APIRouter(prefix="/api/admin", tags=["Admin Control"])
audit = get_audit_logger()

class OnboardRequest(BaseModel):
    id: str
    csr_pem: str

class StatusUpdateRequest(BaseModel):
    status: str


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
def set_doctor_password(doctor_id: str):
    """
    Deprecated insecure path.
    Password resets must use admin-authenticated recovery in server_app/routers/admin_api.py.
    """
    audit.warning("Deprecated core admin password route called for doctor_id=%s", doctor_id)
    raise HTTPException(status_code=410, detail="Deprecated endpoint. Use /api/admin/doctors/{doctor_id}/recover-access.")

@router.post("/doctors/onboard")
def onboard_doctor(payload: OnboardRequest):
    """Receives a signed CSR from the Doctor App."""
    audit.info("Doctor onboarding payload received for doctor_id=%s", payload.id)
    
    doc = db.doctors.get(payload.id)
    if not doc:
        audit.warning("Doctor onboarding rejected: unprovisioned doctor_id=%s", payload.id)
        raise HTTPException(status_code=404, detail="Doctor ID not provisioned.")
    
    try:
        doctor_csr = load_pem_csr(payload.csr_pem)
        if not verify_csr_signature(doctor_csr):
            raise HTTPException(status_code=400, detail="Invalid CSR signature.")

        subject_ids = doctor_csr.subject.get_attributes_for_oid(NameOID.USER_ID)
        if not subject_ids or subject_ids[0].value != payload.id:
            raise HTTPException(status_code=400, detail="CSR subject does not match doctor identity.")

        pqc_pub_bytes = extract_pqc_public_key_from_csr(doctor_csr)
        tls_pub_pem = doctor_csr.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid CSR payload.")

    import base64 as _base64
    doc["csr_pem"] = payload.csr_pem
    doc["pqc_public_key_b64"] = _base64.b64encode(pqc_pub_bytes).decode("utf-8")
    doc["tls_public_key_pem"] = tls_pub_pem
    
    db.save_db()
    audit.info("Doctor onboarding succeeded for doctor_id=%s (csr enrolled)", payload.id)
    
    return {"message": "Keys enrolled successfully"}

@router.post("/doctors/{doctor_id}/issue-cert")
def issue_certificate(doctor_id: str):
    """Hospital acts as CA: Issues an X.509 cert binding TLS and PQC identities."""
    audit.info("Admin certificate issue requested for doctor_id=%s", doctor_id)
    doc = db.doctors.get(doctor_id)
    if not doc:
        audit.warning("Certificate issue failed: doctor not found doctor_id=%s", doctor_id)
        raise HTTPException(status_code=404, detail="Doctor not found")
    
    csr_pem = doc.get("csr_pem")
    if not csr_pem:
        audit.warning("Certificate issue blocked: missing keys for doctor_id=%s", doctor_id)
        raise HTTPException(
            status_code=400, 
            detail="Doctor has not fully enrolled. Missing CSR."
        )

    try:
        doctor_csr = load_pem_csr(csr_pem)
        if not verify_csr_signature(doctor_csr):
            raise HTTPException(status_code=400, detail="Invalid CSR signature.")

        subject_ids = doctor_csr.subject.get_attributes_for_oid(NameOID.USER_ID)
        if not subject_ids or subject_ids[0].value != doc["id"]:
            raise HTTPException(status_code=400, detail="CSR subject does not match doctor identity.")

        issuer_key = load_hospital_ca_signer()
        try:
            cert = CertificateAuthority.generate_doctor_certificate_from_csr(
                doctor_csr=doctor_csr,
                issuer_key=issuer_key,
                issuer_cert=state.hospital_root_cert,
            )
        finally:
            issuer_key.container_key = None
        
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
