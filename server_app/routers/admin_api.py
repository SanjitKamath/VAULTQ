import base64
from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from cryptography.hazmat.primitives import serialization
import time

from ..core.database import db
from ..core.server_state import state
from ..core.audit_logger import get_audit_logger
from ..core.auth_utils import hash_password
from ..core.admin_auth import require_admin_token
from security_suite.security.certificates import CertificateAuthority

import secrets
import string

router = APIRouter(prefix="/api/admin", tags=["Admin Control"])
audit = get_audit_logger()

class OnboardRequest(BaseModel):
    id: str
    name: str = "Unknown Doctor"
    pqc_public_key_b64: str
    tls_public_key_pem: str

class StatusUpdateRequest(BaseModel):
    status: str

class AdminPasswordUpdateRequest(BaseModel):
    password: str


def _issue_certificate_for_doctor(doc: dict):
    pqc_pub_key = doc.get("pqc_public_key_b64")
    tls_pub_key_pem = doc.get("tls_public_key_pem")
    if not pqc_pub_key or not tls_pub_key_pem:
        raise HTTPException(
            status_code=400,
            detail="Doctor has not fully enrolled. Missing PQC or TLS public key.",
        )

    pk_bytes = base64.b64decode(pqc_pub_key)
    tls_pub_key = serialization.load_pem_public_key(tls_pub_key_pem.encode())

    cert = CertificateAuthority.generate_doctor_certificate(
        doctor_pqc_public_bytes=pk_bytes,
        doctor_tls_public_key=tls_pub_key,
        doctor_details={"name": doc["name"], "doctor_id": doc["id"]},
        issuer_key=state.hospital_ca,
        issuer_cert=state.hospital_root_cert,
    )
    pem_data = cert.public_bytes(serialization.Encoding.PEM).decode()
    cert_id = db.save_certificate_record(doc["id"], pem_data, cert.not_valid_after.timestamp())
    doc["status"] = "active"
    db.save_db()
    return cert_id, cert


def _generate_temp_password(length: int = 14) -> str:
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))

@router.get("/stats")
def get_system_stats(_: None = Depends(require_admin_token)):
    audit.info("Admin stats requested")
    docs = db.get_all_doctors()
    return {
        "total_doctors": len(docs),
        "active_certs": len(db.certificates),
        "ca_status": "Online",
        "ca_algorithm": "ML-DSA-65"
    }

@router.get("/doctors")
def list_doctors(_: None = Depends(require_admin_token)):
    audit.info("Admin doctor list requested")
    return db.get_all_doctors()

@router.put("/doctors/{doctor_id}/password")
def set_doctor_password(doctor_id: str, payload: AdminPasswordUpdateRequest, _: None = Depends(require_admin_token)):
    audit.info("Admin password update requested for doctor_id=%s", doctor_id)
    doc = db.doctors.get(doctor_id)
    if not doc:
        audit.warning("Admin password update failed: doctor not found doctor_id=%s", doctor_id)
        raise HTTPException(status_code=404, detail="Doctor not found")

    new_password = (payload.password or "").strip()
    if not new_password:
        audit.warning("Admin password update failed: empty password doctor_id=%s", doctor_id)
        raise HTTPException(status_code=400, detail="Password cannot be empty")

    doc["password"] = hash_password(new_password)
    db.save_db()
    audit.info("Admin password update succeeded for doctor_id=%s", doctor_id)
    return {"message": "Password updated", "doctor_id": doctor_id}

@router.post("/doctors/onboard")
def onboard_doctor(payload: OnboardRequest):
    """Receives both ML-DSA and TLS public keys from the Doctor App."""
    audit.info("Doctor onboarding payload received for doctor_id=%s", payload.id)
    
    # Use .get() to safely access the dictionary
    doc = db.doctors.get(payload.id)
    if not doc:
        audit.warning("Doctor onboarding rejected: unprovisioned doctor_id=%s", payload.id)
        raise HTTPException(status_code=404, detail="Doctor ID not provisioned.")
    
    # Save both public keys to the doctor's record
    doc['pqc_public_key_b64'] = payload.pqc_public_key_b64
    doc['tls_public_key_pem'] = payload.tls_public_key_pem
    doc['status'] = 'pending'
    revoked = db.revoke_active_certificates(payload.id, reason="keys_reenrolled")
    
    # Save immediately to hospital_vault.json
    db.save_db()
    audit.info(
        "Doctor onboarding succeeded for doctor_id=%s (public key enrolled, revoked_active_certs=%s)",
        payload.id,
        revoked,
    )
    
    return {"message": "Keys enrolled successfully"}

@router.post("/doctors/{doctor_id}/issue-cert")
def issue_certificate(doctor_id: str, _: None = Depends(require_admin_token)):
    """Hospital acts as CA: Issues an X.509 cert to the Doctor."""
    audit.info("Admin certificate issue requested for doctor_id=%s", doctor_id)
    doc = db.doctors.get(doctor_id) # Fetches the dict
    if not doc:
        audit.warning("Certificate issue failed: doctor not found doctor_id=%s", doctor_id)
        raise HTTPException(status_code=404, detail="Doctor not found")
    
    try:
        cert_id, cert = _issue_certificate_for_doctor(doc)
        audit.info("Certificate issued successfully for doctor_id=%s", doctor_id)

        return {
            "message": "Certificate issued",
            "status": "active",
            "cert_id": cert_id,
            "expires_at": cert.not_valid_after.timestamp(),
        }
    except HTTPException:
        raise
    except Exception as e:
        audit.exception("Certificate issuance failed for doctor_id=%s: %s", doctor_id, str(e))
        raise HTTPException(status_code=500, detail="Failed to generate PQC Certificate")


@router.post("/doctors/{doctor_id}/refresh-cert")
def refresh_certificate(doctor_id: str, _: None = Depends(require_admin_token)):
    """Revokes active certs for a doctor and issues a fresh certificate."""
    audit.info("Admin certificate refresh requested for doctor_id=%s", doctor_id)
    doc = db.doctors.get(doctor_id)
    if not doc:
        audit.warning("Certificate refresh failed: doctor not found doctor_id=%s", doctor_id)
        raise HTTPException(status_code=404, detail="Doctor not found")

    try:
        revoked_count = db.revoke_active_certificates(doctor_id, reason="rotated_by_admin")
        cert_id, cert = _issue_certificate_for_doctor(doc)
        audit.info(
            "Certificate refresh succeeded for doctor_id=%s revoked=%s new_cert_id=%s",
            doctor_id,
            revoked_count,
            cert_id,
        )
        return {
            "message": "Certificate refreshed",
            "doctor_id": doctor_id,
            "revoked_count": revoked_count,
            "cert_id": cert_id,
            "issued_at": int(time.time()),
            "expires_at": cert.not_valid_after.timestamp(),
        }
    except HTTPException:
        raise
    except Exception as e:
        audit.exception("Certificate refresh failed for doctor_id=%s: %s", doctor_id, str(e))
        raise HTTPException(status_code=500, detail="Failed to refresh certificate")


@router.post("/doctors/{doctor_id}/revoke-cert")
def revoke_certificate(doctor_id: str, _: None = Depends(require_admin_token)):
    """Revokes all active certificates for a doctor."""
    audit.info("Admin certificate revoke requested for doctor_id=%s", doctor_id)
    doc = db.doctors.get(doctor_id)
    if not doc:
        audit.warning("Certificate revoke failed: doctor not found doctor_id=%s", doctor_id)
        raise HTTPException(status_code=404, detail="Doctor not found")

    revoked_count = db.revoke_active_certificates(doctor_id, reason="revoked_by_admin")
    if revoked_count > 0:
        doc["status"] = "revoked"
        db.save_db()
    audit.info("Certificate revoke completed for doctor_id=%s revoked=%s", doctor_id, revoked_count)
    return {"message": "Certificate(s) revoked", "doctor_id": doctor_id, "revoked_count": revoked_count}
    
@router.put("/doctors/{doctor_id}/status")
def update_status(doctor_id: str, req: StatusUpdateRequest, _: None = Depends(require_admin_token)):
    """RBAC Control: Revoke or suspend doctors."""
    if req.status not in ["pending", "active", "revoked"]:
        audit.warning("Admin status update failed: invalid status=%s doctor_id=%s", req.status, doctor_id)
        raise HTTPException(status_code=400, detail="Invalid status")
    if hasattr(db, "update_doctor_status"):
        db.update_doctor_status(doctor_id, req.status)
    elif doctor_id in db.doctors:
        db.doctors[doctor_id]["status"] = req.status
        db.save_db()
    else:
        raise HTTPException(status_code=404, detail="Doctor not found")
    audit.info("Admin status update succeeded for doctor_id=%s new_status=%s", doctor_id, req.status)
    return {"message": f"Status updated to {req.status}"}

@router.delete("/doctors/{doctor_id}")
def delete_doctor(doctor_id: str, _: None = Depends(require_admin_token)):
    """Deletes the doctor and forces a database save."""
    audit.info("Admin doctor delete requested for doctor_id=%s", doctor_id)
    success = db.delete_doctor(doctor_id)
    if not success:
        audit.warning("Admin doctor delete failed: doctor not found doctor_id=%s", doctor_id)
        raise HTTPException(status_code=404, detail="Doctor not found")
    audit.info("Admin doctor delete succeeded for doctor_id=%s", doctor_id)
    return {"message": "Doctor deleted successfully"}

@router.post("/doctors/provision")
def provision_doctor(name: str, _: None = Depends(require_admin_token)):
    """Generates random credentials and saves them to the persistent JSON."""
    audit.info("Admin doctor provision requested for name=%s", name)
    doc_id = "doc_" + secrets.token_hex(3)
    temp_pass = _generate_temp_password()
    
    # This method must call db.save_db() internally to reflect on disk immediately
    db.add_pre_authorized_doctor(doc_id, name, hash_password(temp_pass))
    audit.info("Admin doctor provision succeeded for doctor_id=%s", doc_id)
    
    return {"id": doc_id, "password": temp_pass}
