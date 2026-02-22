import base64
from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization
import time

from ..core.database import db
from ..core.server_state import state
from ..core.audit_logger import get_audit_logger
from ..core.auth_utils import hash_password
from ..core.admin_auth import require_admin_token
from ..core.ca_setup import load_hospital_ca_signer
from security_suite.security.certificates import (
    CertificateAuthority,
    load_pem_csr,
    verify_csr_signature,
    extract_pqc_public_key_from_csr,
)

import secrets
import string

router = APIRouter(prefix="/api/admin", tags=["Admin Control"])
audit = get_audit_logger()

class OnboardRequest(BaseModel):
    id: str
    csr_pem: str

class StatusUpdateRequest(BaseModel):
    status: str

def _issue_certificate_for_doctor(doc: dict):
    csr_pem = doc.get("csr_pem")
    if not csr_pem:
        raise HTTPException(
            status_code=400,
            detail="Doctor has not fully enrolled. Missing CSR.",
        )

    doctor_csr = load_pem_csr(csr_pem)
    if not verify_csr_signature(doctor_csr):
        raise HTTPException(status_code=400, detail="Invalid CSR signature.")

    subject_ids = doctor_csr.subject.get_attributes_for_oid(NameOID.USER_ID)
    if not subject_ids or subject_ids[0].value != doc["id"]:
        raise HTTPException(status_code=400, detail="CSR subject does not match doctor identity.")

    # Ensure required PQC extension exists in CSR.
    try:
        extract_pqc_public_key_from_csr(doctor_csr)
    except (ValueError, x509.ExtensionNotFound):
        raise HTTPException(status_code=400, detail="CSR missing or invalid PQC extension.")

    issuer_key = load_hospital_ca_signer()
    try:
        cert = CertificateAuthority.generate_doctor_certificate_from_csr(
            doctor_csr=doctor_csr,
            issuer_key=issuer_key,
            issuer_cert=state.hospital_root_cert,
        )
    finally:
        # Minimize CA private key residency in process memory.
        issuer_key.container_key = None
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

@router.post("/doctors/{doctor_id}/recover-access")
def recover_doctor_access(doctor_id: str, _: None = Depends(require_admin_token)):
    """
    Admin-only forgot-password recovery:
    - Keeps same doctor_id
    - Rotates to a new temporary password
    - Clears enrolled public keys
    - Revokes active certificates
    - Forces fresh onboarding/certificate issuance
    """
    audit.info("Admin forgot-password recovery requested for doctor_id=%s", doctor_id)
    doc = db.doctors.get(doctor_id)
    if not doc:
        audit.warning("Admin forgot-password recovery failed: doctor not found doctor_id=%s", doctor_id)
        raise HTTPException(status_code=404, detail="Doctor not found")

    temp_pass = _generate_temp_password()
    revoked_count = db.revoke_active_certificates(doctor_id, reason="forgot_password_recovery")

    # Reset server-side identity linkage so doctor must re-enroll key material.
    doc["password"] = hash_password(temp_pass)
    doc["pqc_public_key_b64"] = None
    doc["tls_public_key_pem"] = None
    doc["csr_pem"] = None
    doc["status"] = "authorized"
    db.save_db()
    audit.info(
        "Admin forgot-password recovery succeeded for doctor_id=%s revoked_active_certs=%s",
        doctor_id,
        revoked_count,
    )
    return {
        "message": "Recovery credentials issued. Doctor must re-enroll keys and obtain a new certificate.",
        "doctor_id": doctor_id,
        "password": temp_pass,
        "revoked_active_certs": revoked_count,
    }

@router.post("/doctors/onboard")
def onboard_doctor(payload: OnboardRequest):
    """Receives and validates doctor CSR for certificate enrollment."""
    audit.info("Doctor onboarding payload received for doctor_id=%s", payload.id)
    
    # Use .get() to safely access the dictionary
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

        # Ensure PQC extension is present and store it for admin UI visibility.
        try:
            pqc_pub_bytes = extract_pqc_public_key_from_csr(doctor_csr)
        except (ValueError, x509.ExtensionNotFound):
            raise HTTPException(status_code=400, detail="CSR missing or invalid PQC extension.")
        tls_pub_pem = doctor_csr.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")
    except HTTPException:
        raise
    except Exception as exc:
        audit.warning("Doctor onboarding rejected: invalid CSR for doctor_id=%s err=%s", payload.id, str(exc))
        raise HTTPException(status_code=400, detail="Invalid CSR payload.")

    # Persist CSR and key metadata derived from CSR.
    doc["csr_pem"] = payload.csr_pem
    doc["tls_public_key_pem"] = tls_pub_pem
    doc["pqc_public_key_b64"] = base64.b64encode(pqc_pub_bytes).decode("utf-8")
    doc['status'] = 'pending'
    revoked = db.revoke_active_certificates(payload.id, reason="keys_reenrolled")
    
    # Save immediately to hospital_vault.json
    db.save_db()
    audit.info(
        "Doctor onboarding succeeded for doctor_id=%s (csr enrolled, revoked_active_certs=%s)",
        payload.id,
        revoked,
    )
    
    return {"message": "CSR enrolled successfully"}

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
