import base64
import secrets
import string
import time

from fastapi import APIRouter, HTTPException, Depends, Request
from pydantic import BaseModel
from cryptography import x509
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


# -------------------------------------------------------------------
# ADMIN SESSION AUTH (COOKIE BASED)
# -------------------------------------------------------------------

def require_admin_session(request: Request):
    """Secures admin endpoints with the admin login cookie session."""
    session_cookie = request.cookies.get("admin_session")

    if not session_cookie or session_cookie != state.admin_session_token:
        raise HTTPException(status_code=401, detail="Admin authentication required")


# -------------------------------------------------------------------
# MODELS
# -------------------------------------------------------------------

class OnboardRequest(BaseModel):
    id: str
    csr_pem: str


class StatusUpdateRequest(BaseModel):
    status: str


# -------------------------------------------------------------------
# UTILS
# -------------------------------------------------------------------

def _generate_temp_password(length: int = 14) -> str:
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


def _cert_expiry_ts(cert) -> float:
    not_after = getattr(cert, "not_valid_after_utc", None)
    if not_after is None:
        not_after = cert.not_valid_after
    return not_after.timestamp()


def _issue_certificate_for_doctor(doc: dict):
    """Validates the CSR and issues an X.509 certificate for the doctor."""
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
        raise HTTPException(status_code=400, detail="CSR subject mismatch.")

    try:
        extract_pqc_public_key_from_csr(doctor_csr)
    except (ValueError, x509.ExtensionNotFound):
        raise HTTPException(status_code=400, detail="CSR missing PQC extension.")

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

    cert_id = db.save_certificate_record(
        doc["id"],
        pem_data,
        _cert_expiry_ts(cert),
    )

    doc["status"] = "active"

    db.save_db()

    return cert_id, cert


# -------------------------------------------------------------------
# ADMIN DASHBOARD APIs
# -------------------------------------------------------------------

@router.get("/stats")
def get_system_stats(_: None = Depends(require_admin_session)):
    audit.info("Admin stats requested")
    docs = db.get_all_doctors()

    return {
        "total_doctors": len(docs),
        "active_certs": len(getattr(db, 'certificates', {})),
        "ca_status": "Online",
        "ca_algorithm": "ML-DSA-65",
    }


@router.get("/doctors")
def list_doctors(_: None = Depends(require_admin_session)):
    audit.info("Admin doctor list requested")
    return db.get_all_doctors()


# -------------------------------------------------------------------
# DOCTOR MANAGEMENT
# -------------------------------------------------------------------

@router.post("/doctors/provision")
def provision_doctor(name: str, _: None = Depends(require_admin_session)):
    audit.info("Admin doctor provision requested for name=%s", name)

    doc_id = "doc_" + secrets.token_hex(3)
    temp_pass = _generate_temp_password()

    db.add_pre_authorized_doctor(doc_id, name, hash_password(temp_pass))

    audit.info("Admin doctor provision succeeded for doctor_id=%s", doc_id)

    return {"id": doc_id, "password": temp_pass}


@router.post("/doctors/{doctor_id}/recover-access")
def recover_doctor_access(doctor_id: str, _: None = Depends(require_admin_session)):
    doc = db.doctors.get(doctor_id)

    if not doc:
        raise HTTPException(status_code=404, detail="Doctor not found")

    temp_pass = _generate_temp_password()

    revoked = db.revoke_active_certificates(doctor_id)

    doc["password"] = hash_password(temp_pass)
    doc["csr_pem"] = None
    doc["pqc_public_key_b64"] = None
    doc["tls_public_key_pem"] = None
    doc["status"] = "authorized"

    db.save_db()

    return {
        "doctor_id": doctor_id,
        "password": temp_pass,
        "revoked_active_certs": revoked,
    }


@router.post("/doctors/{doctor_id}/issue-cert")
def issue_certificate(doctor_id: str, _: None = Depends(require_admin_session)):
    doc = db.doctors.get(doctor_id)

    if not doc:
        raise HTTPException(status_code=404, detail="Doctor not found")

    cert_id, cert = _issue_certificate_for_doctor(doc)

    return {
        "message": "Certificate issued",
        "cert_id": cert_id,
        "expires_at": _cert_expiry_ts(cert),
    }


@router.post("/doctors/{doctor_id}/refresh-cert")
def refresh_certificate(doctor_id: str, _: None = Depends(require_admin_session)):
    doc = db.doctors.get(doctor_id)

    if not doc:
        raise HTTPException(status_code=404, detail="Doctor not found")

    revoked = db.revoke_active_certificates(doctor_id)

    cert_id, cert = _issue_certificate_for_doctor(doc)

    return {
        "doctor_id": doctor_id,
        "revoked_count": revoked,
        "cert_id": cert_id,
        "expires_at": _cert_expiry_ts(cert),
    }


@router.post("/doctors/{doctor_id}/revoke-cert")
def revoke_certificate(doctor_id: str, _: None = Depends(require_admin_session)):
    revoked = db.revoke_active_certificates(doctor_id)

    return {
        "doctor_id": doctor_id,
        "revoked_count": revoked,
    }


@router.delete("/doctors/{doctor_id}")
def delete_doctor(doctor_id: str, _: None = Depends(require_admin_session)):
    success = db.delete_doctor(doctor_id)

    if not success:
        raise HTTPException(status_code=404, detail="Doctor not found")

    return {"message": "Doctor deleted successfully"}
