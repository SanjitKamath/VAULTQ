import os
import secrets
import base64
from pydantic import BaseModel
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization
from fastapi import APIRouter, HTTPException, Response, Cookie, Request, Header
from ..core.database import db
from ..core.audit_logger import get_audit_logger
from ..core.auth_utils import verify_password  # <-- IMPORT THE SECURE VERIFIER
from ..core.admin_auth import (
    create_admin_session as create_server_admin_session,
    revoke_admin_session,
)
import time
from security_suite.security.certificates import (
    load_pem_csr,
    verify_csr_signature,
    extract_pqc_public_key_from_csr,
)

router = APIRouter(prefix="/api/auth", tags=["Authentication"])
pre_enroll_router = APIRouter(prefix="/api/pre-enroll", tags=["Pre-Enrollment"])
audit = get_audit_logger()
ADMIN_SESSION_COOKIE_NAME = "vaultq_admin_session"


class OnboardRequest(BaseModel):
    id: str
    csr_pem: str


def _parse_admin_session_ttl() -> int:
    raw = os.getenv("VAULTQ_ADMIN_SESSION_TTL_SECONDS", "3600")
    try:
        return int(raw)
    except ValueError:
        audit.warning(
            "Invalid VAULTQ_ADMIN_SESSION_TTL_SECONDS=%r; falling back to 3600 seconds.",
            raw,
        )
        return 3600


ADMIN_SESSION_TTL_SECONDS = _parse_admin_session_ttl()
ADMIN_COOKIE_SECURE = os.getenv("VAULTQ_ADMIN_COOKIE_SECURE", "1") == "1"
TRUST_PROXY_HEADERS = os.getenv("VAULTQ_TRUST_PROXY_HEADERS", "0") == "1"


def _parse_enroll_token_ttl() -> int:
    raw = os.getenv("VAULTQ_ENROLL_TOKEN_TTL_SECONDS", "300")
    try:
        ttl = int(raw)
    except ValueError:
        audit.warning(
            "Invalid VAULTQ_ENROLL_TOKEN_TTL_SECONDS=%r; falling back to 300 seconds.",
            raw,
        )
        return 300
    if ttl <= 0:
        audit.warning(
            "Invalid VAULTQ_ENROLL_TOKEN_TTL_SECONDS=%r; must be > 0. Falling back to 300 seconds.",
            raw,
        )
        return 300
    return ttl


ENROLL_TOKEN_TTL_SECONDS = _parse_enroll_token_ttl()


def _is_mtls_listener_request(request: Request) -> bool:
    expected_port_raw = os.getenv("VAULTQ_MTLS_PORT", "8080").strip() or "8080"
    try:
        expected_port = int(expected_port_raw)
    except ValueError:
        expected_port = 8080

    if request.url.port is not None:
        return request.url.port == expected_port

    host = (request.headers.get("host") or "").strip()
    if ":" in host:
        try:
            return int(host.rsplit(":", 1)[1]) == expected_port
        except ValueError:
            return False
    return False


def _doctor_id_from_cert_blob(cert_blob) -> str | None:
    if cert_blob is None:
        return None
    cert_obj = None
    try:
        if isinstance(cert_blob, bytes):
            try:
                cert_obj = x509.load_pem_x509_certificate(cert_blob)
            except Exception:
                cert_obj = x509.load_der_x509_certificate(cert_blob)
        elif isinstance(cert_blob, str):
            raw = cert_blob.strip()
            if "BEGIN CERTIFICATE" in raw:
                cert_obj = x509.load_pem_x509_certificate(raw.encode("utf-8"))
            else:
                cert_obj = x509.load_der_x509_certificate(base64.b64decode(raw))
    except Exception:
        return None

    if cert_obj is None:
        return None

    try:
        subject_ids = cert_obj.subject.get_attributes_for_oid(NameOID.USER_ID)
        if subject_ids:
            return subject_ids[0].value
    except Exception:
        return None
    return None


def _extract_authenticated_doctor_id(request: Request) -> str:
    hdr_doctor_id = (request.headers.get("x-client-doctor-id") or "").strip()
    hdr_cert = (request.headers.get("x-client-cert") or "").strip()
    if (hdr_doctor_id or hdr_cert) and not TRUST_PROXY_HEADERS:
        audit.warning("Doctor request rejected: untrusted proxy identity headers present")
        raise HTTPException(status_code=401, detail="Untrusted proxy identity headers.")

    # Optional reverse-proxy propagated identity header.
    if hdr_doctor_id:
        return hdr_doctor_id

    # Optional reverse-proxy propagated client cert.
    if hdr_cert:
        doctor_id = _doctor_id_from_cert_blob(hdr_cert)
        if doctor_id:
            return doctor_id

    # ASGI TLS extension (if exposed by the runtime/server stack).
    tls_ext = (request.scope.get("extensions") or {}).get("tls") or {}
    candidates = []
    if isinstance(tls_ext, dict):
        if tls_ext.get("client_cert") is not None:
            candidates.append(tls_ext.get("client_cert"))
        chain = tls_ext.get("client_cert_chain")
        if isinstance(chain, (list, tuple)):
            candidates.extend(chain)
    for cert_blob in candidates:
        doctor_id = _doctor_id_from_cert_blob(cert_blob)
        if doctor_id:
            return doctor_id

    raise HTTPException(status_code=401, detail="Unauthorized doctor request.")


def _get_cert_response(doctor_id: str) -> dict:
    now_ts = time.time()
    latest = db.get_latest_active_certificate(doctor_id) if hasattr(db, "get_latest_active_certificate") else None
    if latest and latest.get("pem_data") and float(latest.get("expires_at", 0)) > now_ts:
        return {"status": "issued", "pem_data": latest["pem_data"], "cert_id": latest.get("id")}
    return {"status": "pending"}


def _enroll_token_from_request(request: Request, x_enroll_token: str = "") -> str:
    token = (x_enroll_token or "").strip()
    if token:
        return token
    return (request.query_params.get("enroll_token") or "").strip()


def _validate_preenroll_token_or_raise(
    doctor_id: str,
    request: Request,
    x_enroll_token: str = "",
    *,
    allow_used: bool,
    context: str,
) -> str:
    enroll_token = _enroll_token_from_request(request, x_enroll_token)
    if not enroll_token:
        audit.warning("%s rejected: missing enrollment token for doctor_id=%s", context, doctor_id)
        raise HTTPException(status_code=401, detail="Missing enrollment token.")

    token_status = db.validate_enrollment_token(enroll_token, doctor_id, allow_used=allow_used)
    if token_status == "ok":
        audit.info(
            "%s token validation passed for doctor_id=%s token_state=%s",
            context,
            doctor_id,
            "used_allowed" if allow_used else "active",
        )
        return enroll_token

    if token_status == "doctor_mismatch":
        audit.warning("%s rejected: enrollment token doctor mismatch for doctor_id=%s", context, doctor_id)
        raise HTTPException(status_code=403, detail="Forbidden doctor identity.")

    audit.warning(
        "%s rejected: invalid enrollment token status=%s doctor_id=%s",
        context,
        token_status,
        doctor_id,
    )
    raise HTTPException(status_code=401, detail="Invalid or expired enrollment token.")

@router.post("/verify")
def verify_doctor_credentials(payload: dict):
    doc_id = payload.get("id")
    password = payload.get("password")
    audit.info("Auth verify requested for doctor_id=%s", doc_id)
    
    if doc_id not in db.doctors:
        audit.warning("Auth failed: unknown doctor_id=%s", doc_id)
        raise HTTPException(status_code=401, detail="Doctor ID not recognized.")
        
    stored_doc = db.doctors[doc_id]
    
    # CRITICAL FIX: Use the bcrypt verifier instead of plaintext comparison
    if not verify_password(password or "", stored_doc.get("password", "")):
        audit.warning("Auth failed: invalid password for doctor_id=%s", doc_id)
        raise HTTPException(status_code=401, detail="Incorrect password.")

    audit.info("Auth success for doctor_id=%s", doc_id)
    return {"status": "authorized", "name": stored_doc["name"]}


@router.post("/admin/session")
def create_admin_session(payload: dict, response: Response):
    expected = os.getenv("VAULTQ_ADMIN_TOKEN", "").strip()
    if not expected:
        raise HTTPException(status_code=503, detail="Admin API is not configured.")

    presented = (payload.get("token") or "").strip()
    if not presented or not secrets.compare_digest(presented, expected):
        audit.warning("Admin session create failed: invalid token")
        raise HTTPException(status_code=401, detail="Unauthorized admin request.")

    session_id, csrf_token = create_server_admin_session(presented, ADMIN_SESSION_TTL_SECONDS)

    response.set_cookie(
        key=ADMIN_SESSION_COOKIE_NAME,
        value=session_id,
        max_age=ADMIN_SESSION_TTL_SECONDS,
        httponly=True,
        secure=ADMIN_COOKIE_SECURE,
        samesite="strict",
        path="/",
    )
    audit.info("Admin session created (httpOnly cookie, ttl=%s)", ADMIN_SESSION_TTL_SECONDS)
    return {"status": "ok", "csrf_token": csrf_token}


@router.delete("/admin/session")
def delete_admin_session(response: Response, vaultq_admin_session: str = Cookie(default="")):
    session_id = (vaultq_admin_session or "").strip()
    if session_id:
        revoke_admin_session(session_id)
    response.delete_cookie(key=ADMIN_SESSION_COOKIE_NAME, path="/")
    audit.info("Admin session deleted")
    return {"status": "ok"}

@router.get("/my-cert/{doctor_id}")
def download_my_cert(doctor_id: str, request: Request):
    """Allows the Doctor App to poll for its certificate after the Admin issues it."""
    try:
        authenticated_doctor_id = _extract_authenticated_doctor_id(request)
        if authenticated_doctor_id != doctor_id:
            audit.warning(
                "Doctor cert poll rejected: identity mismatch requested=%s authenticated=%s",
                doctor_id,
                authenticated_doctor_id,
            )
            raise HTTPException(status_code=403, detail="Forbidden doctor identity.")
    except HTTPException as exc:
        # Direct Uvicorn mTLS does not always expose client cert identity in request scope.
        # On the strict mTLS listener, allow endpoint access based on transport auth alone.
        if exc.status_code == 401 and _is_mtls_listener_request(request):
            audit.info(
                "Doctor cert poll proceeding via mTLS-listener fallback for doctor_id=%s",
                doctor_id,
            )
        else:
            raise

    return _get_cert_response(doctor_id)


@pre_enroll_router.post("/auth/verify")
def preenroll_verify_doctor_credentials(payload: dict):
    doc_id = payload.get("id")
    password = payload.get("password")
    audit.info("Pre-enroll auth verify requested for doctor_id=%s", doc_id)

    if doc_id not in db.doctors:
        audit.warning("Pre-enroll auth failed: unknown doctor_id=%s", doc_id)
        raise HTTPException(status_code=401, detail="Doctor ID not recognized.")

    stored_doc = db.doctors[doc_id]
    if not verify_password(password or "", stored_doc.get("password", "")):
        audit.warning("Pre-enroll auth failed: invalid password for doctor_id=%s", doc_id)
        raise HTTPException(status_code=401, detail="Incorrect password.")

    enroll_token = secrets.token_urlsafe(32)
    expires_at = time.time() + ENROLL_TOKEN_TTL_SECONDS
    db.issue_enrollment_token(enroll_token, doc_id, expires_at)
    audit.info(
        "Pre-enroll auth success and token issued for doctor_id=%s expires_at=%s",
        doc_id,
        int(expires_at),
    )
    return {
        "status": "authorized",
        "name": stored_doc["name"],
        "enroll_token": enroll_token,
        "enroll_token_expires_at": int(expires_at),
    }


@pre_enroll_router.get("/auth/my-cert/{doctor_id}")
def preenroll_download_my_cert(
    doctor_id: str,
    request: Request,
    x_enroll_token: str = Header(default="", alias="X-Enroll-Token"),
):
    _validate_preenroll_token_or_raise(
        doctor_id,
        request,
        x_enroll_token,
        allow_used=True,
        context="Pre-enroll doctor cert poll",
    )
    return _get_cert_response(doctor_id)


@pre_enroll_router.post("/doctors/onboard")
def preenroll_onboard_doctor(
    payload: OnboardRequest,
    request: Request,
    x_enroll_token: str = Header(default="", alias="X-Enroll-Token"),
):
    audit.info("Pre-enroll onboarding payload received for doctor_id=%s", payload.id)
    enroll_token = _validate_preenroll_token_or_raise(
        payload.id,
        request,
        x_enroll_token,
        allow_used=False,
        context="Pre-enroll onboarding",
    )
    token_status = db.consume_enrollment_token(enroll_token, payload.id)
    if token_status != "ok":
        if token_status == "doctor_mismatch":
            audit.warning("Pre-enroll onboarding rejected: enrollment token doctor mismatch for doctor_id=%s", payload.id)
            raise HTTPException(status_code=403, detail="Forbidden doctor identity.")
        audit.warning(
            "Pre-enroll onboarding rejected: invalid enrollment token status=%s doctor_id=%s",
            token_status,
            payload.id,
        )
        raise HTTPException(status_code=401, detail="Invalid or expired enrollment token.")

    doc = db.doctors.get(payload.id)
    if not doc:
        audit.warning("Pre-enroll onboarding rejected: unprovisioned doctor_id=%s", payload.id)
        raise HTTPException(status_code=404, detail="Doctor ID not provisioned.")

    try:
        doctor_csr = load_pem_csr(payload.csr_pem)
        if not verify_csr_signature(doctor_csr):
            raise HTTPException(status_code=400, detail="Invalid CSR signature.")

        subject_ids = doctor_csr.subject.get_attributes_for_oid(NameOID.USER_ID)
        if not subject_ids or subject_ids[0].value != payload.id:
            raise HTTPException(status_code=400, detail="CSR subject does not match doctor identity.")

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
        audit.warning("Pre-enroll onboarding rejected: invalid CSR for doctor_id=%s err=%s", payload.id, str(exc))
        raise HTTPException(status_code=400, detail="Invalid CSR payload.")

    doc["csr_pem"] = payload.csr_pem
    doc["tls_public_key_pem"] = tls_pub_pem
    doc["pqc_public_key_b64"] = base64.b64encode(pqc_pub_bytes).decode("utf-8")
    doc["status"] = "pending"
    revoked = db.revoke_active_certificates(payload.id, reason="keys_reenrolled")
    db.save_db()
    audit.info(
        "Pre-enroll onboarding succeeded for doctor_id=%s (csr enrolled, revoked_active_certs=%s)",
        payload.id,
        revoked,
    )
    return {"message": "CSR enrolled successfully"}
