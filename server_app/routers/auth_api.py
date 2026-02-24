import os
import secrets
from fastapi import APIRouter, HTTPException, Response, Cookie
from ..core.database import db
from ..core.audit_logger import get_audit_logger
from ..core.auth_utils import verify_password  # <-- IMPORT THE SECURE VERIFIER
from ..core.admin_auth import (
    create_admin_session as create_server_admin_session,
    revoke_admin_session,
)
import time

router = APIRouter(prefix="/api/auth", tags=["Authentication"])
audit = get_audit_logger()
ADMIN_SESSION_COOKIE_NAME = "vaultq_admin_session"


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
def download_my_cert(doctor_id: str):
    """Allows the Doctor App to poll for its certificate after the Admin issues it."""
    now_ts = time.time()
    latest = db.get_latest_active_certificate(doctor_id) if hasattr(db, "get_latest_active_certificate") else None
    if latest and latest.get("pem_data") and float(latest.get("expires_at", 0)) > now_ts:
        return {"status": "issued", "pem_data": latest["pem_data"], "cert_id": latest.get("id")}

    return {"status": "pending"}  # Admin hasn't issued/rotated an active certificate yet
