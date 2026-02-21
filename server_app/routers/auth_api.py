from fastapi import APIRouter, HTTPException
from ..core.database import db
from ..core.audit_logger import get_audit_logger
from ..core.auth_utils import verify_password  # <-- IMPORT THE SECURE VERIFIER
import time

router = APIRouter(prefix="/api/auth", tags=["Authentication"])
audit = get_audit_logger()

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

@router.get("/my-cert/{doctor_id}")
def download_my_cert(doctor_id: str):
    """Allows the Doctor App to poll for its certificate after the Admin issues it."""
    now_ts = time.time()
    latest = db.get_latest_active_certificate(doctor_id) if hasattr(db, "get_latest_active_certificate") else None
    if latest and latest.get("pem_data") and float(latest.get("expires_at", 0)) > now_ts:
        return {"status": "issued", "pem_data": latest["pem_data"], "cert_id": latest.get("id")}

    return {"status": "pending"}  # Admin hasn't issued/rotated an active certificate yet
