from fastapi import APIRouter, HTTPException, Depends
from ..core.database import db
from ..core.audit_logger import get_audit_logger

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
    
    # Check if password matches
    if stored_doc["password"] != password:
        audit.warning("Auth failed: invalid password for doctor_id=%s", doc_id)
        raise HTTPException(status_code=401, detail="Incorrect password.")

    audit.info("Auth success for doctor_id=%s", doc_id)
    return {"status": "authorized", "name": stored_doc["name"]}
