from fastapi import APIRouter, HTTPException, Depends
from ..core.database import db

router = APIRouter(prefix="/api/auth", tags=["Authentication"])

@router.post("/verify")
def verify_doctor_credentials(payload: dict):
    doc_id = payload.get("id")
    password = payload.get("password")
    
    if doc_id not in db.doctors:
        raise HTTPException(status_code=401, detail="Doctor ID not recognized.")
        
    stored_doc = db.doctors[doc_id]
    
    # Check if password matches
    if stored_doc["password"] != password:
        raise HTTPException(status_code=401, detail="Incorrect password.")
        
    return {"status": "authorized", "name": stored_doc["name"]}