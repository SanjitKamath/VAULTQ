import base64
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from cryptography.hazmat.primitives import serialization

from ..core.database import db, DoctorRecord, CertRecord
from ..core.server_state import state
from security_suite.security.certificates import CertificateAuthority

router = APIRouter(prefix="/api/admin", tags=["Admin Control"])

class OnboardRequest(BaseModel):
    name: str
    specialty: str
    pqc_public_key_b64: str

class StatusUpdateRequest(BaseModel):
    status: str

@router.get("/stats")
def get_system_stats():
    docs = db.get_all_doctors()
    return {
        "total_doctors": len(docs),
        "active_certs": len(db.certificates),
        "ca_status": "Online",
        "ca_algorithm": "ML-DSA-65"
    }

@router.get("/doctors")
def list_doctors():
    return db.get_all_doctors()

@router.post("/doctors/onboard")
def onboard_doctor(req: OnboardRequest):
    """Registers a doctor and their PQC public key (Pending Status)"""
    new_doc = DoctorRecord(
        name=req.name, 
        specialty=req.specialty, 
        pqc_public_key_b64=req.pqc_public_key_b64
    )
    db.add_doctor(new_doc)
    return {"message": "Doctor registered successfully", "doctor": new_doc}

@router.post("/doctors/{doctor_id}/issue-cert")
def issue_certificate(doctor_id: str):
    """Hospital acts as CA: Issues an X.509 cert to the Doctor."""
    doc = db.doctors.get(doctor_id)
    if not doc:
        raise HTTPException(status_code=404, detail="Doctor not found")
        
    pk_bytes = base64.b64decode(doc.pqc_public_key_b64)
    
    # Generate the standard X.509 Certificate using security_suite
    cert = CertificateAuthority.generate_doctor_certificate(
        doctor_public_key_bytes=pk_bytes,
        doctor_details={"name": doc.name, "doctor_id": doc.id},
        issuer_key=state.hospital_ca,
        issuer_cert=state.hospital_root_cert
    )
    
    # Export to PEM format for distribution
    pem_data = cert.public_bytes(serialization.Encoding.PEM).decode()
    
    # Save to DB
    record = CertRecord(
        doctor_id=doc.id, 
        pem_data=pem_data,
        expires_at=int(cert.not_valid_after.timestamp())
    )
    db.save_certificate(record)
    
    return {"message": "Certificate Issued", "cert_id": record.cert_id, "status": doc.status}

@router.put("/doctors/{doctor_id}/status")
def update_status(doctor_id: str, req: StatusUpdateRequest):
    """RBAC Control: Revoke or suspend doctors."""
    if req.status not in ["pending", "active", "revoked"]:
        raise HTTPException(status_code=400, detail="Invalid status")
    db.update_doctor_status(doctor_id, req.status)
    return {"message": f"Status updated to {req.status}"}

@router.delete("/doctors/{doctor_id}")
def delete_doctor(doctor_id: str):
    success = db.delete_doctor(doctor_id)
    if not success:
        raise HTTPException(status_code=404, detail="Doctor not found")
    return {"message": f"Doctor {doctor_id} has been wiped from the system."}