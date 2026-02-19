from pydantic import BaseModel, Field
from typing import Optional
import json
import os
import time
import uuid

# --- Pydantic Data Models ---
class DoctorRecord(BaseModel):
    id: str = Field(default_factory=lambda: f"doc_{uuid.uuid4().hex[:8]}")
    name: str
    specialty: str
    pqc_public_key_b64: str = Field(..., description="Base64 encoded ML-DSA public key")
    status: str = Field(default="pending", description="pending, active, or revoked")
    cert_id: Optional[str] = None
    created_at: int = Field(default_factory=lambda: int(time.time()))

class CertRecord(BaseModel):
    cert_id: str = Field(default_factory=lambda: f"cert_{uuid.uuid4().hex[:12]}")
    doctor_id: str
    pem_data: str
    issued_at: int = Field(default_factory=lambda: int(time.time()))
    expires_at: int

class VaultQDatabase:
    def __init__(self):
        self.db_file = "hospital_vault.json"
        self.load_db()

    def load_db(self):
        if os.path.exists(self.db_file):
            with open(self.db_file, "r") as f:
                data = json.load(f)
                self.doctors = data.get("doctors", {})
                self.certificates = data.get("certificates", {})
        else:
            self.doctors = {} # Schema: {id: {name, password, status, pub_key}}
            self.certificates = {}

    def save_db(self):
        with open(self.db_file, "w") as f:
            json.dump({"doctors": self.doctors, "certificates": self.certificates}, f)

    def add_pre_authorized_doctor(self, doc_id, name, password):
        self.doctors[doc_id] = {
            "name": name,
            "password": password, # In production, use a hash (bcrypt)
            "status": "authorized",
            "pqc_public_key": None
        }
        self.save_db()

def delete_doctor(self, doctor_id: str):
        """Permanently removes a doctor and their associated security metadata."""
        if doctor_id in self.doctors:
            # 1. Remove the doctor record
            del self.doctors[doctor_id]
            
            # 2. Scrub any issued certificates tied to this doctor
            certs_to_remove = [cid for cid, c in self.certificates.items() if c.doctor_id == doctor_id]
            for cid in certs_to_remove:
                del self.certificates[cid]
            return True
        return False

db = VaultQDatabase()
