import json
import os
import time
from pydantic import BaseModel
from typing import Optional, List
import secrets
from pathlib import Path
from .audit_logger import get_audit_logger

# --- Pydantic Models for API Validation ---

class DoctorRecord(BaseModel):
    id: Optional[str] = None  
    name: str
    specialty: str = "General Practice"
    status: str = "pending"
    pqc_public_key_b64: Optional[str] = None
    csr_pem: Optional[str] = None
    password: Optional[str] = None

class CertRecord(BaseModel):
    id: str
    doctor_id: str
    issue_date: str
    expiry_date: str
    status: str = "active"

# --- Database Manager ---

class VaultQDatabase:
    def __init__(self):
        self.audit = get_audit_logger()
        base_dir = Path(__file__).resolve().parents[1]
        self.db_file = base_dir/ "storage" / "hospital_vault.json"
        self.doctors = {}
        self.certificates = {}
        self.audit.info("DB init: loading vault database from %s", self.db_file)
        self.load_db()

    def load_db(self):
        if not self.db_file.exists():
            self.audit.info("DB load: file not found, creating new database file")
            self.save_db()   # create empty DB file on first run
            return

        try:
            with open(self.db_file, "r") as f:
                data = json.load(f)
                self.doctors = data.get("doctors", {})
                self.certificates = data.get("certificates", {})
                self.audit.info(
                    "DB load: completed (doctors=%s certificates=%s)",
                    len(self.doctors),
                    len(self.certificates),
                )
        except Exception as e:
            self.audit.exception("DB load error: %s", str(e))

    def save_db(self):
        self.db_file.parent.mkdir(mode=0o700, parents=True, exist_ok=True)  
        with open(self.db_file, "w") as f:
            json.dump({
                "doctors": self.doctors, 
                "certificates": self.certificates
            }, f, indent=4)
        self.audit.info(
            "DB save: persisted (doctors=%s certificates=%s)",
            len(self.doctors),
            len(self.certificates),
        )
            
    def get_all_doctors(self):
        """Returns all doctor records ensuring every record has an 'id' field for the UI."""
        results = []
        for doc_id, data in self.doctors.items():
            # Ensure the ID is present in the dictionary returned to the UI
            data['id'] = doc_id 
            results.append(data)
        return results

    def add_doctor(self, doctor_data):
        if hasattr(doctor_data, "model_dump"):
            doc_dict = doctor_data.model_dump()
        else:
            doc_dict = doctor_data

        doc_id = doc_dict.get("id") or doc_dict.get("doctor_id")
        self.doctors[doc_id] = doc_dict
        self.audit.info("DB add_doctor: doctor_id=%s", doc_id)
        self.save_db()

    def add_pre_authorized_doctor(self, doc_id, name, password):
        self.doctors[doc_id] = {
            "id": doc_id,
            "name": name,
            "password": password,
            "status": "authorized",
            "specialty": "General Practice",
            "pqc_public_key_b64": None,
            "tls_public_key_pem": None,
            "csr_pem": None,
        }
        self.audit.info("DB add_pre_authorized_doctor: doctor_id=%s name=%s", doc_id, name)
        self.save_db()

    def delete_doctor(self, doctor_id: str):
        if doctor_id in self.doctors:
            del self.doctors[doctor_id]
            self.certificates = {k: v for k, v in self.certificates.items() if v.get("doctor_id") != doctor_id}
            self.audit.info("DB delete_doctor: doctor_id=%s and associated certs removed", doctor_id)
            self.save_db()
            return True
        self.audit.warning("DB delete_doctor: doctor_id not found (%s)", doctor_id)
        return False
    
    def add_certificate(self, cert_data):
        if hasattr(cert_data, "model_dump"):
            cert_dict = cert_data.model_dump()
        else:
            cert_dict = cert_data
            
        cert_id = cert_dict.get("id")
        self.certificates[cert_id] = cert_dict
        self.audit.info("DB add_certificate: cert_id=%s doctor_id=%s", cert_id, cert_dict.get("doctor_id"))
        self.save_db()

    def save_certificate_record(self, doctor_id: str, pem_data: str, expires_at: float):
        """Saves the newly issued X.509 certificate to the database."""
        # Ensure the certificates dictionary exists
        if not hasattr(self, 'certificates'):
            self.certificates = {}

        # Generate a unique ID for the certificate
        cert_id = f"cert_{secrets.token_hex(4)}"
        
        # Create the certificate record
        self.certificates[cert_id] = {
            "id": cert_id,
            "doctor_id": doctor_id,
            "pem_data": pem_data,
            "expires_at": expires_at,
            "status": "active"
        }
        self.audit.info("DB save_certificate_record: cert_id=%s doctor_id=%s", cert_id, doctor_id)
        
        # Save to the JSON file immediately
        self.save_db()
        return cert_id

    def revoke_active_certificates(self, doctor_id: str, reason: str = "revoked_by_admin") -> int:
        """Marks all active certificates for a doctor as revoked."""
        revoked = 0
        now_ts = int(time.time())
        for cert in self.certificates.values():
            if cert.get("doctor_id") == doctor_id and cert.get("status") == "active":
                cert["status"] = "revoked"
                cert["revoked_at"] = now_ts
                cert["revocation_reason"] = reason
                revoked += 1
        if revoked:
            self.audit.info(
                "DB revoke_active_certificates: doctor_id=%s revoked=%s reason=%s",
                doctor_id,
                revoked,
                reason,
            )
            self.save_db()
        return revoked

    def get_latest_active_certificate(self, doctor_id: str):
        """Returns the latest active certificate record for a doctor."""
        candidates = [
            cert
            for cert in self.certificates.values()
            if cert.get("doctor_id") == doctor_id and cert.get("status") == "active"
        ]
        if not candidates:
            return None
        return max(candidates, key=lambda c: float(c.get("expires_at", 0)))

# Instantiate the global database object
db = VaultQDatabase()
