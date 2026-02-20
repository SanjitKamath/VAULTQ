import json
import os
from pydantic import BaseModel
from typing import Optional, List
import secrets

# --- Pydantic Models for API Validation ---

class DoctorRecord(BaseModel):
    id: Optional[str] = None  
    name: str
    specialty: str = "General Practice"
    status: str = "pending"
    pqc_public_key_b64: Optional[str] = None
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
        self.db_file = "hospital_vault.json"
        self.doctors = {}
        self.certificates = {}
        self.load_db()

    def load_db(self):
        if os.path.exists(self.db_file):
            try:
                with open(self.db_file, "r") as f:
                    data = json.load(f)
                    self.doctors = data.get("doctors", {})
                    self.certificates = data.get("certificates", {})
            except Exception as e:
                print(f"Error loading DB: {e}")

    def save_db(self):
        with open(self.db_file, "w") as f:
            json.dump({
                "doctors": self.doctors, 
                "certificates": self.certificates
            }, f, indent=4)

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
        self.save_db()

    def add_pre_authorized_doctor(self, doc_id, name, password):
        self.doctors[doc_id] = {
            "id": doc_id,
            "name": name,
            "password": password,
            "status": "authorized",
            "specialty": "General Practice",
            "pqc_public_key_b64": None
        }
        self.save_db()

    def delete_doctor(self, doctor_id: str):
        if doctor_id in self.doctors:
            del self.doctors[doctor_id]
            self.certificates = {k: v for k, v in self.certificates.items() if v.get("doctor_id") != doctor_id}
            self.save_db()
            return True
        return False
    
    def add_certificate(self, cert_data):
        if hasattr(cert_data, "model_dump"):
            cert_dict = cert_data.model_dump()
        else:
            cert_dict = cert_data
            
        cert_id = cert_dict.get("id")
        self.certificates[cert_id] = cert_dict
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
        
        # Save to the JSON file immediately
        self.save_db()
        return cert_id

# Instantiate the global database object
db = VaultQDatabase()