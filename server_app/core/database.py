import json
import os
import time
import tempfile
import threading
from pydantic import BaseModel
from typing import Optional, List
import secrets
from pathlib import Path
from .audit_logger import get_audit_logger
from .auth_utils import hash_password, SCHEME_PREFIX

# --- Pydantic Models for API Validation ---

class DoctorRecord(BaseModel):
    id: Optional[str] = None  
    name: str
    specialty: str = "General Practice"
    status: str = "pending"
    pqc_public_key_b64: Optional[str] = None
    tls_public_key_pem: Optional[str] = None
    csr_pem: Optional[str] = None
    hashed_password: Optional[str] = None

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
        self.patients = {}
        self.enrollment_tokens = {}
        self._enrollment_lock = threading.Lock()
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
                self.patients = data.get("patients", {})
                self.enrollment_tokens = data.get("enrollment_tokens", {})
                self.audit.info(
                    "DB load: completed (doctors=%s certificates=%s patients=%s enrollment_tokens=%s)",
                    len(self.doctors),
                    len(self.certificates),
                    len(self.patients),
                    len(self.enrollment_tokens),
                )
        except Exception as e:
            self.audit.exception("DB load error: %s", str(e))

    def save_db(self):
        self.db_file.parent.mkdir(parents=True, exist_ok=True)
        os.chmod(self.db_file.parent, 0o700)
        fd, temp_path = tempfile.mkstemp(
            prefix=f".{self.db_file.name}.",
            suffix=".tmp",
            dir=str(self.db_file.parent),
        )
        try:
            try:
                os.chmod(temp_path, 0o600)
            except Exception:
                os.close(fd)
                raise
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(
                    {
                        "doctors": self.doctors,
                        "certificates": self.certificates,
                        "patients": self.patients,
                        "enrollment_tokens": self.enrollment_tokens,
                    },
                    f,
                    indent=4,
                )
                f.flush()
                os.fsync(f.fileno())
            os.replace(temp_path, self.db_file)
            os.chmod(self.db_file, 0o600)
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)
        self.audit.info(
            "DB save: persisted (doctors=%s certificates=%s patients=%s enrollment_tokens=%s)",
            len(self.doctors),
            len(self.certificates),
            len(self.patients),
            len(self.enrollment_tokens),
        )

    def issue_enrollment_token(self, token: str, doctor_id: str, expires_at: float):
        now_ts = time.time()
        # Garbage collect expired/consumed tokens opportunistically.
        self.enrollment_tokens = {
            k: v
            for k, v in self.enrollment_tokens.items()
            if float(v.get("expires_at", 0)) > now_ts and not bool(v.get("used", False))
        }
        self.enrollment_tokens[token] = {
            "doctor_id": doctor_id,
            "expires_at": float(expires_at),
            "used": False,
            "single_use": True,
            "issued_at": now_ts,
            "used_at": None,
        }
        self.audit.info("DB issue_enrollment_token: doctor_id=%s expires_at=%s", doctor_id, int(expires_at))
        self.save_db()

    def consume_enrollment_token(self, token: str, doctor_id: str):
        with self._enrollment_lock:
            record = self.enrollment_tokens.get(token)
            if record is None:
                return "missing"

            now_ts = time.time()
            if float(record.get("expires_at", 0)) <= now_ts:
                return "expired"

            if record.get("doctor_id") != doctor_id:
                return "doctor_mismatch"

            if bool(record.get("used", False)):
                return "used"

            # Consume first and persist before onboarding mutations to prevent replay.
            record["used"] = True
            record["used_at"] = now_ts
            self.save_db()
            return "ok"

    def validate_enrollment_token(self, token: str, doctor_id: str, allow_used: bool = False):
        record = self.enrollment_tokens.get(token)
        if record is None:
            return "missing"

        now_ts = time.time()
        if float(record.get("expires_at", 0)) <= now_ts:
            return "expired"

        if record.get("doctor_id") != doctor_id:
            return "doctor_mismatch"

        if bool(record.get("used", False)) and not allow_used:
            return "used"

        return "ok"
            
    def get_all_doctors(self):
        """Returns all doctor records ensuring every record has an 'id' field for the UI."""
        results = []
        for doc_id, data in self.doctors.items():
            row = dict(data)
            row["id"] = doc_id
            results.append(row)
        return results

    def add_doctor(self, doctor_data):
        if hasattr(doctor_data, "model_dump"):
            doc_dict = doctor_data.model_dump()
        else:
            doc_dict = doctor_data

        doc_dict = dict(doc_dict)
        raw_id = doc_dict.get("id") or doc_dict.get("doctor_id")
        doc_id = str(raw_id).strip() if raw_id is not None else ""
        if not doc_id:
            raise ValueError("Doctor record must include a non-empty 'id' or 'doctor_id'.")
        doc_dict["id"] = doc_id
        self.doctors[doc_id] = doc_dict
        self.audit.info("DB add_doctor: doctor_id=%s", doc_id)
        self.save_db()

    @staticmethod
    def _ensure_password_hash(password: str) -> str:
        pwd = (password or "").strip()
        if not pwd:
            raise ValueError("Password must be non-empty.")
        if pwd.startswith(SCHEME_PREFIX) or pwd.startswith("$2a$") or pwd.startswith("$2b$") or pwd.startswith("$2y$"):
            return pwd
        return hash_password(pwd)

    def add_pre_authorized_doctor(self, doc_id, name, password):
        hashed_password = self._ensure_password_hash(password)
        self.doctors[doc_id] = {
            "id": doc_id,
            "name": name,
            "password": hashed_password,
            "status": "authorized",
            "specialty": "General Practice",
            "pqc_public_key_b64": None,
            "tls_public_key_pem": None,
            "csr_pem": None,
        }
        self.audit.info("DB add_pre_authorized_doctor: doctor_id=%s", doc_id)
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

    # ── Patient Operations ────────────────────────────────────────────

    def add_patient(self, patient_id: str, name: str, password: str):
        hashed_password = self._ensure_password_hash(password)
        self.patients[patient_id] = {
            "id": patient_id,
            "name": name,
            "password": hashed_password,
            "status": "active",
        }
        self.audit.info("DB add_patient: patient_id=%s", patient_id)
        self.save_db()

    def get_all_patients(self):
        results = []
        for pat_id, data in self.patients.items():
            row = dict(data)
            row["id"] = pat_id
            results.append(row)
        return results

    def delete_patient(self, patient_id: str):
        if patient_id in self.patients:
            del self.patients[patient_id]
            self.audit.info("DB delete_patient: patient_id=%s removed", patient_id)
            self.save_db()
            return True
        self.audit.warning("DB delete_patient: patient_id not found (%s)", patient_id)
        return False


# Instantiate the global database object
db = VaultQDatabase()
