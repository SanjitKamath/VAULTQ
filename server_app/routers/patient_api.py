import os
import json
import base64
import time
import secrets
import string
from pydantic import BaseModel
from fastapi import APIRouter, HTTPException, Header, Depends
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from ..core.database import db
from ..core.server_state import state
from ..core.audit_logger import get_audit_logger
from ..core.auth_utils import verify_password, hash_password
from ..core.admin_auth import require_admin_token
from security_suite.security.integrity import sha256_hex, build_server_record_hash_message
from security_suite.crypto import DSAManager

router = APIRouter(prefix="/api/patient", tags=["Patient Portal"])
audit = get_audit_logger()

VAULT_DIR = os.path.join(os.path.dirname(__file__), "..", "storage", "vault")

# Simple in-memory session store: token -> { patient_id, expires_at }
_patient_sessions: dict[str, dict] = {}
SESSION_TTL = 3600  # 1 hour


def _safe_path_component(value: str) -> str:
    return "".join(c if c.isalnum() or c in ("-", "_") else "_" for c in str(value))


def _create_session(patient_id: str) -> str:
    token = secrets.token_urlsafe(48)
    _patient_sessions[token] = {
        "patient_id": patient_id,
        "expires_at": time.time() + SESSION_TTL,
    }
    return token


def _require_patient_session(x_patient_token: str = Header(default="")) -> str:
    """Validates the patient session token and returns the patient_id."""
    session = _patient_sessions.get(x_patient_token)
    if not session:
        raise HTTPException(status_code=401, detail="Invalid or missing session token.")
    if time.time() > session["expires_at"]:
        del _patient_sessions[x_patient_token]
        raise HTTPException(status_code=401, detail="Session expired. Please log in again.")
    return session["patient_id"]


def _generate_temp_password(length: int = 14) -> str:
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


# ── Patient Admin (called from Admin Dashboard) ─────────────────────

class PatientPasswordUpdateRequest(BaseModel):
    password: str


@router.get("/admin/list")
def list_patients(_: None = Depends(require_admin_token)):
    audit.info("Admin patient list requested")
    return db.get_all_patients()


@router.post("/admin/provision")
def provision_patient(name: str, _: None = Depends(require_admin_token)):
    """Generates random patient credentials and saves them to the persistent JSON."""
    audit.info("Admin patient provision requested for name=%s", name)
    pat_id = "pat_" + secrets.token_hex(3)
    temp_pass = _generate_temp_password()
    db.add_patient(pat_id, name, hash_password(temp_pass))
    audit.info("Admin patient provision succeeded for patient_id=%s", pat_id)
    return {"id": pat_id, "password": temp_pass}


@router.put("/admin/{patient_id}/password")
def set_patient_password(patient_id: str, payload: PatientPasswordUpdateRequest, _: None = Depends(require_admin_token)):
    audit.info("Admin password update requested for patient_id=%s", patient_id)
    pat = db.patients.get(patient_id)
    if not pat:
        raise HTTPException(status_code=404, detail="Patient not found")
    new_password = (payload.password or "").strip()
    if not new_password:
        raise HTTPException(status_code=400, detail="Password cannot be empty")
    pat["password"] = hash_password(new_password)
    db.save_db()
    audit.info("Admin password update succeeded for patient_id=%s", patient_id)
    return {"message": "Password updated", "patient_id": patient_id}


@router.delete("/admin/{patient_id}")
def delete_patient(patient_id: str, _: None = Depends(require_admin_token)):
    audit.info("Admin patient delete requested for patient_id=%s", patient_id)
    success = db.delete_patient(patient_id)
    if not success:
        raise HTTPException(status_code=404, detail="Patient not found")
    audit.info("Admin patient delete succeeded for patient_id=%s", patient_id)
    return {"message": "Patient deleted successfully"}


# ── Patient Authentication ───────────────────────────────────────────

@router.post("/auth/login")
def patient_login(payload: dict):
    """Authenticates a patient with ID + password and returns a session token."""
    patient_id = payload.get("id", "").strip()
    password = payload.get("password", "")
    audit.info("Patient auth requested for patient_id=%s", patient_id)

    pat = db.patients.get(patient_id)
    if not pat:
        audit.warning("Patient auth failed: unknown patient_id=%s", patient_id)
        raise HTTPException(status_code=401, detail="Patient ID not recognized.")

    if pat.get("status") != "active":
        audit.warning("Patient auth failed: inactive patient_id=%s", patient_id)
        raise HTTPException(status_code=403, detail="Patient account is not active.")

    if not verify_password(password, pat.get("password", "")):
        audit.warning("Patient auth failed: invalid password for patient_id=%s", patient_id)
        raise HTTPException(status_code=401, detail="Incorrect password.")

    token = _create_session(patient_id)
    audit.info("Patient auth success for patient_id=%s", patient_id)
    return {"status": "authorized", "token": token, "name": pat["name"]}


# ── Record Listing ───────────────────────────────────────────────────

@router.get("/records")
def list_patient_records(x_patient_token: str = Header(default="")):
    """Lists all encrypted records for the authenticated patient."""
    patient_id = _require_patient_session(x_patient_token)
    audit.info("Patient record list requested for patient_id=%s", patient_id)

    patient_dir = os.path.join(VAULT_DIR, _safe_path_component(patient_id))
    if not os.path.isdir(patient_dir):
        return []

    records = []
    for fname in sorted(os.listdir(patient_dir)):
        if not fname.endswith(".json"):
            continue
        fpath = os.path.join(patient_dir, fname)
        try:
            with open(fpath, "r") as f:
                envelope = json.load(f)
            records.append({
                "record_id": fname.replace(".json", ""),
                "timestamp": envelope.get("timestamp"),
                "patient_id": envelope.get("patient_id"),
                "master_kid": envelope.get("master_kid"),
                "payload_hash": envelope.get("payload_hash"),
                "record_hash": envelope.get("record_hash"),
            })
        except Exception:
            continue

    audit.info("Patient record list returned %d records for patient_id=%s", len(records), patient_id)
    return records


# ── Record Retrieval with DEK Verification ───────────────────────────

@router.get("/records/{record_id}")
def get_patient_record(record_id: str, x_patient_token: str = Header(default="")):
    """
    Retrieves a single record, verifies integrity (record_hash, payload_hash,
    master_kid), decrypts the master-key layer, verifies the inner DEK metadata,
    and returns the decrypted file content for the secure viewer.
    """
    patient_id = _require_patient_session(x_patient_token)
    audit.info("Patient record retrieval for patient_id=%s record_id=%s", patient_id, record_id)

    patient_dir = os.path.join(VAULT_DIR, _safe_path_component(patient_id))
    record_path = os.path.join(patient_dir, f"{record_id}.json")

    if not os.path.exists(record_path):
        raise HTTPException(status_code=404, detail="Record not found.")

    with open(record_path, "r") as f:
        stored_envelope = json.load(f)

    # ── Step 1: Verify master_kid matches server's current master key ──
    if stored_envelope.get("master_kid") != state.master_kid:
        audit.warning(
            "DEK verification failed: master_kid mismatch for record=%s (stored=%s current=%s)",
            record_id, stored_envelope.get("master_kid"), state.master_kid,
        )
        raise HTTPException(status_code=403, detail="Encryption key verification failed: master key ID mismatch.")

    # ── Step 2: Verify record_hash integrity ──
    record_hash_message = build_server_record_hash_message(
        master_kid=stored_envelope["master_kid"],
        timestamp=stored_envelope["timestamp"],
        patient_id=stored_envelope["patient_id"],
        payload=stored_envelope["payload"],
        payload_hash=stored_envelope["payload_hash"],
    )
    expected_record_hash = sha256_hex(record_hash_message)
    if expected_record_hash != stored_envelope.get("record_hash"):
        audit.warning("DEK verification failed: record_hash mismatch for record=%s", record_id)
        raise HTTPException(status_code=403, detail="Integrity check failed: record has been tampered with.")

    # ── Step 2b: Verify hospital ML-DSA-65 signature ──
    hospital_sig_b64 = stored_envelope.get("hospital_signature")
    hospital_pub_b64 = stored_envelope.get("hospital_pub")
    hospital_sig_valid = False
    if hospital_sig_b64 and hospital_pub_b64:
        try:
            hospital_sig = base64.b64decode(hospital_sig_b64)
            hospital_pub = base64.b64decode(hospital_pub_b64)
            verifier = DSAManager(private_bytes=None)
            hospital_sig_valid = verifier.verify(record_hash_message, hospital_sig, hospital_pub)
        except Exception:
            audit.warning("Hospital signature verification error for record=%s", record_id)
        if not hospital_sig_valid:
            audit.warning("Hospital signature verification FAILED for record=%s", record_id)
            raise HTTPException(status_code=403, detail="Hospital signature verification failed: record cannot be trusted.")
        audit.info("Hospital ML-DSA-65 signature verified for record=%s", record_id)
    else:
        audit.warning("Hospital signature missing from record=%s", record_id)
        raise HTTPException(status_code=403, detail="Hospital signature missing: record cannot be verified.")

    # ── Step 3: Verify payload_hash ──
    stored_payload_bytes = base64.b64decode(stored_envelope["payload"])
    computed_payload_hash = sha256_hex(stored_payload_bytes)
    if computed_payload_hash != stored_envelope.get("payload_hash"):
        audit.warning("DEK verification failed: payload_hash mismatch for record=%s", record_id)
        raise HTTPException(status_code=403, detail="Integrity check failed: payload hash mismatch.")

    # ── Step 4: Decrypt master-key at-rest layer ──
    master_nonce = stored_payload_bytes[:12]
    master_ciphertext = stored_payload_bytes[12:]
    try:
        decrypted_payload = AESGCM(state.master_key).decrypt(master_nonce, master_ciphertext, None)
    except Exception:
        audit.warning("DEK verification failed: master-key decryption failed for record=%s", record_id)
        raise HTTPException(status_code=500, detail="Decryption failed: master key could not decrypt the record.")

    # ── Step 5: Parse patient package and verify DEK metadata ──
    try:
        patient_package = json.loads(decrypted_payload.decode("utf-8"))
    except Exception:
        raise HTTPException(status_code=500, detail="Decryption succeeded but payload is malformed.")

    dek_verification = {
        "wrapped_dek_present": bool(patient_package.get("wrapped_dek")),
        "nonce_present": bool(patient_package.get("nonce")),
        "encrypted_payload_present": bool(patient_package.get("encrypted_payload")),
        "doctor_signature_present": bool(patient_package.get("doctor_signature")),
        "doctor_public_key_present": bool(patient_package.get("doctor_public_key")),
    }

    if not all(dek_verification.values()):
        audit.warning("DEK verification failed: missing fields in patient_package for record=%s: %s", record_id, dek_verification)
        raise HTTPException(status_code=403, detail="DEK verification failed: incomplete encryption metadata.")

    # ── Step 6: Attempt to decrypt the inner DEK layer ──
    file_b64 = None
    dek_b64 = patient_package.get("dek_b64")
    if dek_b64:
        try:
            dek = base64.b64decode(dek_b64)
            file_nonce = base64.b64decode(patient_package["nonce"])
            file_ciphertext = base64.b64decode(patient_package["encrypted_payload"])
            file_bytes = AESGCM(dek).decrypt(file_nonce, file_ciphertext, None)
            file_b64 = base64.b64encode(file_bytes).decode()
        except Exception:
            audit.warning("DEK decryption failed for record=%s", record_id)

    audit.info(
        "Patient record retrieved successfully: patient_id=%s record_id=%s dek_verification=%s file_recovered=%s",
        patient_id, record_id, dek_verification, file_b64 is not None,
    )
    return {
        "record_id": record_id,
        "timestamp": stored_envelope["timestamp"],
        "patient_id": patient_id,
        "dek_verification": dek_verification,
        "integrity": {
            "record_hash_valid": True,
            "payload_hash_valid": True,
            "master_kid_valid": True,
            "hospital_signature_valid": hospital_sig_valid,
            "hospital_sig_alg": stored_envelope.get("hospital_sig_alg", "unknown"),
        },
        "file_content_b64": file_b64,
        "content_type": "application/pdf",
    }
