import os
import json
import base64
from fastapi import APIRouter, HTTPException
import time
from security_suite.security.models import SecureEnvelope
from security_suite.crypto import DSAManager
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from ..core.database import db
from ..core.server_state import state
from ..core.audit_logger import get_audit_logger

router = APIRouter(prefix="/api/doctor", tags=["Doctor Operations"])
audit = get_audit_logger()

# Create the secure storage directory
STORAGE_DIR = os.path.join(os.path.dirname(__file__), "..", "storage", "vault")
os.makedirs(STORAGE_DIR, exist_ok=True)


def _safe_path_component(value: str) -> str:
    return "".join(c if c.isalnum() or c in ("-", "_") else "_" for c in str(value))


def _print_crypto_data(label: str, data: bytes):
    full_dump = os.getenv("VAULTQ_DEBUG_FULL_DUMPS", "0") == "1"
    if full_dump:
        print(f"[CRYPTO DEBUG] {label} (len={len(data)} bytes): {base64.b64encode(data).decode()}")
        return
    preview = base64.b64encode(data[:256]).decode()
    print(
        f"[CRYPTO DEBUG] {label} (len={len(data)} bytes, preview_b64={preview}, "
        "set VAULTQ_DEBUG_FULL_DUMPS=1 for full dump)"
    )


@router.post("/upload")
def receive_record(envelope: SecureEnvelope):
    """
    Verifies Signature, decrypts transport payload, re-encrypts with server master key,
    and stores under patient-specific vault folder.
    """
    # --- 1. AUTHORIZATION & CERTIFICATE VALIDATION ---
    doctor_id = envelope.kid
    audit.info("Upload received: doctor_id=%s timestamp=%s", doctor_id, envelope.timestamp)
    
    # A. Check if the Doctor exists and is active
    doc = db.doctors.get(doctor_id)
    if not doc:
        audit.warning("Upload rejected: unknown doctor_id=%s", doctor_id)
        raise HTTPException(status_code=401, detail="Unauthorized: Doctor ID not recognized.")
        
    if doc.get('status') != 'active':
        audit.warning("Upload rejected: inactive doctor_id=%s status=%s", doctor_id, doc.get("status"))
        raise HTTPException(status_code=403, detail="Forbidden: Doctor has not been issued a valid certificate.")

    # B. Explicit Certificate Lookup
    # Safely get all certificates belonging to this doctor
    doctor_certs = [cert for cert in getattr(db, 'certificates', {}).values() if cert.get('doctor_id') == doctor_id]
    
    if not doctor_certs:
        audit.warning("Upload rejected: no certificate records for doctor_id=%s", doctor_id)
        raise HTTPException(status_code=403, detail="Forbidden: No certificate record found in CA Vault.")
        
    # C. Validate Expiration and Status
    valid_cert = None
    current_time = time.time()
    for cert in doctor_certs:
        if cert.get('status') == 'active' and cert.get('expires_at', 0) > current_time:
            valid_cert = cert
            break
            
    if not valid_cert:
        audit.warning("Upload rejected: no active/unexpired cert for doctor_id=%s", doctor_id)
        raise HTTPException(status_code=403, detail="Forbidden: Certificate is expired or revoked.")
    audit.info("Upload cert validation passed for doctor_id=%s", doctor_id)

    # --- 2. AUTHENTICATION (SIGNATURE VERIFICATION) ---
    doctor_pub_b64 = doc.get("pqc_public_key_b64")
    if not doctor_pub_b64:
        audit.warning("Upload rejected: missing enrolled PQC public key for doctor_id=%s", doctor_id)
        raise HTTPException(status_code=401, detail="Missing doctor public key for signature verification.")

    try:
        payload_bytes = base64.b64decode(envelope.payload)
        signature_bytes = base64.b64decode(envelope.signature)
        doctor_pub = base64.b64decode(doctor_pub_b64)
    except Exception:
        audit.warning("Upload rejected: malformed base64 in payload/signature/public key for doctor_id=%s", doctor_id)
        raise HTTPException(status_code=400, detail="Malformed payload/signature/public key encoding.")

    verifier = DSAManager(private_bytes=None)
    is_verified = verifier.verify(payload_bytes, signature_bytes, doctor_pub)
    if not is_verified:
        audit.warning("Upload rejected: signature verification failed for doctor_id=%s", doctor_id)
        raise HTTPException(status_code=401, detail="Invalid PQC Signature")
    audit.info("Upload signature verification passed for doctor_id=%s", doctor_id)

    # --- 3. DECRYPT TRANSPORT PAYLOAD USING ACTIVE SESSION KEY ---
    try:
        transit_nonce = base64.b64decode(envelope.nonce)
    except Exception:
        audit.warning("Upload rejected: malformed transport nonce for doctor_id=%s", doctor_id)
        raise HTTPException(status_code=400, detail="Malformed transport nonce encoding.")
    _print_crypto_data("Server transport ciphertext (before session decryption)", payload_bytes)

    decrypted_patient_package = None
    for session_key in state.active_sessions.values():
        try:
            decrypted_patient_package = AESGCM(session_key).decrypt(transit_nonce, payload_bytes, None)
            break
        except Exception:
            continue

    if decrypted_patient_package is None:
        audit.warning("Upload rejected: transport decryption failed for doctor_id=%s (no matching active session key)", doctor_id)
        raise HTTPException(status_code=401, detail="Unable to decrypt payload with active session keys.")
    audit.info("Upload transport decryption succeeded for doctor_id=%s", doctor_id)
    _print_crypto_data("Server transport plaintext (after session decryption)", decrypted_patient_package)

    # --- 4. EXTRACT PATIENT ID + RE-ENCRYPT WITH SERVER MASTER KEY ---
    patient_id = envelope.patient_id
    try:
        patient_package_obj = json.loads(decrypted_patient_package.decode("utf-8"))
        patient_id = patient_package_obj.get("patient_id", patient_id)
    except Exception:
        # Keep metadata patient_id if inner payload is not JSON-decodable
        pass

    if not patient_id:
        audit.warning("Upload rejected: missing patient_id after decryption for doctor_id=%s", doctor_id)
        raise HTTPException(status_code=400, detail="patient_id missing from payload metadata.")

    master_nonce = os.urandom(12)
    _print_crypto_data("Server plaintext (before master-key encryption)", decrypted_patient_package)
    master_ciphertext = AESGCM(state.master_key).encrypt(master_nonce, decrypted_patient_package, None)
    _print_crypto_data("Server ciphertext (after master-key encryption)", master_ciphertext)
    # Keep envelope schema exactly as requested by embedding nonce + ciphertext inside payload.
    stored_payload_b64 = base64.b64encode(master_nonce + master_ciphertext).decode()

    stored_envelope = {
        "master_kid": state.master_kid,
        "timestamp": int(time.time()),
        "patient_id": patient_id,
        "payload": stored_payload_b64,
    }

    # --- 5. STORE UNDER vault/<patient_id>/ ---
    patient_dir = os.path.join(STORAGE_DIR, _safe_path_component(str(patient_id)))
    os.makedirs(patient_dir, exist_ok=True)
    record_id = f"rec_{int(time.time())}_{_safe_path_component(base64.b64encode(os.urandom(6)).decode())}"
    file_path = os.path.join(patient_dir, f"{record_id}.json")

    with open(file_path, "w") as f:
        json.dump(stored_envelope, f, indent=4)
    audit.info(
        "Upload stored: doctor_id=%s patient_id=%s record_id=%s master_kid=%s path=%s",
        doctor_id,
        patient_id,
        record_id,
        state.master_kid,
        file_path,
    )
    
    return {
        "status": "Verified, decrypted, re-encrypted with master key, and secured",
        "record_id": record_id,
        "patient_id": patient_id,
        "master_kid": state.master_kid,
        "saved_to": file_path
    }

@router.post("/auth/change-password")
def server_change_password(doctor_id: str, old_pass: str, new_pass: str):
    audit.info("Password change requested from doctor app for doctor_id=%s", doctor_id)
    if doctor_id not in db.doctors:
        audit.warning("Password change rejected: doctor not found doctor_id=%s", doctor_id)
        raise HTTPException(status_code=404, detail="Doctor not found")
    
    # Verify old password on server
    if db.doctors[doctor_id]["password"] != old_pass:
        audit.warning("Password change rejected: old password mismatch doctor_id=%s", doctor_id)
        raise HTTPException(status_code=401, detail="Old password incorrect")
    
    # Update the permanent database
    db.doctors[doctor_id]["password"] = new_pass
    db.save_db() # Persist to hospital_vault.json
    audit.info("Password change succeeded for doctor_id=%s", doctor_id)
    
    return {"message": "Password updated successfully on server."}
