import os
import json
import base64
import time
from fastapi import APIRouter, HTTPException
from cryptography.x509.oid import NameOID

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from security_suite.security.models import SecureEnvelope, StoredVaultEnvelope
from security_suite.security.integrity import (
    sha256_hex,
    build_doctor_signature_message,
    build_server_record_hash_message,
)
from security_suite.crypto import DSAManager
from security_suite.security.certificates import (
    load_pem_certificate,
    extract_pqc_public_key_from_cert,
    verify_cert_chain,
)

from ..core.database import db
from ..core.server_state import state
from ..core.audit_logger import get_audit_logger
from ..core.auth_utils import verify_password, hash_password  # For secure bcrypt passwords
from ..core.integrity_audit import append_integrity_event

router = APIRouter(prefix="/api/doctor", tags=["Doctor Operations"])
audit = get_audit_logger()

# Create the secure storage directory
STORAGE_DIR = os.path.join(os.path.dirname(__file__), "..", "storage", "vault")
os.makedirs(STORAGE_DIR, exist_ok=True)
MAX_CLOCK_SKEW_SECONDS = 300
REPLAY_CACHE_TTL_SECONDS = 900


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
    Verifies Signature, re-encrypts the Application-Layer payload with the server master key,
    and stores under patient-specific vault folder. 
    (Transport decryption is natively handled by mTLS).
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

    # --- 2. FRESHNESS + REPLAY CHECKS ---
    if abs(int(current_time) - int(envelope.timestamp)) > MAX_CLOCK_SKEW_SECONDS:
        audit.warning(
            "Upload rejected: stale timestamp for doctor_id=%s timestamp=%s now=%s",
            doctor_id,
            envelope.timestamp,
            int(current_time),
        )
        raise HTTPException(status_code=401, detail="Stale or invalid timestamp.")

    message_id = f"{doctor_id}:{envelope.nonce}:{envelope.timestamp}"
    if state.replay_seen_or_store(message_id, REPLAY_CACHE_TTL_SECONDS):
        audit.warning("Upload rejected: replay detected for doctor_id=%s message_id=%s", doctor_id, message_id)
        raise HTTPException(status_code=401, detail="Replay detected.")

    # --- 2. AUTHENTICATION (APPLICATION-LAYER SIGNATURE VERIFICATION) ---
    cert_pem = valid_cert.get("pem_data")
    if not cert_pem:
        raise HTTPException(status_code=403, detail="Forbidden: Missing certificate payload.")

    try:
        cert_obj = load_pem_certificate(cert_pem)
        if cert_obj.issuer != state.hospital_root_cert.subject:
            raise HTTPException(status_code=403, detail="Certificate issuer mismatch.")

        if not verify_cert_chain(cert_obj, state.hospital_root_cert):
            raise HTTPException(status_code=403, detail="Unsupported issuer public key type.")
        if cert_obj.not_valid_before.timestamp() > current_time or cert_obj.not_valid_after.timestamp() < current_time:
            raise HTTPException(status_code=403, detail="Certificate validity window check failed.")

        subject_ids = cert_obj.subject.get_attributes_for_oid(NameOID.USER_ID)
        if not subject_ids or subject_ids[0].value != doctor_id:
            raise HTTPException(status_code=403, detail="Certificate subject does not match doctor identity.")

        cert_bound_doctor_pub = extract_pqc_public_key_from_cert(cert_obj)
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=403, detail="Certificate chain/signature validation failed.")

    try:
        # payload_bytes is now the plaintext JSON because mTLS handled the transport layer
        payload_bytes = base64.b64decode(envelope.payload)
        signature_bytes = base64.b64decode(envelope.signature)
    except Exception:
        raise HTTPException(status_code=400, detail="Malformed payload/signature encoding.")

    computed_payload_hash = sha256_hex(payload_bytes)
    if computed_payload_hash != envelope.payload_hash:
        raise HTTPException(status_code=401, detail="Integrity check failed: payload hash mismatch.")

    signature_message = build_doctor_signature_message(
        kid=envelope.kid,
        nonce=envelope.nonce,
        timestamp=envelope.timestamp,
        patient_id=envelope.patient_id,
        payload_hash=envelope.payload_hash,
    )

    verifier = DSAManager(private_bytes=None)
    is_verified = verifier.verify(signature_message, signature_bytes, cert_bound_doctor_pub)
    if not is_verified:
        audit.warning("Upload rejected: signature verification failed for doctor_id=%s", doctor_id)
        raise HTTPException(status_code=401, detail="Invalid PQC Signature")
    
    audit.info("Application-layer signature verification passed for doctor_id=%s", doctor_id)

    # --- 3. EXTRACT PATIENT ID + RE-ENCRYPT WITH SERVER MASTER KEY ---
    patient_id = envelope.patient_id
    try:
        patient_package_obj = json.loads(payload_bytes.decode("utf-8"))
        patient_id = patient_package_obj.get("patient_id", patient_id)
    except Exception:
        pass

    if not patient_id:
        raise HTTPException(status_code=400, detail="patient_id missing from payload metadata.")

    # Encrypt the package for at-rest storage
    master_nonce = os.urandom(12)
    _print_crypto_data("Server plaintext (before master-key encryption)", payload_bytes)
    master_ciphertext = AESGCM(state.master_key).encrypt(master_nonce, payload_bytes, None)
    _print_crypto_data("Server ciphertext (after master-key encryption)", master_ciphertext)
    
    stored_payload_bytes = master_nonce + master_ciphertext
    stored_payload_b64 = base64.b64encode(stored_payload_bytes).decode()
    stored_payload_hash = sha256_hex(stored_payload_bytes)
    stored_timestamp = int(time.time())
    record_hash_message = build_server_record_hash_message(
        master_kid=state.master_kid,
        timestamp=stored_timestamp,
        patient_id=str(patient_id),
        payload=stored_payload_b64,
        payload_hash=stored_payload_hash,
    )
    record_hash = sha256_hex(record_hash_message)

    # Hospital signs the record with its ML-DSA-65 CA key (rotation-safe: pub key embedded)
    hospital_signature = state.hospital_ca.sign(record_hash_message)
    audit.info("Hospital ML-DSA-65 signature applied to record for patient_id=%s", patient_id)

    stored_envelope = StoredVaultEnvelope(
        master_kid=state.master_kid,
        timestamp=stored_timestamp,
        patient_id=str(patient_id),
        payload=stored_payload_b64,
        payload_hash=stored_payload_hash,
        record_hash=record_hash,
        hospital_signature=base64.b64encode(hospital_signature).decode(),
        hospital_pub=base64.b64encode(state.hospital_ca.get_public_bytes()).decode(),
        hospital_sig_alg="ML-DSA-65",
    )

    # --- 4. STORE UNDER vault/<patient_id>/ ---
    patient_dir = os.path.join(STORAGE_DIR, _safe_path_component(str(patient_id)))
    os.makedirs(patient_dir, exist_ok=True)
    record_id = f"rec_{int(time.time())}_{_safe_path_component(base64.b64encode(os.urandom(6)).decode())}"
    file_path = os.path.join(patient_dir, f"{record_id}.json")

    with open(file_path, "w") as f:
        json.dump(stored_envelope.model_dump(), f, indent=4)

    integrity_event_path = append_integrity_event(
        {
            "kind": "upload_integrity_v1",
            "timestamp": stored_timestamp,
            "doctor_id": doctor_id,
            "message_id": message_id,
            "nonce": envelope.nonce,
            "request_timestamp": envelope.timestamp,
            "patient_id": str(patient_id),
            "payload_hash": envelope.payload_hash,
            "signature_b64": envelope.signature,
            "record_id": record_id,
            "record_hash": record_hash,
            "cert_id": valid_cert.get("id"),
        }
    )
        
    audit.info(
        "Upload stored: doctor_id=%s patient_id=%s record_id=%s master_kid=%s path=%s integrity_log=%s",
        doctor_id, patient_id, record_id, state.master_kid, file_path, integrity_event_path,
    )
    
    return {
        "status": "Verified, re-encrypted with master key, and secured",
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
    
    # Securely verify the old password using bcrypt
    if not verify_password(old_pass, db.doctors[doctor_id].get("password", "")):
        audit.warning("Password change rejected: old password mismatch doctor_id=%s", doctor_id)
        raise HTTPException(status_code=401, detail="Old password incorrect")
    
    # Hash the new password using bcrypt before storing it
    db.doctors[doctor_id]["password"] = hash_password(new_pass)
    db.save_db()
    audit.info("Password change succeeded for doctor_id=%s", doctor_id)
    
    return {"message": "Password updated successfully on server."}
