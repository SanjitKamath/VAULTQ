import os
import json
import base64
import time
from typing import Literal
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from cryptography.x509.oid import NameOID

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from security_suite.security.models import SecureEnvelope, StoredVaultEnvelope
from security_suite.security.integrity import (
    sha256_hex,
    build_doctor_signature_message,
    build_server_record_hash_message,
    ServerVaultEnvelope,
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


class PasswordChangeRequest(BaseModel):
    doctor_id: str
    old_pass: str
    new_pass: str


def parse_int_env(var_name: str, default: int) -> int:
    raw = os.getenv(var_name)
    if raw is None or not raw.strip():
        return default
    try:
        return int(raw.strip())
    except ValueError:
        audit.warning("Invalid %s=%r; using default %s", var_name, raw, default)
        return default


# Create the secure storage directory
STORAGE_DIR = os.path.join(os.path.dirname(__file__), "..", "storage", "vault")
os.makedirs(STORAGE_DIR, mode=0o700, exist_ok=True)
MAX_CLOCK_SKEW_SECONDS = 300
REPLAY_CACHE_TTL_SECONDS = 900
STORED_ENVELOPE_VERSION: Literal["v2"] = "v2"
STORED_PAYLOAD_CIPHER_ALG: Literal["AES-256-GCM"] = "AES-256-GCM"
STORED_KEY_WRAP_ALG: Literal["AES-256-GCM"] = "AES-256-GCM"
MAX_B64_PAYLOAD_BYTES = parse_int_env("VAULTQ_MAX_B64_PAYLOAD_BYTES", 11184812)  # ~8 MiB decoded
MAX_B64_SIGNATURE_BYTES = parse_int_env("VAULTQ_MAX_B64_SIGNATURE_BYTES", 32768)
MAX_DECODED_PAYLOAD_BYTES = parse_int_env("VAULTQ_MAX_DECODED_PAYLOAD_BYTES", 8388608)  # 8 MiB
MAX_DECODED_SIGNATURE_BYTES = parse_int_env("VAULTQ_MAX_DECODED_SIGNATURE_BYTES", 24576)


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


def _build_storage_aad(*, master_kid: str, doctor_id: str, patient_id: str, timestamp: int) -> bytes:
    return json.dumps(
        {
            "kind": "server-vault-storage-aad-v1",
            "master_kid": master_kid,
            "doctor_id": doctor_id,
            "patient_id": patient_id,
            "timestamp": timestamp,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


@router.post("/upload")
def receive_record(envelope: SecureEnvelope):
    """
    Verifies signature and stores the Application-Layer payload using per-record envelope encryption:
    payload is encrypted with a DEK, and the DEK is encrypted with the server master key.
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
        audit.warning("Upload rejected: missing certificate payload for doctor_id=%s cert_id=%s", doctor_id, valid_cert.get("id"))
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
    except HTTPException as exc:
        audit.warning(
            "Upload rejected: certificate validation failed for doctor_id=%s detail=%s",
            doctor_id,
            str(getattr(exc, "detail", "certificate validation error")),
        )
        raise
    except Exception:
        audit.exception("Upload rejected: certificate chain/signature validation exception for doctor_id=%s", doctor_id)
        raise HTTPException(status_code=403, detail="Certificate chain/signature validation failed.")

    try:
        # payload_bytes is now the plaintext JSON because mTLS handled the transport layer
        if len(envelope.payload) > MAX_B64_PAYLOAD_BYTES:
            audit.warning(
                "Upload rejected: payload b64 too large for doctor_id=%s size=%s max=%s",
                doctor_id,
                len(envelope.payload),
                MAX_B64_PAYLOAD_BYTES,
            )
            raise HTTPException(status_code=413, detail="Payload too large.")

        if len(envelope.signature) > MAX_B64_SIGNATURE_BYTES:
            audit.warning(
                "Upload rejected: signature b64 too large for doctor_id=%s size=%s max=%s",
                doctor_id,
                len(envelope.signature),
                MAX_B64_SIGNATURE_BYTES,
            )
            raise HTTPException(status_code=413, detail="Signature too large.")

        payload_bytes = base64.b64decode(envelope.payload)
        signature_bytes = base64.b64decode(envelope.signature)
    except HTTPException:
        raise
    except Exception:
        audit.warning("Upload rejected: malformed payload/signature encoding for doctor_id=%s", doctor_id)
        raise HTTPException(status_code=400, detail="Malformed payload/signature encoding.")

    if len(payload_bytes) > MAX_DECODED_PAYLOAD_BYTES:
        audit.warning(
            "Upload rejected: decoded payload too large for doctor_id=%s size=%s max=%s",
            doctor_id,
            len(payload_bytes),
            MAX_DECODED_PAYLOAD_BYTES,
        )
        raise HTTPException(status_code=413, detail="Payload too large.")

    if len(signature_bytes) > MAX_DECODED_SIGNATURE_BYTES:
        audit.warning(
            "Upload rejected: decoded signature too large for doctor_id=%s size=%s max=%s",
            doctor_id,
            len(signature_bytes),
            MAX_DECODED_SIGNATURE_BYTES,
        )
        raise HTTPException(status_code=413, detail="Signature too large.")

    computed_payload_hash = sha256_hex(payload_bytes)
    if computed_payload_hash != envelope.payload_hash:
        audit.warning(
            "Upload rejected: payload hash mismatch for doctor_id=%s expected=%s computed=%s",
            doctor_id,
            envelope.payload_hash,
            computed_payload_hash,
        )
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

    # --- 3. EXTRACT PATIENT ID + ENVELOPE-ENCRYPT WITH PER-RECORD DEK ---
    patient_id = envelope.patient_id
    try:
        patient_package_obj = json.loads(payload_bytes.decode("utf-8"))
        patient_id = patient_package_obj.get("patient_id", patient_id)
    except Exception:
        pass

    if not patient_id:
        audit.warning("Upload rejected: patient_id missing after payload parse for doctor_id=%s", doctor_id)
        raise HTTPException(status_code=400, detail="patient_id missing from payload metadata.")

    # Encrypt payload with a per-record DEK, then encrypt DEK with the server master key.
    stored_timestamp = int(time.time())
    storage_aad = _build_storage_aad(
        master_kid=state.master_kid,
        doctor_id=doctor_id,
        patient_id=str(patient_id),
        timestamp=stored_timestamp,
    )
    aad_hash = sha256_hex(storage_aad)
    record_dek = AESGCM.generate_key(bit_length=256)

    payload_nonce = os.urandom(12)
    _print_crypto_data("Server plaintext (before DEK encryption)", payload_bytes)
    payload_ciphertext = AESGCM(record_dek).encrypt(payload_nonce, payload_bytes, storage_aad)
    _print_crypto_data("Server ciphertext (after DEK encryption)", payload_ciphertext)
    stored_payload_bytes = payload_nonce + payload_ciphertext
    stored_payload_hash = sha256_hex(stored_payload_bytes)

    encrypted_dek_nonce = os.urandom(12)
    encrypted_dek = AESGCM(state.master_key).encrypt(encrypted_dek_nonce, record_dek, storage_aad)
    stored_encrypted_dek_bytes = encrypted_dek_nonce + encrypted_dek
    stored_encrypted_dek_hash = sha256_hex(stored_encrypted_dek_bytes)

    payload_nonce_b64 = base64.b64encode(payload_nonce).decode()
    payload_ciphertext_b64 = base64.b64encode(payload_ciphertext).decode()
    encrypted_dek_nonce_b64 = base64.b64encode(encrypted_dek_nonce).decode()
    encrypted_dek_b64 = base64.b64encode(encrypted_dek).decode()
    record_envelope: ServerVaultEnvelope = {
        "envelope_version": STORED_ENVELOPE_VERSION,
        "payload_cipher_alg": STORED_PAYLOAD_CIPHER_ALG,
        "key_wrap_alg": STORED_KEY_WRAP_ALG,
        "payload_nonce_b64": payload_nonce_b64,
        "payload_ciphertext_b64": payload_ciphertext_b64,
        "encrypted_dek_nonce_b64": encrypted_dek_nonce_b64,
        "encrypted_dek_b64": encrypted_dek_b64,
        "encrypted_dek_hash": stored_encrypted_dek_hash,
        "aad_hash": aad_hash,
    }

    record_hash = sha256_hex(
        build_server_record_hash_message(
            master_kid=state.master_kid,
            timestamp=stored_timestamp,
            doctor_id=doctor_id,
            patient_id=str(patient_id),
            payload_hash=stored_payload_hash,
            envelope=record_envelope,
        )
    )

    stored_envelope = StoredVaultEnvelope(
        master_kid=state.master_kid,
        timestamp=stored_timestamp,
        doctor_id=doctor_id,
        patient_id=str(patient_id),
        envelope_version=STORED_ENVELOPE_VERSION,
        payload_cipher_alg=STORED_PAYLOAD_CIPHER_ALG,
        key_wrap_alg=STORED_KEY_WRAP_ALG,
        payload_nonce_b64=payload_nonce_b64,
        payload_ciphertext_b64=payload_ciphertext_b64,
        payload_hash=stored_payload_hash,
        encrypted_dek_nonce_b64=encrypted_dek_nonce_b64,
        encrypted_dek_b64=encrypted_dek_b64,
        encrypted_dek_hash=stored_encrypted_dek_hash,
        aad_hash=aad_hash,
        record_hash=record_hash,
    )

    # --- 4. STORE UNDER vault/<patient_id>/ ---
    patient_dir = os.path.join(STORAGE_DIR, _safe_path_component(str(patient_id)))
    os.makedirs(patient_dir, mode=0o700, exist_ok=True)
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
            "envelope_version": STORED_ENVELOPE_VERSION,
            "payload_cipher_alg": STORED_PAYLOAD_CIPHER_ALG,
            "key_wrap_alg": STORED_KEY_WRAP_ALG,
            "stored_payload_hash": stored_payload_hash,
            "stored_encrypted_dek_hash": stored_encrypted_dek_hash,
            "aad_hash": aad_hash,
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
def server_change_password(payload: PasswordChangeRequest):
    doctor_id = payload.doctor_id
    old_pass = payload.old_pass
    new_pass = payload.new_pass
    audit.info("Password change requested from doctor app for doctor_id=%s", doctor_id)
    if doctor_id not in db.doctors:
        audit.warning("Password change rejected: doctor not found doctor_id=%s", doctor_id)
        raise HTTPException(status_code=404, detail="Doctor not found")

    old_pass = (old_pass or "").strip()
    new_pass = (new_pass or "").strip()
    if not old_pass or not new_pass:
        audit.warning("Password change rejected: empty old/new password doctor_id=%s", doctor_id)
        raise HTTPException(status_code=400, detail="Old and new passwords are required")
    if old_pass == new_pass:
        audit.warning("Password change rejected: new password matches old for doctor_id=%s", doctor_id)
        raise HTTPException(status_code=400, detail="New password must be different from old password")
    
    # Securely verify the old password using bcrypt
    if not verify_password(old_pass, db.doctors[doctor_id].get("password", "")):
        audit.warning("Password change rejected: old password mismatch doctor_id=%s", doctor_id)
        raise HTTPException(status_code=401, detail="Old password incorrect")
    
    # Hash the new password using bcrypt before storing it
    db.doctors[doctor_id]["password"] = hash_password(new_pass)
    db.save_db()
    audit.info("Password change succeeded for doctor_id=%s", doctor_id)
    
    return {"message": "Password updated successfully on server."}
