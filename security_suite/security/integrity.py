import hashlib
import json
from typing import TypedDict

class ServerVaultEnvelope(TypedDict):
    envelope_version: str
    payload_cipher_alg: str
    key_wrap_alg: str
    payload_nonce_b64: str
    payload_ciphertext_b64: str
    encrypted_dek_nonce_b64: str
    encrypted_dek_b64: str
    encrypted_dek_hash: str
    aad_hash: str

def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical_bytes(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def build_doctor_signature_message(
    *,
    kid: str,
    nonce: str,
    timestamp: int,
    patient_id: str,
    payload_hash: str,
) -> bytes:
    """
    Deterministic signature context so both signer/verifier compute identical bytes.
    """
    return _canonical_bytes(
        {
            "kind": "doctor-upload-v1",
            "kid": kid,
            "nonce": nonce,
            "timestamp": timestamp,
            "patient_id": patient_id,
            "payload_hash": payload_hash,
        }
    )


def build_server_record_hash_message(
    *,
    master_kid: str,
    timestamp: int,
    doctor_id: str,
    patient_id: str,
    payload_hash: str,
    envelope: ServerVaultEnvelope,
) -> bytes:
    """
    Deterministic context for integrity hash of stored server vault records.
    """
    return _canonical_bytes(
        {
            "kind": "server-vault-record-v2",
            "master_kid": master_kid,
            "timestamp": timestamp,
            "doctor_id": doctor_id,
            "patient_id": patient_id,
            "envelope_version": envelope["envelope_version"],
            "payload_cipher_alg": envelope["payload_cipher_alg"],
            "key_wrap_alg": envelope["key_wrap_alg"],
            "payload_nonce_b64": envelope["payload_nonce_b64"],
            "payload_ciphertext_b64": envelope["payload_ciphertext_b64"],
            "payload_hash": payload_hash,
            "encrypted_dek_nonce_b64": envelope["encrypted_dek_nonce_b64"],
            "encrypted_dek_b64": envelope["encrypted_dek_b64"],
            "encrypted_dek_hash": envelope["encrypted_dek_hash"],
            "aad_hash": envelope["aad_hash"],
        }
    )
