import hashlib
import json


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
    patient_id: str,
    payload: str,
    payload_hash: str,
) -> bytes:
    """
    Deterministic context for integrity hash of stored server vault records.
    """
    return _canonical_bytes(
        {
            "kind": "server-vault-record-v1",
            "master_kid": master_kid,
            "timestamp": timestamp,
            "patient_id": patient_id,
            "payload": payload,
            "payload_hash": payload_hash,
        }
    )
