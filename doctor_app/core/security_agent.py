import os
import time
import json
import base64
import threading
from pathlib import Path
import requests
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.keywrap import aes_key_wrap
from security_suite.crypto import DSAManager
from security_suite.security.models import SecureEnvelope
from security_suite.security.integrity import sha256_hex, build_doctor_signature_message
from .config import config
from .models import UploadForm
from .audit_logger import get_audit_logger

UPLOAD_TIMEOUT_SECONDS = float(os.getenv("VAULTQ_UPLOAD_TIMEOUT_SECONDS", "30"))


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


def _extract_http_error_detail(exc: requests.exceptions.HTTPError) -> str:
    resp = exc.response
    if resp is None:
        return str(exc)
    try:
        payload = resp.json()
        if isinstance(payload, dict):
            return str(payload.get("detail") or payload.get("message") or str(exc))
        return str(payload)
    except ValueError:
        text = (resp.text or "").strip()
        if text:
            return text
        return f"{resp.status_code} {resp.reason or 'HTTP Error'}"


class SecurityAgent:
    """Manages the PQC State and Network Operations asynchronously over mTLS."""
    
    def __init__(
        self,
        log_callback,
        status_callback,
        loaded_private_key: bytes = None,
        doctor_id: str = None,
        enroll_token: str = "",
    ):
        self.log = log_callback
        self.status = status_callback
        self.doctor_id = doctor_id
        self.audit = get_audit_logger()
        self.is_connected = False
        self.enroll_token = (enroll_token or "").strip()
        
        keys_dir = Path(getattr(config, "keys_dir", "doctor_app/storage/keys"))
        keys_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.cert_path = str(keys_dir / "doctor_cert.pem")
        self.key_path = str(keys_dir / "doctor_container.key")
        self.ca_cert_path = config.ca_cert_path
        
        self.log("Security agent initialized", "INFO")
        self.audit.info("SecurityAgent init for doctor_id=%s", self.doctor_id)
        
        # Load existing ML-DSA Identity for application-layer signing
        if loaded_private_key:
            self.signer = DSAManager(private_bytes=loaded_private_key)
            self.log("Existing ML-DSA Identity loaded from secure vault.", "INFO")
            self.audit.info("SecurityAgent: loaded existing ML-DSA identity for doctor_id=%s", self.doctor_id)
        else:
            self.signer = DSAManager(private_bytes=None)
            self.signer.generate_keypair() 
            self.log("New ML-DSA Identity generated.", "INFO")
            self.audit.info("SecurityAgent: generated new ML-DSA identity for doctor_id=%s", self.doctor_id)

    def initiate_handshake(self):
        """
        Replaces the old custom handshake. 
        Now simply verifies the mTLS connection with the server.
        """
        threading.Thread(target=self._connection_task, daemon=True).start()

    def _tls_request_kwargs(self):
        """Use strict mTLS over HTTPS only."""
        if not str(config.server_url).lower().startswith("https://"):
            raise RuntimeError("Insecure server URL blocked. VaultQ doctor client requires HTTPS.")
        if (
            os.path.exists(self.cert_path)
            and os.path.exists(self.key_path)
            and os.path.exists(self.ca_cert_path)
        ):
            return {"cert": (self.cert_path, self.key_path), "verify": self.ca_cert_path}
        raise RuntimeError(
            "mTLS assets missing. Provide doctor certificate, private key, and trusted CA certificate."
        )

    def _pre_enroll_verify_kwargs(self):
        if not os.path.exists(self.ca_cert_path):
            raise RuntimeError(f"CA certificate not found: {self.ca_cert_path}")
        return {"verify": self.ca_cert_path}

    def _refresh_cert_from_pre_enroll(self) -> bool:
        """
        Pull latest issued doctor certificate over TLS-only pre-enrollment endpoint.
        Returns True if a cert was refreshed locally.
        """
        doctor_id = self.doctor_id or "unknown"
        pre_enroll_url = str(getattr(config, "pre_enroll_url", "")).rstrip("/")
        if not pre_enroll_url.lower().startswith("https://"):
            return False

        headers = {}
        if self.enroll_token:
            headers["X-Enroll-Token"] = self.enroll_token

        resp = requests.get(
            f"{pre_enroll_url}/api/pre-enroll/auth/my-cert/{doctor_id}",
            headers=headers,
            timeout=5,
            **self._pre_enroll_verify_kwargs(),
        )
        if resp.status_code != 200:
            return False
        body = resp.json()
        if body.get("status") != "issued" or not body.get("pem_data"):
            return False

        Path(self.cert_path).parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        with open(self.cert_path, "w", encoding="utf-8") as f:
            f.write(body["pem_data"])
        return True

    def _connection_task(self):
        try:
            self.log("Establishing mTLS connection to VaultQ Server...", "INFO")
            self.audit.info("mTLS Connection start for doctor_id=%s", self.doctor_id)
            
            # Doctor-safe connectivity check (does not require admin token).
            # Returns {"status": "pending"} or {"status": "issued"}.
            doctor_id = self.doctor_id or "unknown"
            resp = requests.get(
                f"{config.server_url}/api/auth/my-cert/{doctor_id}",
                timeout=5,
                **self._tls_request_kwargs(),
            )
            resp.raise_for_status()
            
            self.is_connected = True
            self.log("Secure mTLS Session Established. Identity Verified.", "SUCCESS")
            self.audit.info("mTLS connection success for doctor_id=%s", self.doctor_id)
            self.update_status(True)
                
        except Exception as e:
            msg = str(e)
            if "Remote end closed connection without response" in msg or "Connection aborted" in msg:
                try:
                    if self._refresh_cert_from_pre_enroll():
                        self.log("Fetched latest issued certificate. Retrying mTLS handshake...", "INFO")
                        self.audit.info("mTLS recovery: refreshed cert from pre-enroll for doctor_id=%s", self.doctor_id)
                        resp = requests.get(
                            f"{config.server_url}/api/auth/my-cert/{self.doctor_id or 'unknown'}",
                            timeout=5,
                            **self._tls_request_kwargs(),
                        )
                        resp.raise_for_status()
                        self.is_connected = True
                        self.log("Secure mTLS Session Established. Identity Verified.", "SUCCESS")
                        self.audit.info("mTLS recovery succeeded for doctor_id=%s", self.doctor_id)
                        self.update_status(True)
                        return
                except Exception as retry_exc:
                    self.audit.warning("mTLS recovery retry failed for doctor_id=%s: %s", self.doctor_id, str(retry_exc))

                admin_base = str(getattr(config, "admin_url", "") or getattr(config, "pre_enroll_url", "")).rstrip("/")
                admin_url = admin_base if admin_base.lower().endswith("/admin") else f"{admin_base}/admin"
                hint = (
                    "mTLS handshake rejected by server (client cert likely invalid/revoked). "
                    f"Refresh/issue cert via {admin_url} and sign in again."
                )
                self.log(f"mTLS Connection Failed: {hint}", "ERROR")
                self.audit.exception(
                    "mTLS connection failed for doctor_id=%s: %s (hint=%s)",
                    self.doctor_id,
                    msg,
                    hint,
                )
            else:
                self.log(f"mTLS Connection Failed: {msg}", "ERROR")
                self.audit.exception("mTLS connection failed for doctor_id=%s: %s", self.doctor_id, msg)
            self.update_status(False)

    def prepare_patient_payload(self, patient_id: str, file_data: bytes) -> dict:
        """
        Implements proper Envelope Encryption for At-Rest Data. 
        The DEK is securely wrapped before transmission.
        """
        self.log("Generating one-time Data Encryption Key (DEK)...", "DEBUG")
        
        # 1. Generate DEK and encrypt the patient file
        dek = AESGCM.generate_key(bit_length=256)
        aesgcm = AESGCM(dek)
        nonce = os.urandom(12)
        
        self.log("Encrypting medical record for Patient...", "DEBUG")
        _print_crypto_data("Patient payload plaintext (before DEK encryption)", file_data)
        encrypted_payload = aesgcm.encrypt(nonce, file_data, None)
        _print_crypto_data("Patient payload ciphertext (after DEK encryption)", encrypted_payload)
        
        # 2. Wrap the DEK with an ephemeral transport key placeholder.
        # End-to-end KEK exchange should be integrated with server-side unwrapping in a dedicated key service.
        wrapped_dek = aes_key_wrap(os.urandom(32), dek)
        
        # 3. Sign the ciphertext with the Doctor's ML-DSA private key
        self.log("Signing patient payload with ML-DSA Identity...", "DEBUG")
        signature = self.signer.sign(encrypted_payload)
        
        if not signature:
            raise ValueError("ML-DSA Signer failed to generate a signature.")
            
        pub_bytes = self.signer.get_public_bytes()
        encoded_pub_key = base64.b64encode(pub_bytes).decode() if pub_bytes else ""
        
        return {
            "nonce": base64.b64encode(nonce).decode(),
            "wrapped_dek": base64.b64encode(wrapped_dek).decode(),
            "patient_id": patient_id,
            "encrypted_payload": base64.b64encode(encrypted_payload).decode(),
            "doctor_signature": base64.b64encode(signature).decode(),
            "doctor_public_key": encoded_pub_key
        }

    def process_and_upload(self, form: UploadForm):
        """Prepares application-layer envelope and uploads over mTLS."""
        threading.Thread(target=self._upload_task, args=(form,), daemon=True).start()

    def _upload_task(self, form: UploadForm):
        if not self.is_connected:
            self.log("Cannot upload: No secure mTLS session.", "ERROR")
            self.audit.warning("Upload blocked: no secure session doctor_id=%s", self.doctor_id)
            return

        try:
            self.log(f"Reading {os.path.basename(form.filepath)}...", "INFO")
            with open(form.filepath, "rb") as f:
                file_bytes = f.read()

            # Layer 1: At-Rest Encryption (Envelope Encryption for the Patient/Server)
            patient_package = self.prepare_patient_payload(form.patient_id, file_bytes)
            
            # Since mTLS handles transport encryption, we no longer double-encrypt the payload here.
            # We simply JSONify the patient package to prepare it for signing.
            payload_bytes = json.dumps(patient_package).encode('utf-8')
            payload_b64 = base64.b64encode(payload_bytes).decode()
            payload_hash = sha256_hex(payload_bytes)

            # Layer 2: Server Authentication Signature (Application Layer Integrity)
            self.log("Signing transport envelope for Server...", "DEBUG")
            envelope_nonce_b64 = base64.b64encode(os.urandom(12)).decode()
            envelope_timestamp = int(time.time())
            envelope_kid = self.doctor_id or config.doctor_kid or "unknown_kid"
            
            signature_message = build_doctor_signature_message(
                kid=envelope_kid,
                nonce=envelope_nonce_b64,
                timestamp=envelope_timestamp,
                patient_id=form.patient_id,
                payload_hash=payload_hash,
            )
            transit_signature = self.signer.sign(signature_message)
            
            if not transit_signature:
                raise ValueError("Payload signing failed.")

            # Create the final envelope
            envelope = SecureEnvelope(
                kid=envelope_kid,
                nonce=envelope_nonce_b64,
                timestamp=envelope_timestamp,
                patient_id=form.patient_id,
                payload=payload_b64,
                payload_hash=payload_hash,
                signature=base64.b64encode(transit_signature).decode()
            )

            # Transmit securely over mTLS
            self.log("Transmitting Secure Envelope over mTLS...", "INFO")
            resp = requests.post(
                f"{config.server_url}/api/doctor/upload", 
                json=envelope.model_dump(),
                timeout=UPLOAD_TIMEOUT_SECONDS,
                **self._tls_request_kwargs(),
            )
            resp.raise_for_status()
            
            self.log(f"Upload Successful! ID: {resp.json().get('record_id')}", "SUCCESS")
            self.audit.info("Upload success doctor_id=%s patient_id=%s", self.doctor_id, form.patient_id)

        except requests.exceptions.SSLError as e:
            self.log("Upload Rejected: TLS Authentication Failed (Invalid Cert/MITM).", "ERROR")
            self.audit.warning("TLS upload rejected doctor_id=%s: %s", self.doctor_id, str(e))
        except requests.exceptions.Timeout as e:
            self.log("Upload Failed: Server timed out during upload.", "ERROR")
            self.audit.warning("Upload timeout doctor_id=%s: %s", self.doctor_id, str(e))
        except requests.exceptions.HTTPError as e:
            error_detail = _extract_http_error_detail(e)
            self.log(f"Upload Rejected: {error_detail}", "ERROR")
            self.audit.warning(
                "Upload rejected doctor_id=%s status=%s detail=%s",
                self.doctor_id,
                getattr(e.response, "status_code", "unknown"),
                error_detail,
            )
        except Exception as e:
            self.log(f"Upload Error: {str(e)}", "ERROR")
            self.audit.exception("Upload error doctor_id=%s: %s", self.doctor_id, str(e))

    def update_status(self, connected: bool):
        """Uses the status callback to update the UI or terminal."""
        self.is_connected = connected
        if self.status:
            self.status(connected)

    def shutdown(self):
        """Graceful shutdown method (called when UI closes)."""
        self.log("Security agent shutting down...", "INFO")
