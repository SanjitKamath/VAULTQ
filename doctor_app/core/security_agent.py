import os
import time
import json
import base64
import threading
import requests
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from security_suite.crypto import ECDHManager, KEMManager, DSAManager, HybridSessionManager
from security_suite.security.models import SecureEnvelope
from .config import config
from .models import HandshakeResponse, HandshakePayload, UploadForm

class SecurityAgent:
    """Manages the PQC State and Network Operations asynchronously."""
    
    # CRITICAL FIX 1: Accept the loaded_private_key and doctor_id
    def __init__(self, log_callback, status_callback, loaded_private_key: bytes = None, doctor_id: str = None):
        self.log = log_callback
        self.status = status_callback
        self.doctor_id = doctor_id # Store the ID for the SecureEnvelope
        
        self.session_key = None
        self.is_connected = False
        
        self.log("Security agent initialized", "INFO")
        
        # Load existing key if logged in, otherwise generate a new one
        if loaded_private_key:
            self.signer = DSAManager(private_bytes=loaded_private_key)
            self.log("Existing ML-DSA Identity loaded from secure vault.", "INFO")
        else:
            self.signer = DSAManager(private_bytes=None)
            self.signer.generate_keypair() 
            self.log("New ML-DSA Identity generated.", "INFO")
        
        self.ecdh = ECDHManager()
        self.kem = KEMManager()

    def initiate_handshake(self):
        """Runs the Hybrid Handshake in a background thread."""
        threading.Thread(target=self._handshake_task, daemon=True).start()

    def _handshake_task(self):
        try:
            self.log("Connecting to VaultQ Server...", "INFO")
            
            # Step 1: Init
            resp = requests.get(f"{config.server_url}/handshake/init", timeout=5)
            resp.raise_for_status()
            server_keys = HandshakeResponse(**resp.json())
            
            self.log("Received Server Hybrid Public Keys.", "DEBUG")
            
            # Step 2: Exchange
            ct, ss_pqc = self.kem.encapsulate(base64.b64decode(server_keys.pqc_pub))
            ss_ecdh = self.ecdh.compute_shared_secret(base64.b64decode(server_keys.ecdh_pub))
            
            # Step 3: Derive
            self.session_key = HybridSessionManager.derive_final_session_key(ss_pqc, ss_ecdh)
            
            # Step 4: Complete
            payload = HandshakePayload(
                pqc_ct=base64.b64encode(ct).decode(),
                ecdh_pub=base64.b64encode(self.ecdh.get_public_bytes()).decode()
            )
            
            verify_resp = requests.post(f"{config.server_url}/handshake/complete", json=payload.model_dump())
            verify_resp.raise_for_status()
            
            proof = verify_resp.json().get("server_proof")
            my_proof = HybridSessionManager.generate_session_proof(self.session_key)
            
            if proof == my_proof:
                self.is_connected = True
                self.log("Handshake Complete. Quantum-Secure Session Established.", "SUCCESS")
                self.update_status(True)
            else:
                raise ValueError("MITM Detected: Proof mismatch.")
                
        except Exception as e:
            self.log(f"Handshake Failed: {str(e)}", "ERROR")
            self.update_status(False)

    def prepare_patient_payload(self, file_data: bytes, patient_public_key: bytes = None) -> dict:
        """
        Implements Envelope Encryption for the Patient Record (At-Rest Security).
        """
        self.log("Generating one-time Data Encryption Key (DEK)...", "DEBUG")
        dek = AESGCM.generate_key(bit_length=256)
        aesgcm = AESGCM(dek)
        nonce = os.urandom(12)
        
        self.log("Encrypting medical record for Patient...", "DEBUG")
        encrypted_payload = aesgcm.encrypt(nonce, file_data, None)
        
        # Wrap the DEK (Mocked for now until we build the Patient App's key generation)
        wrapped_dek = dek  
        
        self.log("Signing patient payload with ML-DSA Identity...", "DEBUG")
        signature = self.signer.sign(encrypted_payload)
        
        # Guard clause in case the signer itself fails
        if not signature:
            raise ValueError("ML-DSA Signer failed to generate a signature.")
            
        # FIX: Safely handle the public key since the local vault only loaded the private key
        pub_bytes = self.signer.get_public_bytes()
        encoded_pub_key = base64.b64encode(pub_bytes).decode() if pub_bytes else ""
        
        return {
            "nonce": base64.b64encode(nonce).decode(),
            "wrapped_dek": base64.b64encode(wrapped_dek).decode(),
            "encrypted_payload": base64.b64encode(encrypted_payload).decode(),
            "doctor_signature": base64.b64encode(signature).decode(),
            "doctor_public_key": encoded_pub_key # Will send an empty string safely if None
        }

    def process_and_upload(self, form: UploadForm):
        """Executes double-encryption and uploads the document."""
        threading.Thread(target=self._upload_task, args=(form,), daemon=True).start()

    def _upload_task(self, form: UploadForm):
        if not self.is_connected:
            self.log("Cannot upload: No secure session.", "ERROR")
            return

        try:
            self.log(f"Reading {os.path.basename(form.filepath)}...", "INFO")
            with open(form.filepath, "rb") as f:
                file_bytes = f.read()

            # CRITICAL FIX 2: Implement Double Encryption Architecture
            
            # Layer 1: At-Rest Encryption (Envelope Encryption for the Patient)
            patient_package = self.prepare_patient_payload(file_bytes)
            patient_package_bytes = json.dumps(patient_package).encode('utf-8')

            # Layer 2: In-Transit Encryption (Hybrid Handshake Session Key)
            self.log("Applying Transport Encryption...", "DEBUG")
            transit_aes = AESGCM(self.session_key)
            transit_nonce = os.urandom(12)
            transit_ciphertext = transit_aes.encrypt(transit_nonce, patient_package_bytes, None)

            # 3. Server Authentication Signature
            self.log("Signing transport envelope for Server...", "DEBUG")
            transit_signature = self.signer.sign(transit_ciphertext)
            
            if not transit_signature:
                raise ValueError("Transport signing failed.")

            # 4. Package for Server Storage
            # FIX: Ensure we use self.doctor_id as the kid
            envelope = SecureEnvelope(
                kid=self.doctor_id or config.doctor_kid or "unknown_kid",
                nonce=base64.b64encode(transit_nonce).decode(),
                timestamp=int(time.time()),
                payload=base64.b64encode(transit_ciphertext).decode(),
                signature=base64.b64encode(transit_signature).decode()
            )

            # 5. Transmit
            self.log("Transmitting Secure Envelope...", "INFO")
            resp = requests.post(f"{config.server_url}/api/doctor/upload", json=envelope.model_dump())
            resp.raise_for_status()
            
            self.log(f"Upload Successful! ID: {resp.json().get('record_id')}", "SUCCESS")

        except requests.exceptions.HTTPError as e:
             # This will catch the 403 Forbidden if the cert isn't issued yet
             error_detail = e.response.json().get('detail', str(e))
             self.log(f"Upload Rejected: {error_detail}", "ERROR")
        except Exception as e:
            self.log(f"Upload Error: {str(e)}", "ERROR")

    def update_status(self, connected: bool):
        """Uses the status callback to update the UI or terminal."""
        self.is_connected = connected
        if self.status:
            # This triggers set_connection_status in the UI 
            # or print() during enrollment
            self.status(connected)