import os
import json
import base64
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class LocalKeyVault:
    def __init__(self, storage_dir="doctor_app/storage/keystore"):
        self.storage_dir = storage_dir
        os.makedirs(self.storage_dir, exist_ok=True)

    def _derive_key(self, password: str, salt: bytes) -> bytes:
        """Derives a strong AES-256 key from a human password."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=480000, # High iteration count against brute-force attacks
        )
        return kdf.derive(password.encode())

    def save_identity(self, doctor_id: str, password: str, private_key: bytes):
        """Encrypts the ML-DSA private key and saves it to disk."""
        salt = os.urandom(16)
        aes_key = self._derive_key(password, salt)
        aesgcm = AESGCM(aes_key)
        nonce = os.urandom(12)
        
        encrypted_key = aesgcm.encrypt(nonce, private_key, None)

        vault_data = {
            "salt": base64.b64encode(salt).decode('utf-8'),
            "nonce": base64.b64encode(nonce).decode('utf-8'),
            "encrypted_key": base64.b64encode(encrypted_key).decode('utf-8')
        }
        
        with open(os.path.join(self.storage_dir, f"{doctor_id}.vault"), "w") as f:
            json.dump(vault_data, f)

    def load_identity(self, doctor_id: str, password: str) -> bytes:
        """Decrypts and returns the ML-DSA private key."""
        filepath = os.path.join(self.storage_dir, f"{doctor_id}.vault")
        if not os.path.exists(filepath):
            return None # Doctor vault does not exist
            
        with open(filepath, "r") as f:
            vault_data = json.load(f)

        salt = base64.b64decode(vault_data["salt"])
        nonce = base64.b64decode(vault_data["nonce"])
        encrypted_key = base64.b64decode(vault_data["encrypted_key"])

        aes_key = self._derive_key(password, salt)
        aesgcm = AESGCM(aes_key)
        
        try:
            return aesgcm.decrypt(nonce, encrypted_key, None)
        except Exception:
            raise ValueError("Invalid password or corrupted vault.")
        
    def change_password(self, doctor_id: str, old_password: str, new_password: str):
        """Re-encrypts the local PQC identity with a new password."""
        # Step 1: Unlock the current key with the old password
        private_key = self.load_identity(doctor_id, old_password)
        if not private_key:
            raise ValueError("Authentication failed: Old password incorrect.")

        # Step 2: Save it again with the new password (this overwrites the file)
        self.save_identity(doctor_id, new_password, private_key)
        return True