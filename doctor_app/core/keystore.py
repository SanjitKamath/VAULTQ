import os
import json
import base64
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from .audit_logger import get_audit_logger


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


class LocalKeyVault:
    def __init__(self, storage_dir="doctor_app/storage/keystore"):
        self.storage_dir = storage_dir
        os.makedirs(self.storage_dir, mode=0o700, exist_ok=True)
        self.audit = get_audit_logger()
        self.audit.info("LocalKeyVault initialized at %s", self.storage_dir)

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
        self.audit.info("LocalKeyVault save_identity start for doctor_id=%s", doctor_id)
        _print_crypto_data("Local vault plaintext private key (before encryption)", private_key)
        salt = os.urandom(16)
        aes_key = self._derive_key(password, salt)
        aesgcm = AESGCM(aes_key)
        nonce = os.urandom(12)
        
        encrypted_key = aesgcm.encrypt(nonce, private_key, None)
        _print_crypto_data("Local vault ciphertext private key (after encryption)", encrypted_key)

        vault_data = {
            "salt": base64.b64encode(salt).decode('utf-8'),
            "nonce": base64.b64encode(nonce).decode('utf-8'),
            "encrypted_key": base64.b64encode(encrypted_key).decode('utf-8')
        }
        
        with open(os.path.join(self.storage_dir, f"{doctor_id}.vault"), "w") as f:
            json.dump(vault_data, f)
        self.audit.info("LocalKeyVault save_identity complete for doctor_id=%s", doctor_id)

    def load_identity(self, doctor_id: str, password: str) -> bytes:
        """Decrypts and returns the ML-DSA private key."""
        self.audit.info("LocalKeyVault load_identity start for doctor_id=%s", doctor_id)
        filepath = os.path.join(self.storage_dir, f"{doctor_id}.vault")
        if not os.path.exists(filepath):
            self.audit.info("LocalKeyVault load_identity miss for doctor_id=%s (vault not found)", doctor_id)
            return None # Doctor vault does not exist
            
        with open(filepath, "r") as f:
            vault_data = json.load(f)

        salt = base64.b64decode(vault_data["salt"])
        nonce = base64.b64decode(vault_data["nonce"])
        encrypted_key = base64.b64decode(vault_data["encrypted_key"])

        aes_key = self._derive_key(password, salt)
        aesgcm = AESGCM(aes_key)
        
        try:
            _print_crypto_data("Local vault ciphertext private key (before decryption)", encrypted_key)
            decrypted = aesgcm.decrypt(nonce, encrypted_key, None)
            _print_crypto_data("Local vault plaintext private key (after decryption)", decrypted)
            self.audit.info("LocalKeyVault load_identity success for doctor_id=%s", doctor_id)
            return decrypted
        except Exception:
            self.audit.warning("LocalKeyVault load_identity failed for doctor_id=%s (password mismatch/corruption)", doctor_id)
            raise ValueError("Invalid password or corrupted vault.")
        
    def change_password(self, doctor_id: str, old_password: str, new_password: str):
        """Re-encrypts the local PQC identity with a new password."""
        self.audit.info("LocalKeyVault change_password start for doctor_id=%s", doctor_id)
        # Step 1: Unlock the current key with the old password
        private_key = self.load_identity(doctor_id, old_password)
        if not private_key:
            self.audit.warning("LocalKeyVault change_password failed: old password check failed for doctor_id=%s", doctor_id)
            raise ValueError("Authentication failed: Old password incorrect.")

        # Step 2: Save it again with the new password (this overwrites the file)
        self.save_identity(doctor_id, new_password, private_key)
        self.audit.info("LocalKeyVault change_password success for doctor_id=%s", doctor_id)
        return True

    def delete_identity(self, doctor_id: str) -> bool:
        """Deletes local encrypted identity for forced re-enrollment."""
        filepath = os.path.join(self.storage_dir, f"{doctor_id}.vault")
        if not os.path.exists(filepath):
            return False
        os.remove(filepath)
        self.audit.info("LocalKeyVault delete_identity removed vault for doctor_id=%s", doctor_id)
        return True
