import os
import json
import base64
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from .audit_logger import get_audit_logger


def _print_crypto_data(label: str, data: bytes):
    if os.getenv("VAULTQ_DEBUG_CRYPTO", "0") != "1":
        return
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
    def __init__(self, storage_dir=None):
        if storage_dir is None:
            storage_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "storage", "keystore")
        self.storage_dir = storage_dir
        os.makedirs(self.storage_dir, exist_ok=True)
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

    def _suite_tag(self, suite: str = None) -> str:
        if suite and "classical" in suite.lower():
            return "classical"
        return "pqc"

    def _vault_path(self, doctor_id: str, suite: str = None) -> str:
        return os.path.join(self.storage_dir, f"{doctor_id}.{self._suite_tag(suite)}.vault")

    def _legacy_vault_path(self, doctor_id: str) -> str:
        return os.path.join(self.storage_dir, f"{doctor_id}.vault")

    def save_identity(self, doctor_id: str, password: str, private_key: bytes, suite: str = None):
        """Encrypts the suite-specific private key and saves it to disk."""
        suite_tag = self._suite_tag(suite)
        self.audit.info("LocalKeyVault save_identity start for doctor_id=%s suite=%s", doctor_id, suite_tag)
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
        
        with open(self._vault_path(doctor_id, suite), "w", encoding="utf-8") as f:
            json.dump(vault_data, f)
        self.audit.info("LocalKeyVault save_identity complete for doctor_id=%s suite=%s", doctor_id, suite_tag)

    def load_identity(self, doctor_id: str, password: str, suite: str = None) -> bytes:
        """Decrypts and returns the suite-specific private key."""
        suite_tag = self._suite_tag(suite)
        self.audit.info("LocalKeyVault load_identity start for doctor_id=%s suite=%s", doctor_id, suite_tag)
        filepath = self._vault_path(doctor_id, suite)
        # Backward compatibility for older unsuffixed PQC vaults.
        if suite_tag == "pqc" and not os.path.exists(filepath):
            legacy_path = self._legacy_vault_path(doctor_id)
            if os.path.exists(legacy_path):
                filepath = legacy_path
        if not os.path.exists(filepath):
            self.audit.info("LocalKeyVault load_identity miss for doctor_id=%s suite=%s (vault not found)", doctor_id, suite_tag)
            return None # Doctor vault does not exist
            
        with open(filepath, "r", encoding="utf-8") as f:
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
            self.audit.info("LocalKeyVault load_identity success for doctor_id=%s suite=%s", doctor_id, suite_tag)
            return decrypted
        except Exception:
            self.audit.warning(
                "LocalKeyVault load_identity failed for doctor_id=%s suite=%s (password mismatch/corruption)",
                doctor_id,
                suite_tag,
            )
            raise ValueError("Invalid password or corrupted vault.")
        
    def change_password(self, doctor_id: str, old_password: str, new_password: str, suite: str = None):
        """Re-encrypts the suite-specific local identity with a new password."""
        suite_tag = self._suite_tag(suite)
        self.audit.info("LocalKeyVault change_password start for doctor_id=%s suite=%s", doctor_id, suite_tag)
        # Step 1: Unlock the current key with the old password
        private_key = self.load_identity(doctor_id, old_password, suite=suite)
        if not private_key:
            self.audit.warning(
                "LocalKeyVault change_password failed: old password check failed for doctor_id=%s suite=%s",
                doctor_id,
                suite_tag,
            )
            raise ValueError("Authentication failed: Old password incorrect.")

        # Step 2: Save it again with the new password (this overwrites the file)
        self.save_identity(doctor_id, new_password, private_key, suite=suite)
        self.audit.info("LocalKeyVault change_password success for doctor_id=%s suite=%s", doctor_id, suite_tag)
        return True

    def delete_identity(self, doctor_id: str, suite: str = None) -> bool:
        """Deletes local encrypted identity for forced re-enrollment."""
        removed = False
        suite_tag = self._suite_tag(suite)

        filepath = self._vault_path(doctor_id, suite)
        if os.path.exists(filepath):
            os.remove(filepath)
            removed = True

        # Also clear legacy unsuffixed PQC vaults when deleting PQC identity.
        if suite_tag == "pqc":
            legacy = self._legacy_vault_path(doctor_id)
            if os.path.exists(legacy):
                os.remove(legacy)
                removed = True

        if removed:
            self.audit.info("LocalKeyVault delete_identity removed vault for doctor_id=%s suite=%s", doctor_id, suite_tag)
        return removed

    def has_identity(self, doctor_id: str, suite: str = None) -> bool:
        """Checks whether a local encrypted identity exists for the selected suite."""
        suite_tag = self._suite_tag(suite)
        if os.path.exists(self._vault_path(doctor_id, suite)):
            return True
        # Backward compatibility for unsuffixed legacy PQC vaults.
        if suite_tag == "pqc" and os.path.exists(self._legacy_vault_path(doctor_id)):
            return True
        return False
