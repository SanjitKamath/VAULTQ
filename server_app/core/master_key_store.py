import base64
import json
import os
import secrets
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from .audit_logger import get_audit_logger


class MasterKeyStore:
    """
    Persists a single AES-256 master key for server-side at-rest encryption.
    """
    def __init__(self, storage_dir: str = None):
        self.audit = get_audit_logger()
        base_dir = os.path.dirname(os.path.dirname(__file__))
        self.storage_dir = storage_dir or os.path.join(base_dir, "storage", "keys")
        self.key_path = os.path.join(self.storage_dir, "master_key.json")
        os.makedirs(self.storage_dir, mode=0o700, exist_ok=True)
        self.audit.info("MasterKeyStore initialized at %s", self.key_path)

    def load_or_create(self) -> tuple[str, bytes]:
        if os.path.exists(self.key_path):
            with open(self.key_path, "r") as f:
                data = json.load(f)
            self.audit.info("MasterKeyStore load: existing master key loaded (master_kid=%s)", data["master_kid"])
            return data["master_kid"], base64.b64decode(data["master_key_b64"])

        master_key = AESGCM.generate_key(bit_length=256)
        master_kid = f"mk_{secrets.token_hex(8)}"
        record = {
            "master_kid": master_kid,
            "master_key_b64": base64.b64encode(master_key).decode(),
        }
        with open(self.key_path, "w") as f:
            json.dump(record, f, indent=4)
        self.audit.info("MasterKeyStore create: new master key generated (master_kid=%s)", master_kid)
        return master_kid, master_key
