import os
from pathlib import Path

from security_suite.classical import rsa as rsa_classical

from .audit_logger import get_audit_logger


class ServerRSAKeyStore:
    """Persists the server RSA private key for classical envelope processing."""

    def __init__(self, storage_dir: str = None):
        self.audit = get_audit_logger()
        base_dir = Path(__file__).resolve().parents[1]
        self.storage_dir = Path(storage_dir) if storage_dir else base_dir / "storage" / "keys"
        self.key_path = self.storage_dir / "server_classical_rsa_private.pem"
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        self.audit.info("ServerRSAKeyStore initialized at %s", self.key_path)

    def load_or_create(self) -> rsa_classical.RSAManager:
        if self.key_path.exists():
            private_bytes = self.key_path.read_bytes()
            self.audit.info("ServerRSAKeyStore load: existing RSA private key loaded")
            return rsa_classical.RSAManager(private_bytes=private_bytes)

        manager = rsa_classical.RSAManager()
        self.key_path.write_bytes(manager.get_private_bytes())
        try:
            os.chmod(self.key_path, 0o600)
        except OSError:
            pass
        self.audit.info("ServerRSAKeyStore create: new RSA private key generated and persisted")
        return manager
