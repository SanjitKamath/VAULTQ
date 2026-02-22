import os
from pathlib import Path

from pydantic import BaseModel, Field


def _load_env_file() -> None:
    root_dir = Path(__file__).resolve().parents[2]
    env_path = root_dir / ".env"
    if not env_path.exists():
        return

    for raw_line in env_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


_load_env_file()
_ROOT = Path(__file__).resolve().parents[2]
_KEYS_DIR = _ROOT / "doctor_app" / "storage" / "keys"
_DEFAULT_SERVER_URL = "https://127.0.0.1:8080"


class AppConfig(BaseModel):
    server_url: str = Field(default=os.getenv("VAULTQ_SERVER_URL", _DEFAULT_SERVER_URL))
    ca_cert_path: str = Field(
        default=os.getenv("VAULTQ_DOCTOR_CA_CERT_PATH", str(_KEYS_DIR / "hospital_root_ca.pem"))
    )
    keys_dir: str = Field(default=str(_KEYS_DIR))
    window_title: str = Field(default="VaultQ | Doctor Security Terminal")
    window_size: str = Field(default="1000x700")
    doctor_name: str = Field(default="Dr. Sanjit Kamath")
    doctor_kid: str = Field(default="kid_vaultq_001")  # In prod, loaded from X.509 cert


config = AppConfig()
