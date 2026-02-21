import base64
import hashlib

import bcrypt

SCHEME_PREFIX = "bcrypt_sha256$"


def _normalize_secret(password: str) -> bytes:
    # Normalize to a fixed-size digest so we avoid bcrypt's 72-byte input limit.
    digest = hashlib.sha256(password.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=")


def hash_password(password: str) -> str:
    """Hashes a plaintext password using sha256+bcrypt."""
    normalized = _normalize_secret(password)
    hashed = bcrypt.hashpw(normalized, bcrypt.gensalt())
    return SCHEME_PREFIX + hashed.decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verifies password against modern and legacy formats."""
    if not hashed_password:
        return False

    candidate = (plain_password or "").encode("utf-8")

    try:
        if hashed_password.startswith(SCHEME_PREFIX):
            normalized = _normalize_secret(plain_password or "")
            return bcrypt.checkpw(normalized, hashed_password[len(SCHEME_PREFIX) :].encode("utf-8"))

        # Backward compatibility for legacy raw bcrypt hashes
        if hashed_password.startswith("$2a$") or hashed_password.startswith("$2b$") or hashed_password.startswith("$2y$"):
            return bcrypt.checkpw(candidate, hashed_password.encode("utf-8"))
    except Exception:
        pass

    # Backward compatibility for old plaintext records during migration.
    return (plain_password or "") == hashed_password
