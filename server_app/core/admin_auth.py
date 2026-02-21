import os
import secrets
from fastapi import Header, HTTPException


def require_admin_token(x_admin_token: str = Header(default="")) -> None:
    expected = os.getenv("VAULTQ_ADMIN_TOKEN", "").strip()
    if not expected:
        raise HTTPException(status_code=503, detail="Admin API is not configured.")
    if not x_admin_token or not secrets.compare_digest(x_admin_token, expected):
        raise HTTPException(status_code=401, detail="Unauthorized admin request.")
