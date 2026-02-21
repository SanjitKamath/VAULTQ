import os
import secrets
from fastapi import Cookie, Header, HTTPException


def require_admin_token(
    x_admin_token: str = Header(default=""),
    vaultq_admin_session: str = Cookie(default=""),
) -> None:
    expected = os.getenv("VAULTQ_ADMIN_TOKEN", "").strip()
    if not expected:
        raise HTTPException(status_code=503, detail="Admin API is not configured.")
    presented = (x_admin_token or vaultq_admin_session or "").strip()
    if not presented or not secrets.compare_digest(presented, expected):
        raise HTTPException(status_code=401, detail="Unauthorized admin request.")
