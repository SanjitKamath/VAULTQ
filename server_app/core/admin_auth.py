import os
import secrets
import time
from typing import Dict, Tuple
from fastapi import Cookie, Header, HTTPException, Request


_ADMIN_SESSION_STORE: Dict[str, Tuple[str, float, str]] = {}


def create_admin_session(admin_token: str, ttl_seconds: int) -> Tuple[str, str]:
    session_id = secrets.token_urlsafe(32)
    csrf_token = secrets.token_urlsafe(32)
    expires_at = time.time() + max(1, int(ttl_seconds))
    _ADMIN_SESSION_STORE[session_id] = (admin_token, expires_at, csrf_token)
    return session_id, csrf_token


def validate_admin_session(session_id: str) -> Tuple[str, str] | None:
    record = _ADMIN_SESSION_STORE.get(session_id)
    if not record:
        return None
    admin_token, expires_at, csrf_token = record
    if expires_at < time.time():
        _ADMIN_SESSION_STORE.pop(session_id, None)
        return None
    return admin_token, csrf_token


def revoke_admin_session(session_id: str) -> None:
    _ADMIN_SESSION_STORE.pop(session_id, None)


def require_admin_token(
    request: Request,
    x_admin_token: str = Header(default=""),
    x_csrf_token: str = Header(default=""),
    vaultq_admin_session: str = Cookie(default=""),
) -> None:
    expected = os.getenv("VAULTQ_ADMIN_TOKEN", "").strip()
    if not expected:
        raise HTTPException(status_code=503, detail="Admin API is not configured.")

    if x_admin_token and secrets.compare_digest(x_admin_token.strip(), expected):
        return

    session_id = (vaultq_admin_session or "").strip()
    if session_id:
        session_data = validate_admin_session(session_id)
        if not session_data:
            raise HTTPException(status_code=401, detail="Unauthorized admin request.")
        session_token, session_csrf = session_data
        if not secrets.compare_digest(session_token, expected):
            raise HTTPException(status_code=401, detail="Unauthorized admin request.")

        if request.method.upper() not in {"GET", "HEAD", "OPTIONS"}:
            presented_csrf = (x_csrf_token or "").strip()
            if not presented_csrf or not secrets.compare_digest(presented_csrf, session_csrf):
                raise HTTPException(status_code=401, detail="Unauthorized admin request.")
        return

    presented = (x_admin_token or "").strip()
    if not presented or not secrets.compare_digest(presented, expected):
        raise HTTPException(status_code=401, detail="Unauthorized admin request.")
