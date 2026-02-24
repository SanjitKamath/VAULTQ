import uvicorn
import ssl
import os
import sys
import asyncio
import threading
import logging
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.responses import HTMLResponse
from .core.ca_setup import ensure_server_tls_artifacts
from .core.admin_auth import validate_admin_session
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

logger = logging.getLogger("vaultq.server.main")

# Avoid noisy Proactor transport shutdown tracebacks on Windows
# when clients disconnect abruptly (WinError 10054).
if sys.platform.startswith("win"):
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

app = FastAPI(title="VaultQ Core Server")
_MAX_UPLOAD_BYTES_RAW = os.getenv("VAULTQ_MAX_UPLOAD_BYTES", "").strip()
if not _MAX_UPLOAD_BYTES_RAW:
    _MAX_UPLOAD_BYTES_RAW = "8388608"  # 8 MiB default
try:
    MAX_UPLOAD_BYTES = int(_MAX_UPLOAD_BYTES_RAW)
except ValueError as exc:
    raise ValueError(
        f"Invalid VAULTQ_MAX_UPLOAD_BYTES value: {_MAX_UPLOAD_BYTES_RAW!r}. Expected a numeric byte limit."
    ) from exc
# Hardened behavior: always enforce mTLS on the main API listener.
REQUIRE_MTLS = True
_PRE_ENROLL_PORT_RAW = os.getenv("VAULTQ_PRE_ENROLL_PORT", "").strip()
if not _PRE_ENROLL_PORT_RAW:
    _PRE_ENROLL_PORT_RAW = "8081"
try:
    PRE_ENROLL_PORT = int(_PRE_ENROLL_PORT_RAW)
except ValueError as exc:
    raise ValueError(
        f"Invalid VAULTQ_PRE_ENROLL_PORT value: {_PRE_ENROLL_PORT_RAW!r}. Expected a numeric TCP port."
    ) from exc
if not (1 <= PRE_ENROLL_PORT <= 65535):
    raise ValueError(
        f"VAULTQ_PRE_ENROLL_PORT={PRE_ENROLL_PORT} is out of valid TCP port range (1-65535)."
    )

# Define directories
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEMPLATE_DIR = os.path.join(BASE_DIR, "ui", "templates")
PATIENT_BUILD_DIR = os.path.join(BASE_DIR, "..", "patient_app", "dist")
ADMIN_STATIC_DIR = os.path.join(BASE_DIR, "ui", "static")

# Include API routers (handshake_api is removed since TLS handles it)
from .routers import doctor_api, admin_api, auth_api, patient_api
app.include_router(doctor_api.router)
app.include_router(admin_api.router)
app.include_router(auth_api.router)
app.include_router(patient_api.router)

# Separate TLS-only endpoint set for pre-enrollment before doctor cert issuance.
pre_enroll_app = FastAPI(title="VaultQ Pre-Enrollment Server")
pre_enroll_app.include_router(auth_api.pre_enroll_router)
# Browser-admin flows on TLS-only listener (token+CSRF protected, no mTLS client cert).
pre_enroll_app.include_router(admin_api.router)
pre_enroll_app.include_router(auth_api.router)
pre_enroll_app.include_router(patient_api.router)


def _install_windows_connreset_filter():
    """
    Suppress noisy WinError 10054 callback traces on Windows when clients
    disconnect abruptly (browser tab close/reload, keepalive teardown).
    """
    if not sys.platform.startswith("win"):
        return
    loop = asyncio.get_running_loop()
    default_handler = loop.get_exception_handler()

    def _handler(current_loop, context):
        exc = context.get("exception")
        if isinstance(exc, ConnectionResetError) and getattr(exc, "winerror", None) == 10054:
            return
        if default_handler is not None:
            default_handler(current_loop, context)
        else:
            current_loop.default_exception_handler(context)

    loop.set_exception_handler(_handler)


@app.on_event("startup")
async def _install_windows_connreset_filter_main():
    _install_windows_connreset_filter()


@pre_enroll_app.on_event("startup")
async def _install_windows_connreset_filter_pre_enroll():
    _install_windows_connreset_filter()


@app.middleware("http")
async def upload_size_guard(request: Request, call_next):
    """
    Reject oversized doctor uploads before request body parsing/validation.
    This prevents large-body JSON allocation attacks at the API layer.
    """
    if request.url.path == "/api/doctor/upload":
        content_length = request.headers.get("content-length")
        if content_length is None:
            return JSONResponse(status_code=411, content={"detail": "Content-Length header required for upload."})

        try:
            content_length_val = int(content_length)
        except ValueError:
            return JSONResponse(status_code=400, content={"detail": "Invalid Content-Length header."})

        if content_length_val <= 0:
            return JSONResponse(status_code=400, content={"detail": "Invalid upload size."})

        if content_length_val > MAX_UPLOAD_BYTES:
            return JSONResponse(
                status_code=413,
                content={"detail": f"Upload too large. Max {MAX_UPLOAD_BYTES} bytes."},
            )

    return await call_next(request)

# Restored: Admin Dashboard UI Route
def _render_admin_html(csrf_token: str):
    try:
        with open(os.path.join(TEMPLATE_DIR, "admin.html"), "r", encoding="utf-8") as f:
            html = f.read()
        return html.replace("{{CSRF_TOKEN}}", csrf_token)
    except (FileNotFoundError, OSError) as exc:
        logger.exception("Failed to render admin dashboard template: %s", exc)
        return HTMLResponse(
            content="Internal Server Error: admin dashboard template unavailable.",
            status_code=500,
        )


@app.get("/admin", response_class=HTMLResponse)
def admin_dashboard(request: Request):
    csrf_token = ""
    session_id = (request.cookies.get("vaultq_admin_session", "") or "").strip()
    if session_id:
        session_data = validate_admin_session(session_id)
        if session_data:
            _, csrf_token = session_data

    return _render_admin_html(csrf_token)


@pre_enroll_app.get("/admin", response_class=HTMLResponse)
def admin_dashboard_tls_only(request: Request):
    csrf_token = ""
    session_id = (request.cookies.get("vaultq_admin_session", "") or "").strip()
    if session_id:
        session_data = validate_admin_session(session_id)
        if session_data:
            _, csrf_token = session_data

    return _render_admin_html(csrf_token)

# Admin static assets (local bundled CSS/JS for dashboard hardening).
if os.path.isdir(ADMIN_STATIC_DIR):
    app.mount("/admin/static", StaticFiles(directory=ADMIN_STATIC_DIR), name="admin-static")
    pre_enroll_app.mount("/admin/static", StaticFiles(directory=ADMIN_STATIC_DIR), name="admin-static-pre")

# Patient Portal: serve React build (static assets + SPA catch-all)
_patient_assets_dir = os.path.join(PATIENT_BUILD_DIR, "assets")
if os.path.isdir(_patient_assets_dir):
    app.mount("/patient/assets", StaticFiles(directory=_patient_assets_dir), name="patient-assets")
    pre_enroll_app.mount("/patient/assets", StaticFiles(directory=_patient_assets_dir), name="patient-assets-pre")

@app.get("/patient")
def patient_spa_root():
    return FileResponse(os.path.join(PATIENT_BUILD_DIR, "index.html"))

@pre_enroll_app.get("/patient")
def patient_spa_root_tls_only():
    return FileResponse(os.path.join(PATIENT_BUILD_DIR, "index.html"))

@app.get("/patient/{full_path:path}")
def patient_spa_catchall(full_path: str = ""):
    return FileResponse(os.path.join(PATIENT_BUILD_DIR, "index.html"))

@pre_enroll_app.get("/patient/{full_path:path}")
def patient_spa_catchall_tls_only(full_path: str = ""):
    return FileResponse(os.path.join(PATIENT_BUILD_DIR, "index.html"))

def start_secure_server():
    """Starts strict mTLS API on 8080 and TLS-only pre-enrollment API on PRE_ENROLL_PORT."""
    cert_dir = os.path.join(BASE_DIR, "storage", "certs")
    server_cert = os.path.join(cert_dir, "server.crt")
    server_key = os.path.join(cert_dir, "server.key")
    root_ca = os.path.join(cert_dir, "hospital_root_ca.pem")
    port = 8080

    # Auto-provision server cert/key from existing hospital root CA if missing.
    generated = ensure_server_tls_artifacts()

    if not (generated and os.path.exists(server_cert) and os.path.exists(server_key) and os.path.exists(root_ca)):
        raise RuntimeError(
            "TLS artifacts unavailable. Expected/auto-generated server.crt/server.key plus hospital_root_ca.pem in "
            "server_app/storage/certs."
        )

    print("Starting VAULTQ Server (mTLS) on https://localhost:8080")

    _pre_enroll_error: list[BaseException] = []

    def _start_pre_enroll_server():
        try:
            uvicorn.run(
                pre_enroll_app,
                host="0.0.0.0",
                port=PRE_ENROLL_PORT,
                ssl_certfile=server_cert,
                ssl_keyfile=server_key,
                ssl_ca_certs=root_ca,
                ssl_cert_reqs=ssl.CERT_NONE,
            )
        except Exception as exc:
            _pre_enroll_error.append(exc)

    _pre_enroll_thread = threading.Thread(target=_start_pre_enroll_server, daemon=True)
    _pre_enroll_thread.start()
    _pre_enroll_thread.join(timeout=2)  # brief grace period for early bind failures
    if _pre_enroll_error:
        raise RuntimeError(
            f"Pre-enrollment server failed to start on port {PRE_ENROLL_PORT}: {_pre_enroll_error[0]}"
        ) from _pre_enroll_error[0]    
    print(
        f"Starting TLS-only browser/pre-enroll endpoint on "
        f"https://localhost:{PRE_ENROLL_PORT} (admin: /admin, pre-enroll: /api/pre-enroll)"
    )

    uvicorn.run(
        app,
        host="0.0.0.0",
        port=port,
        ssl_certfile=server_cert,
        ssl_keyfile=server_key,
        ssl_ca_certs=root_ca,
        ssl_cert_reqs=ssl.CERT_REQUIRED if REQUIRE_MTLS else ssl.CERT_NONE,
    )

    

if __name__ == "__main__":
    start_secure_server()
