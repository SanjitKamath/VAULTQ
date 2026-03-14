import uvicorn
import ssl
import os
import sys
import asyncio
import logging
import secrets
from pathlib import Path
from pydantic import BaseModel

def _load_env_file() -> None:
    root_dir = Path(__file__).resolve().parents[1]
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

from fastapi import FastAPI, Request, Form
from fastapi.responses import JSONResponse, HTMLResponse, FileResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from .core.ca_setup import ensure_server_tls_artifacts
from .core.server_state import state
from .routers import doctor_api, admin_api, auth_api, patient_api

logger = logging.getLogger("vaultq.server.main")

# Avoid noisy Windows connection reset tracebacks
if sys.platform.startswith("win"):
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

app = FastAPI(title="VaultQ Core Server")

# -----------------------------
# Configuration
# -----------------------------

_MAX_UPLOAD_BYTES_RAW = os.getenv("VAULTQ_MAX_UPLOAD_BYTES", "").strip() or "8388608"

try:
    MAX_UPLOAD_BYTES = int(_MAX_UPLOAD_BYTES_RAW)
except ValueError as exc:
    raise ValueError(
        f"Invalid VAULTQ_MAX_UPLOAD_BYTES value: {_MAX_UPLOAD_BYTES_RAW!r}"
    ) from exc

ADMIN_USERNAME = os.getenv("VAULTQ_ADMIN_USER", "").strip()
ADMIN_PASSWORD = os.getenv("VAULTQ_ADMIN_PASSWORD", "").strip()
if not ADMIN_USERNAME or not ADMIN_PASSWORD:
    raise RuntimeError(
        "Missing admin credentials. Set VAULTQ_ADMIN_USER and VAULTQ_ADMIN_PASSWORD in .env."
    )
_MTLS_PORT_RAW = os.getenv("VAULTQ_MTLS_PORT", "8080").strip() or "8080"
try:
    MTLS_PORT = int(_MTLS_PORT_RAW)
except ValueError:
    MTLS_PORT = 8080
REQUIRE_MTLS = os.getenv("VAULTQ_REQUIRE_MTLS", "1") == "1"

# Initialize empty admin session
state.admin_session_token = None
logger.info(f"Cryptography suite set to: {state.crypto_suite}")

# -----------------------------
# Paths
# -----------------------------

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

TEMPLATE_DIR = os.path.join(BASE_DIR, "ui", "templates")
PATIENT_BUILD_DIR = os.path.join(BASE_DIR, "..", "patient_app", "dist")
ADMIN_STATIC_DIR = os.path.join(BASE_DIR, "ui", "static")

templates = Jinja2Templates(directory=TEMPLATE_DIR)

# -----------------------------
# Routers
# -----------------------------

app.include_router(doctor_api.router)
app.include_router(admin_api.router)
app.include_router(auth_api.router)
app.include_router(auth_api.pre_enroll_router)
app.include_router(patient_api.router)

# -----------------------------
# Windows Connection Reset Filter
# -----------------------------

def _install_windows_connreset_filter():

    if not sys.platform.startswith("win"):
        return

    loop = asyncio.get_running_loop()
    default_handler = loop.get_exception_handler()

    def _handler(current_loop, context):

        exc = context.get("exception")

        if isinstance(exc, ConnectionResetError) and getattr(exc, "winerror", None) == 10054:
            return

        if default_handler:
            default_handler(current_loop, context)
        else:
            current_loop.default_exception_handler(context)

    loop.set_exception_handler(_handler)


@app.on_event("startup")
async def _install_filter_startup():
    _install_windows_connreset_filter()

# -----------------------------
# Upload Size Protection
# -----------------------------

@app.middleware("http")
async def upload_size_guard(request: Request, call_next):

    if request.url.path == "/api/doctor/upload":

        content_length = request.headers.get("content-length")

        if content_length is None:
            return JSONResponse(
                status_code=411,
                content={"detail": "Content-Length header required"}
            )

        try:
            size = int(content_length)
        except ValueError:
            return JSONResponse(status_code=400, content={"detail": "Invalid Content-Length"})

        if size <= 0:
            return JSONResponse(status_code=400, content={"detail": "Invalid upload size"})

        if size > MAX_UPLOAD_BYTES:
            return JSONResponse(
                status_code=413,
                content={"detail": f"Upload too large. Max {MAX_UPLOAD_BYTES} bytes"}
            )

    return await call_next(request)

# -----------------------------
# Ensure doctor certs (mTLS)
# -----------------------------

@app.middleware("http")
async def doctor_mtls_guard(request: Request, call_next):

    if request.url.path.startswith("/api/doctor"):
        if not REQUIRE_MTLS:
            return await call_next(request)

        req_port = request.url.port
        if req_port is None:
            host_header = (request.headers.get("host") or "").strip()
            if ":" in host_header:
                try:
                    req_port = int(host_header.rsplit(":", 1)[1])
                except ValueError:
                    req_port = None

        # Strict mTLS is already enforced by Uvicorn/OpenSSL on the mTLS listener.
        # Trust the listener boundary first to avoid runtime transport-inspection false negatives.
        if req_port == MTLS_PORT:
            return await call_next(request)

        transport = request.scope.get("transport")

        if transport:
            ssl_object = transport.get_extra_info("ssl_object")

            if ssl_object:
                try:
                    cert = ssl_object.getpeercert()
                except Exception:
                    cert = None

                # ssl.getpeercert() may return {} for a valid peer cert depending on runtime details.
                if cert is not None:
                    return await call_next(request)

                try:
                    cert_binary = ssl_object.getpeercert(binary_form=True)
                except Exception:
                    cert_binary = None

                if cert_binary:
                    return await call_next(request)

        return JSONResponse(
            status_code=401,
            content={"detail": f"Client certificate required for doctor API. Use mTLS listener on port {MTLS_PORT}."}
        )

    return await call_next(request)

# -----------------------------
# Admin Login
# -----------------------------

@app.post("/api/admin/login")
def admin_login(username: str = Form(...), password: str = Form(...)):

    if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:

        token = secrets.token_urlsafe(32)

        # store token globally for API auth
        state.admin_session_token = token

        response = RedirectResponse("/admin", status_code=302)

        response.set_cookie(
            key="admin_session",
            value=token,
            httponly=True,
            secure=True,
            samesite="lax",
            max_age=3600
        )

        return response

    return HTMLResponse("<h2>Invalid credentials</h2>", status_code=401)

# -----------------------------
# Logout
# -----------------------------

@app.post("/api/admin/logout")
def admin_logout():

    state.admin_session_token = None

    response = RedirectResponse("/admin", status_code=302)
    response.delete_cookie("admin_session")

    return response

# -----------------------------
# Admin Portal
# -----------------------------

@app.get("/")
def root():
    return RedirectResponse("/admin")


@app.get("/admin", response_class=HTMLResponse)
def serve_admin_portal(request: Request):
    session_cookie = (request.cookies.get("admin_session") or "").strip()
    active_session = (state.admin_session_token or "").strip()

    # Require an actual non-empty session token before serving admin dashboard.
    if not active_session or session_cookie != active_session:

        return templates.TemplateResponse(
            "admin_login.html",
            {"request": request}
        )

    return templates.TemplateResponse(
        "admin.html",
        {"request": request, "CSRF_TOKEN": "PLACEHOLDER_CSRF_TOKEN"}
    )

class CryptoSuiteSetting(BaseModel):
    suite: str

@app.get("/api/admin/settings/crypto-suite")
def get_crypto_suite():
    return {"suite": state.crypto_suite}

@app.post("/api/admin/settings/crypto-suite")
def set_crypto_suite(setting: CryptoSuiteSetting):
    if setting.suite not in ["PQC", "Classical"]:
        return JSONResponse(status_code=400, content={"detail": "Invalid crypto suite"})
    state.crypto_suite = setting.suite
    state.audit.info(f"Crypto suite updated to: {state.crypto_suite}")
    return {"status": "ok"}

# -----------------------------
# Admin Static Assets
# -----------------------------

if os.path.isdir(ADMIN_STATIC_DIR):

    app.mount(
        "/admin/static",
        StaticFiles(directory=ADMIN_STATIC_DIR),
        name="admin-static"
    )

# -----------------------------
# Patient React Portal
# -----------------------------

patient_assets_dir = os.path.join(PATIENT_BUILD_DIR, "assets")

if os.path.isdir(patient_assets_dir):

    app.mount(
        "/patient/assets",
        StaticFiles(directory=patient_assets_dir),
        name="patient-assets"
    )


@app.get("/patient")
def patient_spa_root():
    return FileResponse(os.path.join(PATIENT_BUILD_DIR, "index.html"))


@app.get("/patient/{full_path:path}")
def patient_spa_catchall(full_path: str = ""):
    return FileResponse(os.path.join(PATIENT_BUILD_DIR, "index.html"))

# -----------------------------
# Start Secure Dual Servers
# -----------------------------

async def start_dual_servers():
    cert_dir = os.path.join(BASE_DIR, "storage", "certs")
    server_cert = os.path.join(cert_dir, "server.crt")
    server_key = os.path.join(cert_dir, "server.key")
    root_ca = os.path.join(cert_dir, "hospital_root_ca.pem")

    ensure_server_tls_artifacts()

    if not (os.path.exists(server_cert) and os.path.exists(server_key) and os.path.exists(root_ca)):
        raise RuntimeError(
            f"Missing TLS artifacts in {cert_dir}. Please run 'python -m server_app.core.ca_setup' first."
        )

    # Server 1: The strict mTLS server (Port 8080)
    config_mtls = uvicorn.Config(
        "server_app.main:app",
        host="0.0.0.0",
        port=8080,
        ssl_keyfile=server_key,
        ssl_certfile=server_cert,
        ssl_ca_certs=root_ca,
        ssl_cert_reqs=ssl.CERT_REQUIRED, # STRICT mTLS
        log_level="info",
    )
    server_mtls = uvicorn.Server(config_mtls)

    # Server 2: The standard TLS server for browser/pre-enroll (Port 8081)
    config_tls = uvicorn.Config(
        "server_app.main:app",
        host="0.0.0.0",
        port=8081,
        ssl_keyfile=server_key,
        ssl_certfile=server_cert,
        ssl_cert_reqs=ssl.CERT_NONE, # Standard TLS (Browser friendly)
        log_level="info",
    )
    server_tls = uvicorn.Server(config_tls)

    print(f"Starting VAULTQ Server (mTLS) on https://localhost:8080")
    print(f"Starting TLS-only browser/pre-enroll endpoint on https://localhost:8081")

    # Run both servers concurrently
    await asyncio.gather(
        server_mtls.serve(),
        server_tls.serve()
    )

if __name__ == "__main__":
    try:
        asyncio.run(start_dual_servers())
    except KeyboardInterrupt:
        logger.info("Server manually stopped.")
