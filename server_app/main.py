import uvicorn
import ssl
import os
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.responses import HTMLResponse
from .core.ca_setup import ensure_server_tls_artifacts

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
REQUIRE_MTLS = os.getenv("VAULTQ_REQUIRE_MTLS", "0") == "1"

# Define template directory for the admin dashboard
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEMPLATE_DIR = os.path.join(BASE_DIR, "ui", "templates")

# Include API routers (handshake_api is removed since TLS handles it)
from .routers import doctor_api, admin_api, auth_api
app.include_router(doctor_api.router)
app.include_router(admin_api.router)
app.include_router(auth_api.router)


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
@app.get("/admin", response_class=HTMLResponse)
def admin_dashboard():
    with open(os.path.join(TEMPLATE_DIR, "admin.html"), "r") as f:
        return f.read()

def start_secure_server():
    """Starts the Uvicorn server with TLS on port 8080, optional mTLS via env flag."""
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
