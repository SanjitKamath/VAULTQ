import uvicorn
import ssl
import os
from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from .core.ca_setup import ensure_server_tls_artifacts

app = FastAPI(title="VaultQ Core Server")

# Define template directory for the admin dashboard
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEMPLATE_DIR = os.path.join(BASE_DIR, "ui", "templates")

# Include API routers (handshake_api is removed since TLS handles it)
from .routers import doctor_api, admin_api, auth_api
app.include_router(doctor_api.router)
app.include_router(admin_api.router)
app.include_router(auth_api.router)

# Restored: Admin Dashboard UI Route
@app.get("/admin", response_class=HTMLResponse)
def admin_dashboard():
    with open(os.path.join(TEMPLATE_DIR, "admin.html"), "r") as f:
        return f.read()

def start_secure_server():
    """Starts the Uvicorn server with TLS enforced on port 8080."""
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
        ssl_cert_reqs=ssl.CERT_REQUIRED,
    )

if __name__ == "__main__":
    start_secure_server()
