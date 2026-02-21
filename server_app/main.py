import uvicorn
import ssl
import os
from fastapi import FastAPI
from fastapi.responses import HTMLResponse

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
    """Starts the Uvicorn server with Mutual TLS (mTLS) enforced."""
    cert_dir = os.path.join(BASE_DIR, "storage", "certs")
    server_cert = os.path.join(cert_dir, "server.crt")
    server_key = os.path.join(cert_dir, "server.key")
    root_ca = os.path.join(cert_dir, "hospital_root_ca.pem")

    if os.path.exists(server_cert) and os.path.exists(server_key) and os.path.exists(root_ca):
        uvicorn.run(
            app,
            host="0.0.0.0",
            port=8443,
            ssl_certfile=server_cert,
            ssl_keyfile=server_key,
            ssl_ca_certs=root_ca,
            ssl_cert_reqs=ssl.CERT_REQUIRED,
        )
        return

    if os.getenv("VAULTQ_ALLOW_INSECURE_DEV", "0") == "1":
        uvicorn.run(app, host="0.0.0.0", port=8080)
        return

    raise RuntimeError(
        "TLS artifacts missing. Expected server.crt/server.key/hospital_root_ca.pem in server_app/storage/certs. "
        "Set VAULTQ_ALLOW_INSECURE_DEV=1 only for local development."
    )

if __name__ == "__main__":
    start_secure_server()
