from fastapi import FastAPI
from fastapi.responses import HTMLResponse
import os
from .core.audit_logger import get_audit_logger

# 1. Import the missing admin_api
from .routers import handshake_api, doctor_api, admin_api, auth_api

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEMPLATE_DIR = os.path.join(BASE_DIR, "ui", "templates")

app = FastAPI(title="VaultQ Core Server")
audit = get_audit_logger()
audit.info("Server bootstrap: FastAPI app initialized")

# 2. Include all three routers
app.include_router(handshake_api.router)
app.include_router(doctor_api.router)
app.include_router(admin_api.router) 
app.include_router(auth_api.router)
audit.info("Server bootstrap: routers registered (handshake, doctor, admin, auth)")

@app.get("/admin", response_class=HTMLResponse)
def admin_dashboard():
    with open(os.path.join(TEMPLATE_DIR, "admin.html"), "r") as f:
        return f.read()
    

    
"""
To run independantly for testing, use:
$env:PYTHONPATH = "$PWD"; uvicorn server_app.main:app --host 127.0.0.1 --port 8080
"""
