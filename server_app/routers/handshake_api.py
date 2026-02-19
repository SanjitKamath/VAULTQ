import base64
import traceback # Add this import
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
from ..core.server_state import state
from security_suite.crypto import HybridSessionManager

router = APIRouter(prefix="/handshake", tags=["Security"])

class ClientExchange(BaseModel):
    pqc_ct: str = Field(...)
    ecdh_pub: str = Field(...)

@router.get("/init")
def server_hello():
    return {
        "ecdh_pub": base64.b64encode(state.ecdh.get_public_bytes()).decode(),
        "pqc_pub": base64.b64encode(state.kem.get_public_bytes()).decode()
    }

@router.post("/complete")
def server_exchange(data: ClientExchange):
    try:
        # 1. PQC Decapsulation
        ct_bytes = base64.b64decode(data.pqc_ct)
        ss_pqc = state.kem.decapsulate(ct_bytes, state.kem.get_private_bytes())

        # 2. ECDH Shared Secret
        client_ecdh_bytes = base64.b64decode(data.ecdh_pub)
        ss_ecdh = state.ecdh.compute_shared_secret(client_ecdh_bytes)

        # 3. Hybrid Key Derivation
        session_key = HybridSessionManager.derive_final_session_key(ss_pqc, ss_ecdh)
        
        session_id = HybridSessionManager.generate_session_proof(session_key)
        state.active_sessions[session_id] = session_key

        return {"server_proof": session_id}
    except Exception as e:
        # PRINT THE EXACT CAUSE TO THE SERVER TERMINAL
        print("\n" + "="*50)
        print("CRITICAL HANDSHAKE ERROR:")
        traceback.print_exc()
        print("="*50 + "\n")
        raise HTTPException(status_code=400, detail=f"Handshake failed: {str(e)}")