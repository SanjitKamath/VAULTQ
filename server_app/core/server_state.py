from security_suite.crypto import ECDHManager, KEMManager, DSAManager
# Import the bootstrapping function we wrote earlier
from .ca_setup import bootstrap_hospital_root_ca

class ServerState:
    def __init__(self):
        # 1. Hospital Certificate Authority (CA) Identity Key
        self.hospital_ca = DSAManager(private_bytes=None) 
        
        # FIX: We must explicitly generate the ML-DSA keypair 
        self.hospital_ca.generate_keypair() 
        
        # 2. Bootstrap the Root CA (Generates the self-signed X.509 cert)
        self.hospital_root_cert = bootstrap_hospital_root_ca(self.hospital_ca)

        # 3. Long-term Server Identity Keys for the Handshake
        self.ecdh = ECDHManager()
        self.kem = KEMManager()
        
        # Temporary in-memory session store (Session ID -> Session Key)
        self.active_sessions = {}

# Global Singleton
state = ServerState()