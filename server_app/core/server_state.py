from security_suite.crypto import ECDHManager, KEMManager, DSAManager
# Import the bootstrapping function we wrote earlier
from .ca_setup import bootstrap_hospital_root_ca
from .master_key_store import MasterKeyStore
from .audit_logger import get_audit_logger

class ServerState:
    def __init__(self):
        self.audit = get_audit_logger()
        self.audit.info("ServerState init: starting security subsystem bootstrap")
        # 1. Hospital Certificate Authority (CA) Identity Key
        self.hospital_ca = DSAManager(private_bytes=None) 
        
        # FIX: We must explicitly generate the ML-DSA keypair 
        self.hospital_ca.generate_keypair() 
        self.audit.info("ServerState init: hospital CA keypair generated")
        
        # 2. Bootstrap the Root CA (Generates the self-signed X.509 cert)
        self.hospital_root_cert = bootstrap_hospital_root_ca(self.hospital_ca)
        self.audit.info("ServerState init: hospital root certificate bootstrapped")

        # 3. Long-term Server Identity Keys for the Handshake
        self.ecdh = ECDHManager()
        self.kem = KEMManager()
        self.audit.info("ServerState init: handshake identities ready (ECDH + PQC KEM)")
        
        # Temporary in-memory session store (Session ID -> Session Key)
        self.active_sessions = {}

        # Server-side at-rest master key (persistent across restarts)
        self.master_kid, self.master_key = MasterKeyStore().load_or_create()
        self.audit.info("ServerState init: at-rest master key loaded (master_kid=%s)", self.master_kid)

# Global Singleton
state = ServerState()
