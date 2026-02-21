import threading
import time
import heapq
from security_suite.crypto import ECDHManager, KEMManager
# Import the bootstrapping function we wrote earlier
from .ca_setup import bootstrap_hospital_root_ca
from .master_key_store import MasterKeyStore
from .audit_logger import get_audit_logger

class ServerState:
    def __init__(self):
        self.audit = get_audit_logger()
        self.audit.info("ServerState init: starting security subsystem bootstrap")

        # 1. Bootstrap/load Root CA certificate (public material only in long-lived state)
        self.hospital_root_cert = bootstrap_hospital_root_ca()
        self.audit.info("ServerState init: hospital root certificate bootstrapped")

        # 2. Long-term Server Identity Keys for the Handshake
        self.ecdh = ECDHManager()
        self.kem = KEMManager()
        self.audit.info("ServerState init: handshake identities ready (ECDH + PQC KEM)")
        
        # Temporary in-memory session store (Session ID -> Session Key)
        self.active_sessions = {}
        
        # Replay cache (message-id -> first_seen_epoch), bounded by TTL cleanup.
        self.replay_cache = {}
        self.replay_expiry_heap = []  # (expires_at_epoch, message_id)
        self._replay_lock = threading.Lock()

        # Server-side at-rest master key (persistent across restarts)
        self.master_kid, self.master_key = MasterKeyStore().load_or_create()
        self.audit.info("ServerState init: at-rest master key loaded (master_kid=%s)", self.master_kid)

    def replay_seen_or_store(self, message_id: str, ttl_seconds: int) -> bool:
        """
        Returns True if the message_id is a replay; otherwise stores it and returns False.
        """
        now = int(time.time())
        expires_at = now + ttl_seconds
        with self._replay_lock:
            # Incremental expiry cleanup: only evict entries that are actually expired.
            while self.replay_expiry_heap and self.replay_expiry_heap[0][0] <= now:
                exp, mid = heapq.heappop(self.replay_expiry_heap)
                # Delete only if this heap record still matches current expiry in map.
                current_exp = self.replay_cache.get(mid)
                if current_exp is not None and current_exp == exp:
                    del self.replay_cache[mid]

            if message_id in self.replay_cache:
                return True

            self.replay_cache[message_id] = expires_at
            heapq.heappush(self.replay_expiry_heap, (expires_at, message_id))
            return False

# Global Singleton
state = ServerState()
