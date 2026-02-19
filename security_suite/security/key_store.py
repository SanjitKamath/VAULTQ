import os
import time
import hashlib
import json
from security_suite.crypto.primitive_dsa import DSAManager

KEY_DIR = "secure_keys/"

class KeyRotationManager:
    """
    Manages key lifecycles. 
    automatically generates new keys and archives old ones.
    """
    def __init__(self, role: str):
        self.role = role  
        os.makedirs(KEY_DIR, exist_ok=True)
        self.current_dsa = None
        self.current_kid = None

    def load_or_rotate(self):
        meta_path = f"{KEY_DIR}/{self.role}_meta.json"
        
        if os.path.exists(meta_path):
            with open(meta_path, 'r') as f:
                meta = json.load(f)
            if time.time() - meta['created_at'] > (90 * 86400):
                print("Key expired. Rotating...")
                self._rotate_keys()
            else:
                self._load_keys(meta['kid'])
        else:
            self._rotate_keys()

    def _rotate_keys(self):
        print(f"Generating new ML-DSA keys for {self.role}...")
        
        dsa = DSAManager()
        dsa.generate_keypair()
        
        pub_bytes = dsa.get_public_bytes()
        kid = hashlib.sha256(pub_bytes).hexdigest()[:16] 
        
        with open(f"{KEY_DIR}/{kid}.priv", "wb") as f:
            f.write(dsa.get_private_bytes())
            
        meta = {"kid": kid, "created_at": int(time.time()), "alg": "ML-DSA-65"}
        with open(f"{KEY_DIR}/{self.role}_meta.json", "w") as f:
            json.dump(meta, f)
            
        self.current_dsa = dsa
        self.current_kid = kid
        return kid

    def _load_keys(self, kid):
        with open(f"{KEY_DIR}/{kid}.priv", "rb") as f:
            priv_bytes = f.read()
        self.current_dsa = DSAManager(private_bytes=priv_bytes)
        self.current_kid = kid

    def get_signer(self):
        if not self.current_dsa:
            self.load_or_rotate()
        return self.current_dsa