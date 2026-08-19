import os
import json
import time
import base64
import sqlite3
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

# --- 1. Client Sender Logic ---
def create_transmission_package(sensor_data, master_seed):
    salt = os.urandom(32)
    nonce = os.urandom(12)
    kdf = Argon2id(salt=salt, length=32, iterations=3, lanes=4, memory_cost=65536)
    derived_key = kdf.derive(master_seed)
    
    aesgcm = AESGCM(derived_key)
    serialized_data = json.dumps(sensor_data, sort_keys=True).encode('utf-8')
    ciphertext = aesgcm.encrypt(nonce, serialized_data, associated_data=None)
    
    return {
        'salt': base64.b64encode(salt).decode('utf-8'),
        'nonce': base64.b64encode(nonce).decode('utf-8'),
        'ciphertext': base64.b64encode(ciphertext).decode('utf-8')
    }

# --- 2. Server Receiver Logic ---
class TelemetryIngressGateway:
    def __init__(self, master_secret: bytes):
        self.master_secret = master_secret
        self.ingress_nonce_ledger = set()

    def ingest_and_decapsulate(self, transmission_envelope: dict, max_age_seconds: int = 300) -> dict:
        salt = base64.b64decode(transmission_envelope['salt'])
        nonce = base64.b64decode(transmission_envelope['nonce'])
        ciphertext = base64.b64decode(transmission_envelope['ciphertext'])

        nonce_identifier = transmission_envelope['nonce']
        if nonce_identifier in self.ingress_nonce_ledger:
            raise Exception("Replay vector intercepted.")

        kdf = Argon2id(salt=salt, length=32, iterations=3, lanes=4, memory_cost=65536)
        derived_key = kdf.derive(self.master_secret)
        aesgcm = AESGCM(derived_key)
        
        decrypted_bytes = aesgcm.decrypt(nonce, ciphertext, associated_data=None)
        payload = json.loads(decrypted_bytes.decode('utf-8'))
        
        self.ingress_nonce_ledger.add(nonce_identifier)
        return payload

# --- 3. Persistence Vault Logic ---
class SecurePersistenceVault:
    def __init__(self, db_path: str = "production_vault.db"):
        self.db_path = db_path
        with sqlite3.connect(self.db_path) as connection:
            connection.execute('''
                CREATE TABLE IF NOT EXISTS transaction_ledger (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    nonce_identifier TEXT UNIQUE NOT NULL,
                    payload_data TEXT NOT NULL,
                    epoch_timestamp REAL NOT NULL,
                    status_flag TEXT NOT NULL
                )
            ''')
            connection.commit()

    def log_transaction(self, nonce: str, payload: dict, status: str):
        with sqlite3.connect(self.db_path) as connection:
            connection.execute('''
                INSERT OR IGNORE INTO transaction_ledger (nonce_identifier, payload_data, epoch_timestamp, status_flag)
                VALUES (?, ?, ?, ?)
            ''', (nonce, json.dumps(payload), time.time(), status))
            connection.commit()

# --- 4. Execution Pipeline ---
if __name__ == "__main__":
    print("[*] Initializing unified production pipeline...")
    SHARED_MASTER_SEED = b"A_VERY_SECURE_MASTER_SECRET_KEY_32B!"
    
    vault = SecurePersistenceVault()
    gateway = TelemetryIngressGateway(master_secret=SHARED_MASTER_SEED)
    
    payload = {"sensor_id": "NODE_ALPHA_01", "status": "nominal", "metric": 99.4}
    
    print("[*] Encrypting and dispatching packet...")
    envelope = create_transmission_package(payload, SHARED_MASTER_SEED)
    
    print("[*] Processing through server gateway and logging...")
    try:
        restored = gateway.ingest_and_decapsulate(envelope)
        vault.log_transaction(envelope['nonce'], restored, "VERIFIED_SUCCESS")
        print(f"[+] Success! Decapsulated Payload: {restored}")
    except Exception as e:
        vault.log_transaction(envelope['nonce'], payload, f"FAILED: {e}")
        print(f"[!] Processing failed: {e}")
    
    print("[Program finished]")
