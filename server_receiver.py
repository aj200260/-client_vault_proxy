import os
import time
import json
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

class TelemetryIngressGateway:
    def __init__(self, master_secret: bytes):
        if not master_secret or len(master_secret) < 16:
            raise ValueError("Master secret initialization fails minimum entropy parameters.")
        self.master_secret = master_secret
        self.ingress_nonce_ledger = set()

    def _derive_key(self, salt: bytes) -> bytes:
        """Executes cryptographic key derivation via Argon2id parameters."""
        kdf = Argon2id(
            salt=salt,
            length=32,
            iterations=3,
            lanes=4,
            memory_cost=65536,
        )
        return kdf.derive(self.master_secret)

    def ingest_and_decapsulate(self, transmission_envelope: dict, max_age_seconds: int = 300) -> dict:
        """Ingests transmission envelope, validates nonces and temporal thresholds, and decapsulates the payload."""
        salt = base64.b64decode(transmission_envelope['salt'])
        nonce = base64.b64decode(transmission_envelope['nonce'])
        ciphertext = base64.b64decode(transmission_envelope['ciphertext'])

        nonce_identifier = transmission_envelope['nonce']
        if nonce_identifier in self.ingress_nonce_ledger:
            raise SecurityException("Replay vector intercepted: Duplicate nonce registration detected.")

        derived_key = self._derive_key(salt)
        aesgcm = AESGCM(derived_key)
        
        try:
            decrypted_bytes = aesgcm.decrypt(nonce, ciphertext, associated_data=None)
        except Exception as exception_context:
            raise DecryptionFailureException("Cryptographic authentication and payload integrity verification failed.") from exception_context

        payload = json.loads(decrypted_bytes.decode('utf-8'))

        epoch_current = time.time()
        if epoch_current - payload.get('utc_timestamp', 0) > max_age_seconds:
            raise LatencyThresholdException("Packet epoch timestamp breaches operational window parameters.")

        self.ingress_nonce_ledger.add(nonce_identifier)
        return payload

class SecurityException(Exception):
    pass

class DecryptionFailureException(Exception):
    pass

class LatencyThresholdException(Exception):
    pass


if __name__ == "__main__":
    # Shared secret synchronization vector
    SHARED_MASTER_SEED = b"A_VERY_SECURE_MASTER_SECRET_KEY_32B!"

    print("[*] Initializing server-side ingestion gateway...")
    gateway = TelemetryIngressGateway(master_secret=SHARED_MASTER_SEED)

    # Simulating package generation to test end-to-end pipeline execution
    print("[*] Generating simulated client transmission envelope...")
    salt = os.urandom(32)
    nonce = os.urandom(12)
    test_payload = {
        "sensor_id": "NODE_BETA_09",
        "diagnostic_status": "optimal",
        "temperature_celsius": 74.2,
        "utc_timestamp": time.time()
    }
    
    serialized_data = json.dumps(test_payload, sort_keys=True).encode('utf-8')
    
    # Key derivation and encryption matching protocol specs
    kdf_temp = Argon2id(salt=salt, length=32, iterations=3, lanes=4, memory_cost=65536)
    derived_temp_key = kdf_temp.derive(SHARED_MASTER_SEED)
    cipher_engine = AESGCM(derived_temp_key)
    ciphertext_bytes = cipher_engine.encrypt(nonce, serialized_data, associated_data=None)

    active_envelope = {
        'salt': base64.b64encode(salt).decode('utf-8'),
        'nonce': base64.b64encode(nonce).decode('utf-8'),
        'ciphertext': base64.b64encode(ciphertext_bytes).decode('utf-8')
    }

    print("[*] Processing incoming transmission envelope through gateway...")
    restored_telemetry = gateway.ingest_and_decapsulate(active_envelope)
    print(f"[+] Ingestion Successful. Decapsulated Payload: {restored_telemetry}")
    print("[Program finished]")
