import os
import time
import json
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

class SecureTelemetryProxy:
    def __init__(self, master_secret: bytes):
        if not master_secret or len(master_secret) < 16:
            raise ValueError("Master secret must meet minimum entropy requirements.")
        self.master_secret = master_secret
        self.processed_nonces = set()

    def _derive_key(self, salt: bytes) -> bytes:
        """Derives a cryptographic key using Argon2id with a dynamic salt."""
        kdf = Argon2id(
            salt=salt,
            length=32,
            iterations=3,
            lanes=4,
            memory_cost=65536,
        )
        return kdf.derive(self.master_secret)

    def package_and_encrypt(self, payload_data: dict) -> dict:
        """Executes local zero-knowledge encryption and envelope generation."""
        salt = os.urandom(32)
        nonce = os.urandom(12)

        payload_data['utc_timestamp'] = time.time()
        payload_data['nonce_sig'] = base64.b64encode(nonce).decode('utf-8')

        serialized_payload = json.dumps(payload_data, sort_keys=True).encode('utf-8')

        derived_key = self._derive_key(salt)
        aesgcm = AESGCM(derived_key)
        ciphertext = aesgcm.encrypt(nonce, serialized_payload, associated_data=None)

        transmission_envelope = {
            'salt': base64.b64encode(salt).decode('utf-8'),
            'nonce': base64.b64encode(nonce).decode('utf-8'),
            'ciphertext': base64.b64encode(ciphertext).decode('utf-8')
        }
        return transmission_envelope

    def verify_and_decrypt(self, envelope: dict, max_age_seconds: int = 300) -> dict:
        """Validates temporal integrity, nonces, and decrypts the payload."""
        salt = base64.b64decode(envelope['salt'])
        nonce = base64.b64decode(envelope['nonce'])
        ciphertext = base64.b64decode(envelope['ciphertext'])

        nonce_str = envelope['nonce']
        if nonce_str in self.processed_nonces:
            raise SecurityError("Replay attack detected: Nonce has already been processed.")

        derived_key = self._derive_key(salt)
        aesgcm = AESGCM(derived_key)
        
        try:
            decrypted_bytes = aesgcm.decrypt(nonce, ciphertext, associated_data=None)
        except Exception as e:
            raise DecryptionError("Cryptographic authentication failed.") from e

        payload = json.loads(decrypted_bytes.decode('utf-8'))

        current_time = time.time()
        if current_time - payload.get('utc_timestamp', 0) > max_age_seconds:
            raise TimeoutError("Packet timestamp exceeds the valid operational window.")

        self.processed_nonces.add(nonce_str)
        return payload

class SecurityError(Exception):
    pass

class DecryptionError(Exception):
    pass


if __name__ == "__main__":
    MASTER_SEED = os.getenv("VAULT_MASTER_SECRET", "").encode('utf-8')
    
    if not MASTER_SEED:
        print("[!] Operational Warning: VAULT_MASTER_SECRET environment variable is uninitialized.")
        MASTER_SEED = os.urandom(32)

    # Parameter corrected to master_secret
    proxy = SecureTelemetryProxy(master_secret=MASTER_SEED)

    telemetry_input = {
        "sensor_id": "NODE_ALPHA_04",
        "diagnostic_status": "nominal",
        "pressure_psi": 142.5
    }

    print("[*] Executing local client-side encapsulation...")
    encrypted_packet = proxy.package_and_encrypt(telemetry_input)
    print(f"[+] Encrypted Envelope Generated: {list(encrypted_packet.keys())}")

    print("[*] Simulating secure receiver ingestion and decryption...")
    restored_payload = proxy.verify_and_decrypt(encrypted_packet)
    print(f"[+] Verified Decrypted Payload: {restored_payload}")
