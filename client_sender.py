import os
import json
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

def create_transmission_package(sensor_data, master_seed):
    """Encrypts data and formats it into a secure transmission envelope."""
    salt = os.urandom(32)
    nonce = os.urandom(12)
    
    # Derive the secure key using the shared secret and salt
    kdf = Argon2id(
        salt=salt,
        length=32,
        iterations=3,
        lanes=4,
        memory_cost=65536,
    )
    derived_key = kdf.derive(master_seed)
    
    # Encrypt the data payload
    aesgcm = AESGCM(derived_key)
    serialized_data = json.dumps(sensor_data, sort_keys=True).encode('utf-8')
    ciphertext = aesgcm.encrypt(nonce, serialized_data, associated_data=None)
    
    # Package into the final dictionary format
    envelope = {
        'salt': base64.b64encode(salt).decode('utf-8'),
        'nonce': base64.b64encode(nonce).decode('utf-8'),
        'ciphertext': base64.b64encode(ciphertext).decode('utf-8')
    }
    return envelope

if __name__ == "__main__":
    # Must match the master seed used in your server receiver
    SHARED_MASTER_SEED = b"A_VERY_SECURE_MASTER_SECRET_KEY_32B!"
    
    # Sample information to send
    outgoing_data = {
        "sensor_id": "NODE_BETA_09",
        "status": "operational",
        "metric_value": 42.5
    }
    
    print("[*] Packaging and encrypting data...")
    secure_package = create_transmission_package(outgoing_data, SHARED_MASTER_SEED)
    print("[+] Transmission package created successfully:")
    print(json.dumps(secure_package, indent=2))
