# Client-Side Encryption Gateway and Zero-Knowledge Transmission Prototype

A secure cryptographic architecture designed to encapsulate, transmit, and persistently log sensitive telemetry data with built-in replay mitigation and stateful verification.

## Architecture Overview

This repository houses a multi-tier cryptographic and persistence framework comprising the following modules:

* **`client_sender.py`**: Handles local payload serialization, dynamic salt generation, Argon2id key derivation, and AES-GCM encryption before transmission packaging.
* **`server_receiver.py`**: Acts as an ingress gateway that decapsulates payloads, performs cryptographic authentication, enforces temporal sliding-window boundaries, and mitigates replay attacks via nonce ledger tracking.
* **`persistence_vault.py`**: Interfaces with a local SQLite database to maintain an immutable, tamper-evident audit trail of all transactions and operational status flags.
* **`deploy_orchestrator.py`**: Unifies the client, server, and persistence layers into a single, cohesive production execution pipeline.
* **`LICENSE`**: Establishes proprietary legal protection and distribution restrictions.

## Prerequisites & Dependencies

The system requires Python 3.x along with the official cryptography library. Install the required dependency via pip:

```bash
pip install cryptography
