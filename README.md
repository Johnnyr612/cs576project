# P2P Chat

A decentralized, peer-to-peer messaging app built in Python.

## Project Structure
Initial idea for project structure (subject to change):
```
p2p-chat/
├── main.py                   # Entry point
├── core/
│   ├── peer.py               # Core P2P logic (Peer connection, encrypted messaging, and input/output loop)
│   ├── ephemeral.py          # Ephemeral messaging
│   ├── discovery.py          # Peer discovery (UDP)
│   ├── config.py             # Constants used across modules
│   ├── utils.py              # Reusable utilities
├── crypto/              	  # Cryptographic operations (RSA encryption, key generation, serialization)
│   ├── __init__.py
│   ├── keygen.py 			  # RSA key pair generation
│   ├── serialize.py          # Public key serialization and deserialization (PEM format)
│   ├── rsa_crypto.py         # RSA-based encryption and decryption with OAEP padding
├── gui/                      # (optional, for future GUI)
├── blockchain/               # (optional, for message chain or verification)
├── README.md
```


Additional notes:
Cost of advertising? Decentralized user authentication or message verification? Blockchain usage?
