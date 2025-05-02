# P2P Chat

A decentralized, peer-to-peer messaging app built in Python.

## Project Structure
Initial idea for project structure (subject to change):
```
p2p-chat/
├── peer.py              # Peer connection, encrypted messaging, and input/output loop
├── crypto/              # Cryptographic operations (RSA encryption, key generation, serialization)
│   ├── __init__.py      #
│   ├── keygen.py        # RSA key pair generation
│   ├── serialize.py     # Public key serialization and deserialization (PEM format)
│   ├── rsa_crypto.py    # RSA-based encryption and decryption with OAEP padding
├── blockchain/          # Message hash chain, integrity checks, and block verification (verification)
├── gui/                 # Groupchat graphical interface
├── utils.py             # Shared helper functions (e.g., socket send/receive wrappers)
├── config.py            # Global constants (e.g., default ports, buffer sizes)
└── README.md            # Project overview, setup instructions, and usage guide
```

Additional notes:
Cost of advertising? Decentralized user authentication or message verification? Blockchain usage?
