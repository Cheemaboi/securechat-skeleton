SecureChat – Assignment #2 (Completed)
This repository contains the completed implementation of the SecureChat system for CS-3002 Information Security (Fall 2025).

This system is a console-based, PKI-enabled Secure Chat built in Python. It manually implements all cryptographic operations at the application layer to achieve Confidentiality, Integrity, Authenticity, and Non-Repudiation (CIANR), without relying on TLS/SSL.



Features
PKI: Full Certificate Authority (CA) and certificate generation.

Authentication: Mutual certificate validation and secure user login with salted/hashed passwords.

Confidentiality: All communication is encrypted using AES-128 with a key derived from a Diffie-Hellman exchange.

Integrity: Every message is protected by a SHA-256 hash.

Authenticity: Every message is signed by the sender's RSA private key and verified by the receiver.

Non-Repudiation: A verifiable, signed session transcript (SessionReceipt) is generated at the end of each chat.

🏗️ Folder Structure
(This is the same as the original, showing the completed file structure)

securechat-skeleton/
├─ app/
│  ├─ client.py              # Completed client workflow
│  ├─ server.py              # Completed server workflow
│  ├─ crypto/
│  │  ├─ aes.py              # AES-128 helpers
│  │  ├─ dh.py               # Diffie-Hellman key exchange
│  │  ├─ pki.py              # X.509 certificate validation
│  │  └─ sign.py             # RSA SHA-256 sign/verify
│  ├─ common/
│  │  ├─ protocol.py         # Pydantic message models
│  │  └─ utils.py            # Base64, SHA256, timestamp helpers
│  └─ storage/
│     ├─ db.py               # MySQL user store functions
│     └─ transcript.py       # Append-only transcript logger
├─ scripts/
│  ├─ gen_ca.py              # Script to create Root CA
│  └─ gen_cert.py            # Script to issue client/server certs
├─ tests/manual/
│  ├─ NOTES.md
│  ├─ tamper_test.py         # Client modified for integrity test
│  ├─ replay_test.py         # Client modified for freshness test
│  └─ verify_offline.py      # Script for non-repudiation test
├─ certs/                   # (Generated, .gitignored)
├─ transcripts/             # (Generated, .gitignored)
├─ .env
├─ requirements.txt
└─ ...
⚙️ Execution Steps
Prerequisite: You must have docker and python3 installed.

1. Setup Environment
First, set up the Python virtual environment and install dependencies.

Bash

# 1. Create and activate a virtual environment
python3 -m venv .venv
source .venv/bin/activate  # (or .venv\Scripts\activate on Windows)

# 2. Install required libraries
pip install -r requirements.txt

# 3. Set up the environment file
cp .env.example .env
2. Run the Database
The project uses a MySQL database run via Docker.

Bash

docker run -d --name securechat-db \
    -e MYSQL_ROOT_PASSWORD=rootpass \
    -e MYSQL_DATABASE=securechat \
    -e MYSQL_USER=scuser \
    -e MYSQL_PASSWORD=scpass \
    -p 3306:3_306 mysql:8
3. Initialize the Database
This command creates the users table.

Bash

python -m app.storage.db --init
4. Generate Certificates
This one-time setup creates the CA, server cert, and client cert.

Bash

# 1. Create the Root CA
python scripts/gen_ca.py --name "FAST-NU Root CA"

# 2. Create the server certificate
python scripts/gen_cert.py --cn server.local --out certs/server

# 3. Create the client certificate
python scripts/gen_cert.py --cn client.local --out certs/client
5. Run the Application
You will need two separate terminals, both with the virtual environment activated.

In Terminal 1: Run the Server

Bash

python -m app.server
Output:

Loading server credentials...
Server credentials loaded successfully.
[*] Server listening on 0.0.0.0:6000...
In Terminal 2: Run the Client

Bash

python -m app.client
Output:

Loading client credentials...
Client credentials loaded successfully.
Connecting to 127.0.0.1:6000...
💬 Sample Input/Output Formats
The client will guide you through all interactions.

Registration
Do you want to (login) or (register)? register
Email: user@example.com
Password: (typing is hidden)
Username: testuser
Successfully register as user@example.com!
Login
Do you want to (login) or (register)? login
Email: user@example.com
Password: (typing is hidden)
Successfully login as user@example.com!
...
MAIN session key derived. Chat is now SECURE.
Type /exit to quit.
Chatting
[You]: hello
[Server]: Server received: hello
[You]: this is a secure message
[Server]: Server received: this is a secure message
[You]: /exit
