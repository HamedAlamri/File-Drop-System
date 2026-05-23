# Secure Zero-Trust File Drop System  
CSE4057 – Spring 2026

---

# Team Members

| Name | Responsibilities |
|---|---|
| Faisal Al Breiki | Protocol design, cryptographic implementation, socket communication, secure handshake, replay protection, logging, testing suite, README documentation |
| Hamad Al Amri | File upload/download workflow integration, metadata handling, access control testing, debugging, test validation, security analysis, demonstration preparation |

---

# Project Overview

This project implements a secure Zero-Trust File Drop System where users can securely upload encrypted files for other users through an untrusted server.

The server is responsible for:
- authenticating users,
- storing encrypted files,
- relaying encrypted packages,
- enforcing access control,
- handling expiration and logging,

while never learning plaintext file contents.

The system was implemented using Python sockets and custom cryptographic protocol logic without using TLS or ready-made secure channel frameworks, as required by the assignment.

---

# Security Goals

The system was designed to provide:

- Confidentiality of uploaded files
- Mutual authentication
- Integrity verification
- Origin authentication
- Replay attack protection
- Access control enforcement
- Secure session establishment
- Expiration enforcement
- Security-aware event logging

---

# System Architecture

```text
+-----------+                         +-----------+                         +-----------+
| Client A  | <---- Secure Channel -->|  Server   |<---- Secure Channel -->| Client B  |
| (Sender)  |                         |           |                         |(Recipient)|
+-----------+                         +-----------+                         +-----------+
       \                                      ^
        \                                     |
         \                                    |
          +------------ Certificate Authority-+
```

Components:
- Clients: upload/download encrypted files
- Server: stores encrypted packages and enforces rules
- Certificate Authority (CA): issues and signs certificates

---

# Cryptographic Choices

| Purpose | Algorithm |
|---|---|
| Public Key Cryptography | RSA-2048 |
| Certificates | Custom CA-Signed RSA Certificates |
| Digital Signatures | RSA-PSS + SHA256 |
| Session Key Exchange | ECDH |
| Session Key Derivation | HKDF-SHA256 |
| File Encryption | AES-GCM |
| Randomness Source | os.urandom() |
| Hashing | SHA256 |

---

# Public Key Infrastructure (PKI)

## Certificate Authority

A custom Certificate Authority (CA) module was implemented.

The CA:
1. Generates its own RSA key pair
2. Signs client certificates
3. Signs server certificates
4. Verifies certificate authenticity

Each certificate contains:
- subject ID
- public key
- issuer
- validity period
- serial number
- CA signature

---

# Certificate Issuance Workflow

```text
1. User generates RSA key pair
2. User sends public key to CA
3. CA signs certificate
4. Certificate stored locally
5. Certificate exchanged during handshake
```

---

# Secure Handshake Protocol

The client and server establish a secure authenticated session before any sensitive operation.

# Mutual Authentication

The system enforces mutual authentication.

Client authentication:
- the server verifies the client certificate,
- verifies the CA signature,
- verifies proof-of-possession of the private key.

Server authentication:
- the client verifies the server certificate,
- verifies the CA signature,
- verifies the server proof signature.

This prevents unauthorized entities from impersonating trusted participants.

---

# Handshake Steps

## Step 1 — ClientHello

The client sends:
- client ID
- client certificate
- client nonce
- ECDH public key
- proof-of-possession signature

---

## Step 2 — Certificate Verification

The server:
- verifies CA signature
- checks certificate validity
- verifies proof-of-possession signature

If verification fails:
- connection rejected
- security event logged

---

## Step 3 — ServerHello

The server sends:
- server certificate
- server nonce
- server ECDH public key
- server proof signature

---

## Step 4 — Server Authentication

The client:
- verifies server certificate
- verifies server proof signature

---

## Step 5 — Shared Secret Establishment

Both sides compute an ECDH shared secret.

---

## Step 6 — Session Key Derivation

HKDF-SHA256 derives:
- client-to-server encryption key
- server-to-client encryption key
- additional session values

---

# Freshness and Replay Protection

Replay protection is enforced using:
- nonces
- timestamps
- sequence numbers
- replay cache

The server stores previously used nonces and rejects reused handshake attempts.

Example rejection:

```json
{
  "error": "Replay detected: nonce already used"
}
```

---

# Application Layer Protocol

A custom application-layer protocol was designed and implemented.

---

# Message Types

| Message Type | Purpose |
|---|---|
| CLIENT_HELLO | Initiate handshake |
| SERVER_HELLO | Server handshake response |
| UPLOAD_REQUEST | Upload encrypted package |
| UPLOAD_ACK | Upload success |
| LIST_REQUEST | Request pending files |
| LIST_RESPONSE | Return pending files |
| DOWNLOAD_REQUEST | Retrieve encrypted package |
| DOWNLOAD_RESPONSE | Send encrypted package |
| ERROR | Error reporting |

---

# Message Format

Each protocol message contains:

```json
{
  "type": "MESSAGE_TYPE",
  "session_id": "...",
  "seq": 1,
  "timestamp": 1779488577,
  "nonce": "...",
  "payload": { }
}
```

---

# Request / Response Matching

The protocol uses:
- session IDs
- sequence numbers
- timestamps
- message types

to match requests and responses securely.

---

# Secure File Upload

## Upload Workflow

1. Sender generates random AES file key
2. File encrypted using AES-GCM
3. AES file key wrapped using recipient RSA public key
4. Sender signs metadata and encrypted package
5. Package uploaded to server
6. Server verifies signature before storage

The server never receives plaintext file contents.

---

# Metadata Stored by Server

The server stores:

| Field | Purpose |
|---|---|
| file_id | unique identifier |
| sender_id | sender identity |
| recipient_id | intended recipient |
| upload_time | upload timestamp |
| expiration_time | expiration enforcement |
| filename | file reference |
| status | pending/downloaded |
| wrapped_file_key | recipient encrypted AES key |

---

# Recipient-Specific Key Protection

Each uploaded file uses a unique AES file key.

That AES key is encrypted using the recipient’s RSA public key.

Therefore:
- only the intended recipient can recover the AES key,
- the server cannot decrypt files,
- unauthorized users cannot decrypt files.

---

# Digital Signatures

The sender signs:
- sender ID
- recipient ID
- file ID
- encrypted file hash
- timestamps
- expiration information

The server verifies signatures before accepting uploads.

The recipient verifies signatures after download and decryption.

---

# Secure File Retrieval

## Retrieval Workflow

1. Recipient authenticates
2. Recipient requests pending file list
3. Server returns pending files
4. Recipient requests download
5. Server verifies authorization
6. Server sends encrypted package
7. Recipient unwraps AES key
8. Recipient decrypts file
9. Recipient verifies sender signature

---

# Access Control Enforcement

The server strictly enforces:
- recipient-only retrieval
- authenticated sessions
- user identity binding

Unauthorized attempts are rejected.

Example:

```json
{
  "error": "Unauthorized access: this file is not for you"
}
```

---

# One-Time Download (Bonus Feature)

The system implements server-enforced one-time downloads.

A file transitions:

```text
pending -> downloaded
```

Only successful retrieval consumes the file.

Repeated download attempts are rejected and logged.

Example:

```json
{
  "error": "File already downloaded"
}
```

Interrupted or failed downloads do not consume the file automatically.

---

# File Expiration

Each uploaded file contains an expiration timestamp.

Before retrieval:
- the server checks expiration status,
- expired files are rejected,
- expiration events are logged.

Example:

```json
{
  "error": "File expired and cannot be downloaded"
}
```

---

# Logging

The system maintains security-aware logs.

Logged events include:
- connections
- certificate verification
- handshake events
- uploads
- downloads
- replay detections
- unauthorized access attempts
- expiration rejections
- signature failures

Sensitive data is NOT logged:
- plaintext files
- private keys
- AES keys
- decrypted content

---

# Socket Programming

The system uses:
- TCP sockets
- localhost testing
- multi-client support
- multi-threaded server design

The server can handle:
- multiple connections,
- multiple uploads,
- multiple downloads.

---

# Initial Server Setup

Before running the system for the first time, initialize the Certificate Authority (CA), server certificates, and required folders.

Run:

```bash
python client.py setup-server
```

This setup step will:
- create the Certificate Authority (CA),
- generate server RSA keys,
- issue the server certificate,
- create required folders:
  - certs/
  - keys/
  - storage/
  - downloads/
  - logs/

Expected output example:

```text
[SETUP] CA initialized
[SETUP] Server keys generated
[SETUP] Server certificate issued
[SETUP] Storage folders created
[SETUP] Setup completed successfully
```

---

# Security Demonstration Tests

A dedicated `demo_tests.py` test suite was implemented.

---

# Included Security Tests

| Test | Result |
|---|---|
| Valid Handshake | PASS |
| Bad Proof-of-Possession | PASS |
| Replay Attack | PASS |
| Spoofed LIST Request | PASS |
| Tampered Upload Signature | PASS |
| Unauthorized Download | PASS |
| One-Time Download | PASS |
| Expired File Rejection | PASS |

These tests demonstrate that security mechanisms are actually enforced by the system and not merely printed messages.

---

# Security Analysis and Limitations

Although the system includes strong protections, some limitations still exist.

---

## Possible Vulnerabilities

### 1. Metadata Leakage
The server still sees:
- filenames
- file sizes
- upload timing
- sender/recipient IDs

Countermeasure:
- confidential metadata encryption
- metadata padding

---

### 2. Compromised Client Private Keys
If a user private key is stolen:
- attacker may impersonate the client,
- attacker may decrypt future files.

Countermeasure:
- hardware-backed key storage
- certificate revocation system

---

### 3. Malicious Server Metadata Modification
A malicious server could modify metadata fields.

Countermeasure:
- sign more metadata fields,
- include integrity-protected metadata structures.

---

### 4. Localhost Deployment
Current testing was performed on localhost.

Countermeasure:
- distributed deployment testing,
- Docker containerization,
- WAN testing.

---

### 5. No Certificate Revocation
The current system does not implement:
- CRLs
- OCSP
- dynamic certificate revocation

Countermeasure:
- add CA revocation list support.

---

# Project Structure

```text
File-Drop-System/
│
├── client.py
├── server.py
├── ca.py
├── crypto_utils.py
├── protocol.py
├── emo_tests.py
│
├── certs/
├── keys/
├── storage/
├── downloads/
├── logs/
│
└── README.md
```

---

# How to Run

## 1. Initial Setup

```bash
python client.py setup-server
```

---

## 2. Start Server

```bash
python server.py
```

---

## 3. Start Client

```bash
python client.py
```

---

## 4. Run Security Tests

```bash
python demo_tests.py
```

---

# Demonstration Checklist

The system successfully demonstrates:

- CA certificate issuance
- Mutual certificate authentication
- Secure ECDH handshake
- HKDF key derivation
- Secure encrypted upload
- Recipient-specific key protection
- Digital signatures
- Secure retrieval
- Unauthorized access rejection
- Expiration enforcement
- Replay protection
- Security-aware logging

This matches the assignment requirements.

---

# Division of Labor

The team coordinated using:
- shared GitHub repository
- local testing
- protocol reviews
- integrated debugging sessions

All components were integrated and tested together before final submission.

---

# Conclusion

This project demonstrates a complete Zero-Trust Secure File Drop System using custom-designed cryptographic protocols and secure socket communication.

The system provides:
- authenticated communication,
- encrypted storage,
- integrity verification,
- replay protection,
- access control,
- expiration enforcement,
- security-aware logging,

while ensuring that the server never learns plaintext file contents.

---