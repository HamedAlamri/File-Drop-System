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

The system was implemented using Python sockets and custom cryptographic protocol logic without using TLS or ready-made secure channel frameworks, as required by the assignment, An optional graphical user interface (GUI) was also implemented for easier demonstration and interaction with the secure file system.

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

## Mutual Authentication

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
* Proof-of-possession is implemented by signing fresh handshake nonces using the participant private key.

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

If server authentication fails, the client immediately terminates the connection and refuses to continue the session.

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
| DOWNLOAD_ACK | Signed recipient acknowledgement |
| DOWNLOAD_ACK_RESPONSE | ACK verification response |
| REVOKE_REQUEST | Revoke uploaded file before retrieval |
| REVOKE_ACK | Revocation success confirmation |
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
| status | pending/downloaded/revoked/expired |
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

The server updates the file state only after a successful DOWNLOAD_RESPONSE is delivered to the authenticated recipient.

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

Interrupted or failed downloads do not consume the file automatically, the server tracks file retrieval state transitions securely and rejects repeated retrieval attempts after successful delivery.

---

# Revocation Before Download (Bonus Feature)

The system implements server-enforced file revocation before successful retrieval.

The sender may revoke an uploaded file only if:
- the file has not been downloaded yet,
- the requester is the original sender,
- the file still exists in pending state.

Revocation is enforced by the server and not by the client interface.

When a file is revoked:
- the server changes the file state to revoked,
- future download attempts are rejected,
- revocation events are logged.

Example successful revocation:

```json
{
  "message": "File revoked successfully"
}
```

Example retrieval rejection after revocation:

```json
{
  "error": "File has been revoked by sender"
}
```

The server checks revocation status before every retrieval request.

---

# Signed Recipient Acknowledgement (Bonus Feature)

The system implements signed recipient acknowledgements after successful retrieval and verification.

After downloading and decrypting the file:

1. The recipient verifies the sender digital signature
2. The recipient generates a signed acknowledgement
3. The acknowledgement is cryptographically bound to:

   * file ID
   * recipient ID
   * acknowledgement timestamp
   * verification status
4. The acknowledgement is signed using the recipient private key
5. The server verifies the acknowledgement signature

The acknowledgement is generated only after successful verification of the downloaded package.

This mechanism allows:

* proof of successful delivery,
* proof of recipient verification,
* cryptographic confirmation of receipt.

Example acknowledgement message:

```json
{
  "type": "DOWNLOAD_ACK",
  "payload": {
    "file_id": "FILE-123",
    "recipient_id": "Bob",
    "status": "verified"
  }
}
```

Example successful acknowledgement verification:

```json
{
  "message": "Signed acknowledgement verified"
}
```

Acknowledgement events are logged by the server.

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
- file revocation events
- revoked-file retrieval attempts
- replay detections
- unauthorized access attempts
- expiration rejections
- signature failures
- signed acknowledgement verification

Sensitive data is NOT logged:
- plaintext files
- private keys
- AES keys
- decrypted content

Logs include timestamps, client identities, file identifiers, and security event types.

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
[KEYGEN] Generated RSA keys for server
[SETUP] Server keys and certificate created
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
| Revoked File Rejection | PASS |
| Signed Recipient Acknowledgement | PASS |

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

### 6. No Transport-Layer Encryption

The current implementation establishes authenticated session keys using ECDH and HKDF, but application payloads exchanged after the handshake are not yet encrypted using those derived session keys.

Countermeasure:
- apply authenticated encryption to all post-handshake protocol messages using AES-GCM session encryption.

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
├── demo_tests.py
├── gui_client.py
├── cert_manager.py
├── storage_manager.py
├── logger.py
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

# Optional GUI Client

The project also includes an optional graphical user interface for easier demonstration and usability.

Lets start with this command for setup the server:

```bash
python client.py setup-server
```

Before running the GUI, make sure the server is already running:

```bash
python server.py
```

Then run:

```bash
python gui_client.py
```

If `customtkinter` is not installed, install it using:

```bash
pip install customtkinter
```

The GUI supports:
- starting a secure authenticated session,
- encrypted file upload,
- expiration-time entry from the interface,
- visual file listing using card-style views,
- automatic refresh when switching tabs,
- selecting files for download without manually typing the file ID,
- selecting uploaded files for revocation,
- displaying file status in the interface.

The GUI is only an additional usability layer.

All security decisions are still enforced by the server and the core protocol, including:
- certificate-based authentication,
- access control,
- file encryption,
- signature verification,
- replay protection,
- expiration checks,
- revocation enforcement,
- one-time download enforcement,
- signed recipient acknowledgement verification.

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
- File revocation before download
- Revoked file rejection
- Signed recipient acknowledgement
- ACK signature verification
- Expiration enforcement
- Replay protection
- Security-aware logging
- Optional GUI client for easier demonstration

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
- signed recipient acknowledgement,
- expiration enforcement,
- security-aware logging,

while ensuring that the server never learns plaintext file contents.

---