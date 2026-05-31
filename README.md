# Secure Zero-Trust File Drop System

This project implements a secure file drop system for CSE4057 Spring 2026. It uses raw TCP sockets and a custom application-layer protocol. It does **not** use SSL/TLS, `ssl`, OpenSSL secure socket wrappers, or any ready-made secure channel framework.

Implemented bonus features:

1. **Revocation before download**: the sender can revoke a file before the recipient successfully downloads it.
2. **One-time download**: after a successful recipient-side decrypt/verify and authenticated ACK, the file cannot be downloaded again.
3. **End-to-end encrypted notes**: the sender may attach a short note encrypted with the same file key.

## 1. Requirements

Python 3.10+ is recommended.

Install dependencies:

```bash
pip install -r requirements.txt
```

The only external crypto dependency is `cryptography`. It is used for cryptographic primitives only, not TLS.

## 2. Project structure

```text
secure_drop/
  ca.py          Simple CA creation and certificate issuance
  client.py      Client commands: register, upload, list, download, revoke
  server.py      Multithreaded TCP server
  handshake.py   Custom certificate-authenticated ECDH handshake
  common.py      Shared crypto, framing, certificate, logging utilities
requirements.txt
README.md
demo.sh
```

Runtime folders are created automatically:

```text
pki/                CA, server, and client keys/certificates
storage/server/     encrypted packages, metadata, server logs
downloads/          downloaded files
test_files/         sample input files
```

## 3. Cryptographic design

### 3.1 Public keys and certificates

Each entity has an RSA-3072 key pair. The CA has its own RSA-3072 key pair. A certificate is a JSON object:

```json
{
  "body": {
    "version": 1,
    "subject_id": "alice",
    "role": "client",
    "public_key_pem": "...",
    "issued_at": 123,
    "expires_at": 456,
    "serial": "...",
    "issuer": "Simple-SFD-CA"
  },
  "signature": "base64 RSA-PSS-SHA256 signature over canonical body JSON"
}
```

Certificate verification checks:

- CA signature using RSA-PSS-SHA256.
- certificate validity time.
- expected role, such as `client` or `server`.
- expected subject where required.

### 3.2 Client-server handshake

The handshake is custom and runs over raw TCP:

1. Client sends `HELLO` containing:
   - protocol version,
   - client certificate,
   - fresh 32-byte nonce,
   - ephemeral ECDH P-256 public key.
2. Server verifies the client certificate.
3. Server sends `HELLO` containing:
   - protocol version,
   - server certificate,
   - fresh 32-byte nonce,
   - ephemeral ECDH P-256 public key.
4. Client verifies the server certificate.
5. Client proves possession of its RSA private key by signing the canonical handshake transcript.
6. Server verifies the client proof.
7. Server proves possession of its RSA private key by signing the same transcript.
8. Client verifies the server proof.
9. Both sides compute the ECDH shared secret.
10. Both sides derive channel keys using HKDF-SHA256.

The transcript includes both Hello messages, so the nonces, certificates, roles, and ephemeral ECDH keys are bound to the signed proof.

### 3.3 Session key derivation

The ECDH secret is passed to HKDF-SHA256:

```text
salt = SHA256(client_hello || server_hello)
info = "SFD channel keys v1"
output = 64 bytes
first 32 bytes  = client-to-server AES-GCM key
second 32 bytes = server-to-client AES-GCM key
```

After the handshake, all application messages are encrypted with AES-256-GCM.

### 3.4 Secure channel framing

Each encrypted frame contains:

```json
{
  "seq": 1,
  "ct": "base64 AES-GCM ciphertext+tag"
}
```

The AES-GCM nonce is the 12-byte big-endian sequence number. The sequence number is also authenticated as additional authenticated data. The receiver requires the next exact sequence number; skipped, reordered, or repeated channel frames are rejected.

A 4-byte network-order length prefix is used for TCP framing.

## 4. Application protocol

After authentication, the client sends encrypted request messages. Every request contains:

```json
{
  "type": "REQUEST_TYPE",
  "request_id": "random uuid hex",
  "timestamp": 1234567890
}
```

The server keeps a replay cache per authenticated user. A request is rejected if:

- the timestamp is outside the freshness window,
- the same `(user, request_id)` has already been seen.

Supported request types:

### 4.1 `GET_CERT`

Used by a sender to obtain the recipient's CA-signed certificate from the server.

```json
{"type": "GET_CERT", "user": "bob", "request_id": "...", "timestamp": 123}
```

The server only knows certificates of users who have connected at least once.

### 4.2 `UPLOAD`

The client uploads an encrypted file package:

```json
{
  "type": "UPLOAD",
  "package": {
    "file_id": "...",
    "visible_metadata": {
      "file_id": "...",
      "sender_id": "alice",
      "recipient_id": "bob",
      "upload_timestamp": 123,
      "expires_at": 456,
      "ciphertext_hash": "...",
      "plaintext_hash": "...",
      "file_size": 42
    },
    "wrapped_file_key": "RSA-OAEP encrypted file key for recipient",
    "file_iv": "...",
    "file_aad": "...",
    "ciphertext": "AES-GCM encrypted file bytes",
    "encrypted_note": "AES-GCM encrypted note or null",
    "note_iv": "... or null",
    "signed_fields": "same security-critical fields",
    "sender_signature": "RSA-PSS-SHA256 signature"
  }
}
```

Server-side upload checks:

- authenticated user must match `sender_id`,
- recipient certificate must be known,
- sender signature must verify,
- signed fields must match the package,
- `file_id` must be unique.

The server stores only the encrypted package and visible routing metadata.

### 4.3 `LIST`

Lists files relevant to the authenticated user:

```json
{"type": "LIST", "scope": "recipient"}
```

`scope=recipient` lists files addressed to the user. `scope=sender` lists files sent by the user.

### 4.4 `DOWNLOAD`

The recipient requests a file by ID:

```json
{"type": "DOWNLOAD", "file_id": "..."}
```

Server-side checks:

- file exists,
- authenticated user is the intended recipient,
- file is not expired,
- file is not revoked,
- file has not already been successfully downloaded.

If checks pass, the server sends the encrypted package.

Recipient-side checks:

- sender certificate is CA-valid,
- sender signature verifies,
- file key unwrap succeeds using recipient private key,
- AES-GCM file decryption succeeds,
- plaintext hash matches signed metadata,
- encrypted note, if present, decrypts under the file key.

### 4.5 `ACK_DOWNLOAD`

A successful one-time download is counted only after the recipient decrypts the file and verifies the sender signature locally, then sends this authenticated ACK:

```json
{"type": "ACK_DOWNLOAD", "file_id": "..."}
```

After ACK, the server marks the file as `downloaded`, and later downloads are rejected.

Interrupted or failed downloads before ACK do not consume the one-time download.

### 4.6 `REVOKE`

The sender can revoke a pending file:

```json
{"type": "REVOKE", "file_id": "..."}
```

Server-side checks:

- authenticated user must be the original sender,
- file must not already have a successful download.

Revoked files are not retrievable.

## 5. File encryption and zero-trust storage

For each uploaded file:

1. The sender generates a fresh 256-bit random file key.
2. The sender encrypts the file with AES-256-GCM.
3. The sender wraps the file key using the recipient's RSA public key with RSA-OAEP-SHA256.
4. The sender signs the sender ID, recipient ID, file ID, hashes, timestamp, and expiration time.
5. The server stores the encrypted package but cannot unwrap the file key because it does not have the recipient private key.

The server sees routing metadata such as sender, recipient, status, timestamps, size, and expiration. It does not see plaintext file contents or encrypted note contents.

## 6. Expiration

Each package has an `expires_at` Unix timestamp. The server stores it in `metadata.json`. Before any download, the server checks:

```text
current_time <= expires_at
```

If the file is expired, retrieval is rejected, status is updated to `expired`, and the event is logged.

## 7. Replay protection

Replay risks and defenses:

- **Handshake replay**: Hello messages include fresh nonces and fresh ephemeral ECDH public keys. Proof-of-possession signs the current transcript.
- **Encrypted channel frame replay/reordering**: each frame has a strict AES-GCM-authenticated sequence number.
- **Application request replay**: each request has a random request ID and timestamp. The server rejects duplicate request IDs for the same authenticated user and stale timestamps.
- **Upload replay with the same package**: duplicate `file_id` values are rejected.
- **Download replay**: one-time download state rejects repeated successful retrievals.

## 8. Logging

The server writes logs to:

```text
storage/server/server.log
```

Logged events include:

- server startup,
- authenticated connections,
- certificate verification failures,
- proof-of-possession failures,
- uploads,
- unauthorized download attempts,
- expired-file retrieval attempts,
- revoked-file retrieval attempts,
- one-time repeated download attempts,
- revocation events,
- replay/freshness failures.

Logs do not include private keys, session secrets, file keys, or plaintext file contents.

## 9. Running manually

### 9.1 Create PKI material

From the project root:

```bash
python -m secure_drop.ca init --ca-dir pki/ca
python -m secure_drop.ca issue server --role server --ca-dir pki/ca --out-dir pki/server
python -m secure_drop.ca issue alice --role client --ca-dir pki/ca --out-dir pki/alice
python -m secure_drop.ca issue bob --role client --ca-dir pki/ca --out-dir pki/bob
python -m secure_drop.ca issue mallory --role client --ca-dir pki/ca --out-dir pki/mallory
```

### 9.2 Start the server

```bash
python -m secure_drop.server --host 127.0.0.1 --port 9000 --storage storage/server
```

Keep this terminal open.

### 9.3 Register/announce clients to the server

Open another terminal in the project root:

```bash
python -m secure_drop.client --user alice --cert pki/alice/alice_cert.json --key pki/alice/alice_private_key.pem register
python -m secure_drop.client --user bob --cert pki/bob/bob_cert.json --key pki/bob/bob_private_key.pem register
python -m secure_drop.client --user mallory --cert pki/mallory/mallory_cert.json --key pki/mallory/mallory_private_key.pem register
```

This lets the server learn the clients' CA-signed certificates. Without this, Alice cannot fetch Bob's recipient certificate.

### 9.4 Create a sample file

```bash
mkdir -p test_files downloads
printf "Secret message from Alice to Bob.\n" > test_files/alice_secret.txt
```

### 9.5 Alice uploads a file for Bob

```bash
python -m secure_drop.client --user alice --cert pki/alice/alice_cert.json --key pki/alice/alice_private_key.pem upload --recipient bob --file test_files/alice_secret.txt --expires 3600 --note "Private note for Bob"
```

Copy the returned `file_id`.

### 9.6 Bob lists pending files

```bash
python -m secure_drop.client --user bob --cert pki/bob/bob_cert.json --key pki/bob/bob_private_key.pem list
```

### 9.7 Bob downloads and verifies the file

Replace `<FILE_ID>`:

```bash
python -m secure_drop.client --user bob --cert pki/bob/bob_cert.json --key pki/bob/bob_private_key.pem download <FILE_ID> --out downloads/bob_secret.txt
```

Expected result:

- file decrypts successfully,
- sender signature verifies,
- note decrypts if provided,
- server marks the file downloaded after ACK.

Check content:

```bash
cat downloads/bob_secret.txt
```

### 9.8 Unauthorized access test

Mallory tries to download Bob's file:

```bash
python -m secure_drop.client --user mallory --cert pki/mallory/mallory_cert.json --key pki/mallory/mallory_private_key.pem download <FILE_ID> --out downloads/mallory.txt
```

Expected: rejected with `not authorized for this file`. Server log should show an unauthorized download attempt.

### 9.9 One-time download test

After Bob has successfully downloaded the file once, run the same download command again:

```bash
python -m secure_drop.client --user bob --cert pki/bob/bob_cert.json --key pki/bob/bob_private_key.pem download <FILE_ID> --out downloads/bob_second.txt
```

Expected: rejected with `file already downloaded once`.

### 9.10 Expiration test

Upload a file with a 1-second expiration:

```bash
python -m secure_drop.client --user alice --cert pki/alice/alice_cert.json --key pki/alice/alice_private_key.pem upload --recipient bob --file test_files/alice_secret.txt --expires 1
```

Wait 2 seconds, then Bob tries to download the returned file ID:

```bash
python -m secure_drop.client --user bob --cert pki/bob/bob_cert.json --key pki/bob/bob_private_key.pem download <EXPIRED_FILE_ID> --out downloads/expired.txt
```

Expected: rejected with `file expired`.

### 9.11 Revocation test

Alice uploads a new file, then revokes it before Bob downloads:

```bash
python -m secure_drop.client --user alice --cert pki/alice/alice_cert.json --key pki/alice/alice_private_key.pem upload --recipient bob --file test_files/alice_secret.txt --expires 3600
python -m secure_drop.client --user alice --cert pki/alice/alice_cert.json --key pki/alice/alice_private_key.pem revoke <NEW_FILE_ID>
python -m secure_drop.client --user bob --cert pki/bob/bob_cert.json --key pki/bob/bob_private_key.pem download <NEW_FILE_ID> --out downloads/revoked.txt
```

Expected: Bob's download is rejected with `file revoked`.

## 10. Automated quick demonstration

A quick end-to-end demo is included:

```bash
./demo.sh
```

The script demonstrates CA creation, certificate issuance, server startup, Alice/Bob/Mallory registration, Alice uploading an encrypted file for Bob, Mallory being rejected, Bob listing the file, and Bob downloading/decrypting/verifying it.

The bonus tests for one-time download, expiration, and revocation are best run manually with the commands in sections 9.9, 9.10, and 9.11 so you can inspect each state transition and the server log.

## 11. Security limitations and possible countermeasures

This is an educational prototype, not production-ready security software.

Known limitations:

- **CA identity verification is simplified.** A real system would require stronger identity proofing and certificate lifecycle management.
- **No certificate revocation list.** If a client private key is compromised, old certificates remain valid until expiration. A CRL or OCSP-like check should be added.
- **Server metadata remains visible.** The server sees sender, recipient, file size, timing, status, and expiration. A stronger design could hide filenames/descriptions and reduce timing leakage, but routing metadata cannot be fully hidden from this server design.
- **Server can deny service or delete packages.** Zero-trust storage protects confidentiality and integrity verification, not availability.
- **Server can alter visible metadata.** Recipient signature verification detects important signed-field tampering, but the server can still lie about listing status. More sender/recipient-signed status receipts would improve accountability.
- **No persistent replay cache across server restarts.** Request replay cache is in memory. For stronger protection, persist recent request IDs until they expire.
- **No large-file chunking.** The current implementation sends whole encrypted packages in one protocol message. For very large files, explicit chunking with per-chunk hashes and a signed manifest should be added.
- **No password protection for private keys.** PEM keys are stored unencrypted for easier testing. A real implementation should encrypt private keys at rest.

## 12. Division of labor

This project was developed collaboratively by our group. The concrete contributions are as follows:

- **Ozan Yıldırım**: Handled the core cryptographic design, including certificate generation, the custom ECDH handshake, session key derivation, and AES-GCM encryption logic (`common.py`, `ca.py`, `handshake.py`).
- **Azra Çetintürk**: Implemented the server-side architecture and raw TCP socket networking, multithreaded request handling, zero-trust storage metadata management, strict sequence number framing, and the request replay protection mechanisms (`server.py`, `common.py`).
- **Helin Zeybek**: Developed the client command-line interface, end-to-end file upload/download flows, certificate validation checks against the CA, and integrated all bonus features such as one-time downloads, revocation, and encrypted notes (`client.py`, testing scripts).

## 13. Packaging



```text
OzanYildirim_AzraCetinturk_HelinZeybek_SecureFileDrop.zip
```
