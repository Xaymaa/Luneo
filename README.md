# Luneo

An end-to-end encrypted messaging system built from scratch in Python. Messages are encrypted on the sender's device and can only be decrypted by the intended recipient the server relays ciphertext it cannot read.

Luneo consists of a terminal client and a relay server communicating over TCP with a custom JSON protocol.

## Features

- **End-to-end encryption** hybrid RSA-4096 + AES-256-GCM. The server never sees plaintext.
- **Message signing** every message is signed with RSA-PSS and verified by both the server and the recipient.
- **Challenge–response authentication** proves key ownership at login without transmitting the private key.
- **Offline delivery** messages to offline users are queued server-side and delivered on their next login.
- **File transfer** images (`jpg`, `jpeg`, `png`) and video (`mp4`, `mov`, `gif`) up to 100 MB.
- **Replay protection** each message carries a unique ID; duplicates are rejected.
- **Optional TLS** protects connection metadata and verifies the server's identity.
- **Per-contact inbox** messages received while you're elsewhere are spooled locally and shown when you open that conversation.

## Installation

**Requirements:** Python 3.9+

```bash
git clone <repo-url>
cd luneo
pip install -r requirements-client.txt
```

Server-side only needs `cryptography`:

```bash
pip install -r requirements-server.txt
```

On Ubuntu you may hit PEP 668 ("externally managed environment"). Use a virtualenv:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements-client.txt
```

### Optional: install as a command

```bash
chmod +x luneo-client.py
ln -s "$(pwd)/luneo-client.py" ~/.local/bin/luneo
```

## Usage

### Client

```bash
# Plain TCP (local testing)
python3 luneo-client.py --host 127.0.0.1

# With TLS against a domain with a CA-signed certificate
python3 luneo-client.py --host luneo.example.com --tls

# With TLS against a self-signed certificate
python3 luneo-client.py --host 192.0.2.10 --tls --cert /path/to/server.crt
```

| Flag | Default | Description |
||||
| `--host` | `127.0.0.1` | Server hostname or IP |
| `--port` | `9941` | Server port |
| `--tls` | off | Enable TLS |
| `--cert` | none | CA certificate to pin (self-signed setups) |

### Server

```bash
# Plain TCP
python3 luneo-server.py

# With TLS
python3 luneo-server.py --tls \
 --cert /etc/letsencrypt/live/luneo.example.com/fullchain.pem \
 --key /etc/letsencrypt/live/luneo.example.com/privkey.pem
```

### In-app commands

| Command | Action |
|||
| `/c` | Leave the conversation, choose another contact |
| `/q` | Quit |
| `/i:path/to/file` | Send an image |
| `/v:path/to/file` | Send a video |

On first launch, choose **R** to register (generates a new keypair) or **L** to log in with an existing one.

## How it works

### Registration

The client generates an RSA-4096 keypair locally. The private key stays on the device; the public key is uploaded to the server, which stores it under the chosen username. The server rejects usernames already taken.

### Login

The server proves you hold the private key without you sending it:

1. Server generates 32 random bytes and encrypts them with your stored public key.
2. Client decrypts with its private key and returns the value.
3. Server compares in constant time. Match → authenticated.

The authenticated username is bound to the connection. Every subsequent message is checked against it, so a logged-in user cannot claim to be someone else.

### Sending a message

RSA alone can't encrypt more than a few hundred bytes and is slow for bulk data, so Luneo uses hybrid encryption:

1. Generate a fresh random AES-256 key for this message.
2. Encrypt the content with **AES-256-GCM** (fast, any size, tamper-evident).
3. Encrypt that AES key with the **recipient's RSA public key** (RSA-OAEP).
4. Build an envelope containing the wrapped key, nonce, ciphertext, GCM tag, sender, recipient, format, and a unique message ID.
5. Sign the envelope with the **sender's private key** (RSA-PSS).

A new AES key per message means compromising one message doesn't expose any other.

### Receiving

1. Verify the signature against the sender's public key (fetched from the server on first contact, then cached locally).
2. Check the message ID hasn't been seen before.
3. Unwrap the AES key with your private key.
4. Decrypt with AES-GCM this also verifies the tag, so tampering is detected.

If the sender's public key isn't cached yet, the message is held in memory, the key is requested, and verification resumes when it arrives.

### What the server can and can't do

**Can:** route messages, store public keys, queue messages for offline users, verify signatures, reject spoofed senders.

**Cannot:** read message content. It holds no private keys, and the AES key inside each envelope is encrypted to the recipient.

## Protocol

Messages are JSON objects sent over TCP with **4-byte big-endian length-prefix framing**. TCP is a byte stream with no message boundaries framing guarantees one message in equals one message out, regardless of how the network splits or merges packets.

### Client → server

| Code | Name | Purpose |
||||
| 10 | Message | Encrypted message for another user |
| 11 | Pending Messages Request | Request queued messages |
| 12 | User Authentication | Register or begin login |
| 13 | Challenge Response | Answer to the login challenge |
| 14 | Public Key Request | Fetch a contact's public key |
| 15 | Pending Notification Request | Ask how many messages are waiting |

### Server → client

| Code | Name | Purpose |
||||
| 20 | Server Info | Errors and status messages |
| 21 | Pending Messages Notification | Per-contact unread counts |
| 22 | Pending Messages Response | Delivery of queued messages |
| 23 | Authentication Success | |
| 24 | Authentication Fail | Includes a failure code |
| 25 | Challenge Query | Encrypted challenge for login |
| 26 | Public Key Response | A contact's public key |

Every client message carries a base64 RSA-PSS signature over the rest of the envelope.

## Storage layout

### Client (`~/.luneo/`)

```
~/.luneo/
└── <username>/
  ├── <username>.key     private key (never leaves the device)
  ├── <username>.pub     public key
  ├── known_ids.txt      seen message IDs, for replay protection
  └── contacts/
    └── <contact>/
      ├── <contact>.pub  cached public key
      ├── image/     received images
      ├── video/     received videos
      └── pending/    messages received while you were elsewhere
        ├── pending.txt
        ├── image/
        └── video/
```

### Server (`user_data/`)

```
user_data/
└── <username>/
  ├── <username>.pub     public key
  └── pending/
    └── pending_<sender>.json  queued ciphertext, deleted after delivery
```

The server stores only public keys and encrypted envelopes.

## TLS

TLS and end-to-end encryption solve different problems and stack together:

- **End-to-end encryption** hides message _content_ from everyone including the server.
- **TLS** hides _metadata_ (usernames, timing, message sizes) from network observers and lets clients verify they're talking to the real server.

### Let's Encrypt

```bash
sudo certbot certonly --standalone -d luneo.example.com
```

Use `fullchain.pem` as `--cert` it includes the intermediate certificate. Certificates renew automatically; add a deploy hook so the server picks up the new one:

```bash
# /etc/letsencrypt/renewal-hooks/deploy/luneo.sh
#!/bin/bash
systemctl restart luneo
```

Clients need no changes across renewals they trust the CA root, not the individual certificate.

### Self-signed

```bash
openssl req -x509 -newkey rsa:4096 -sha256 -days 3650 -nodes \
 -keyout luneo.key -out luneo.crt \
 -subj "/CN=luneo" -addext "subjectAltName=IP:203.0.113.10"
```

Distribute `luneo.crt` (never the key) to clients and pass it with `--cert`. The client pins that exact certificate, which is stronger than CA-based trust but breaks when the certificate rotates.

### macOS note

If a Mac client reports `unable to get local issuer certificate`, Python's CA bundle isn't installed. Run the bundled installer:

```bash
/Applications/Python\ 3.12/Install\ Certificates.command
```

or `pip3 install --upgrade certifi`.

## Security design

**Threat model.** Luneo assumes the server is untrusted for message content. A compromised server can observe who talks to whom and when, but cannot read messages, forge them, or replay them undetected.
