# CipherForge Backend

**Encode. Encrypt. Hash.**

CipherForge is a cryptography toolkit built for education and portfolio use. This
repository contains the FastAPI backend that powers the single-page frontend.

Every cryptographic primitive is delegated to `cryptography` and `bcrypt`.
CipherForge implements no block cipher, stream cipher, padding scheme or hash
function of its own.

---

## Table of contents

- [Project overview](#project-overview)
- [Architecture](#architecture)
- [Installation](#installation)
- [Running the server](#running-the-server)
- [API endpoints](#api-endpoints)
- [Supported algorithms](#supported-algorithms)
- [Security considerations](#security-considerations)
- [Why AES-GCM is preferred](#why-aes-gcm-is-preferred)
- [Why DES is legacy](#why-des-is-legacy)
- [Why MD5 is legacy](#why-md5-is-legacy)
- [RSA limitations](#rsa-limitations)
- [Input limits](#input-limits)
- [Testing](#testing)
- [Example API requests](#example-api-requests)

---

## Project overview

| Layer | Responsibility |
| --- | --- |
| `app/api` | HTTP only: status codes, request dispatch, response shaping |
| `app/schemas` | Pydantic validation, size limits, response models |
| `app/encoding` | Base64 and hexadecimal encodings |
| `app/crypto` | AES-256-GCM, ChaCha20-Poly1305, RSA-OAEP, Caesar, DES metadata |
| `app/hashing` | MD5, SHA-256, SHA-512, bcrypt |
| `app/errors.py` | Transport-agnostic domain errors |
| `app/catalog.py` | Algorithm metadata that backs `GET /api/algorithms` |

The dependency rule is strictly one-directional:

```text
Frontend
   ↓
API routes            app/api/*
   ↓
Schemas / validation  app/schemas/*
   ↓
Service layer         app/encoding/*, app/crypto/*, app/hashing/*
   ↓
Established libraries cryptography, bcrypt, hashlib, secrets
```

A route function never performs cryptographic work directly. For example
`app/api/encryption.py` validates the request, calls `app.crypto.aes.encrypt`,
and formats the result. All AES behaviour lives in `app/crypto/aes.py`.

---

## Architecture

```text
CipherVault-Backend/
├── app/
│   ├── main.py              FastAPI app, routers, exception handlers, CORS
│   ├── catalog.py           Algorithm metadata (single source of truth)
│   ├── errors.py            Domain errors shared by all services
│   ├── api/
│   │   ├── encode.py        POST /api/encode
│   │   ├── encryption.py    POST /api/encryption
│   │   ├── hash.py          POST /api/hash, POST /api/hash/bcrypt/verify
│   │   └── algorithms.py    GET /api/algorithms
│   ├── crypto/
│   │   ├── aes.py           AES-256-GCM
│   │   ├── chacha20.py      ChaCha20-Poly1305
│   │   ├── rsa.py           RSA-2048 OAEP
│   │   ├── caesar.py        Caesar cipher (educational)
│   │   └── des.py           DES metadata, execution disabled
│   ├── encoding/
│   │   ├── base64.py
│   │   └── hex.py
│   ├── hashing/
│   │   ├── md5.py
│   │   ├── sha256.py
│   │   ├── sha512.py
│   │   └── bcrypt.py
│   └── schemas/
│       └── crypto.py        Request/response models and limits
├── tests/
├── requirements.txt
└── README.md
```

`app/errors.py`, `app/catalog.py` and `app/api/algorithms.py` are the only
additions to the original layout. `errors.py` keeps FastAPI out of the service
modules, `catalog.py` holds metadata rather than HTTP concerns, and
`algorithms.py` serves the frontend's single source of truth.

---

## Installation

Requires Python 3.11 or newer (3.14 is verified).

```bash
cd CipherVault-Backend

python3 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate

pip install --upgrade pip
pip install -r requirements.txt
```

### Dependencies

| Package | Version | Purpose |
| --- | --- | --- |
| `fastapi` | 0.141.1 | ASGI web framework and OpenAPI generation |
| `uvicorn` | 0.38.0 | ASGI server |
| `cryptography` | 49.0.0 | AES-GCM, ChaCha20-Poly1305, RSA-OAEP, PEM handling |
| `bcrypt` | 5.0.0 | Password hashing |
| `pydantic` | 2.13.4 | Request validation |

`hashlib` and `secrets` ship with CPython and are used for SHA-2, MD5 and
secure randomness. No other runtime dependency is added.

---

## Running the server

```bash
source .venv/bin/activate
uvicorn app.main:app --reload
```

The API is then available at:

| URL | Purpose |
| --- | --- |
| <http://127.0.0.1:8000/docs> | Swagger UI, interactive endpoint testing |
| <http://127.0.0.1:8000/redoc> | ReDoc reference |
| <http://127.0.0.1:8000/openapi.json> | OpenAPI 3.1 schema |
| <http://127.0.0.1:8000/api/health> | Health check |

### CORS

The Vite dev server origins (`http://localhost:5173`, `http://127.0.0.1:5173`,
and the `4173` preview ports) are allowed by default. Override for other
deployments:

```bash
export CORS_ORIGINS="https://cipherforge.example"
uvicorn app.main:app --reload
```

Credentials are never allowed through CORS, because CipherForge has no
cookie-based authentication.

---

## API endpoints

### `GET /api/health`

```json
{"status": "ok", "service": "cipherforge", "version": "1.0.0"}
```

### `POST /api/encode`

Base64 and hexadecimal encode/decode.

```json
{"algorithm": "base64", "operation": "encode", "input": "CipherForge"}
```

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `algorithm` | `"base64"` \| `"hex"` | yes | |
| `operation` | `"encode"` \| `"decode"` | yes | |
| `input` | string | yes | 1 character to 1 MiB |

### `POST /api/encryption`

```json
{"algorithm": "aes", "operation": "encrypt", "input": "Attack at dawn"}
```

| Field | Type | Required when | Notes |
| --- | --- | --- | --- |
| `algorithm` | `aes` \| `chacha20` \| `rsa` \| `caesar` \| `des` | always | |
| `operation` | `encrypt` \| `decrypt` \| `generate_key_pair` | always | `generate_key_pair` is RSA only |
| `input` | string | encrypting | Plaintext |
| `ciphertext` | string | decrypting | Base64 ciphertext |
| `key` | string | AES/ChaCha20 decrypt | Hexadecimal |
| `nonce` | string | AES/ChaCha20 decrypt | Hexadecimal |
| `public_key` | string | RSA encrypt | PEM |
| `private_key` | string | RSA decrypt | PEM |
| `shift` | integer | Caesar | Wraps around 26 |
| `key_size` | integer | RSA keygen | 2048-4096, default 2048 |

On encryption, AES and ChaCha20 generate a fresh key and nonce automatically and
return them. On decryption the caller supplies `ciphertext`, `key` and `nonce`.

### `POST /api/hash`

```json
{"algorithm": "sha256", "input": "abc"}
```

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `algorithm` | `md5` \| `sha256` \| `sha512` \| `bcrypt` | yes | |
| `operation` | `"generate"` | no | Verification uses the endpoint below |
| `input` | string | yes | Password for bcrypt, text otherwise |
| `work_factor` | integer | no | bcrypt only, 4-31, default 12 |

### `POST /api/hash/bcrypt/verify`

```json
{"password": "s3cret-pass", "hash": "$2b$12$..."}
```

Returns `{"success": true, "algorithm": "bcrypt", "operation": "verify", "verified": true|false}`.
A wrong password is a `200` with `"verified": false`, not an error, because
"these credentials do not match" is a valid answer. A malformed hash is a `400`.

### `GET /api/algorithms`

Returns every algorithm with its operations, security status, warnings and
information-panel content. The frontend renders its tabs, algorithm lists,
badges and panels from this response so the client holds no duplicated
definitions.

```json
{
  "categories": ["encode", "encryption", "hash"],
  "encode": [{"id": "base64", "name": "Base64", "operations": ["encode", "decode"], "security_status": "encoding", "disabled": false, "security_info": {"type": "Encoding", "encryption": false}}],
  "encryption": [{"id": "aes", "name": "AES-256-GCM", "operations": ["encrypt", "decrypt"], "security_status": "recommended", "disabled": false}],
  "hash": [{"id": "md5", "name": "MD5", "operations": ["generate"], "security_status": "broken", "disabled": false}]
}
```

### Error format

Every failure uses the same envelope. Stack traces, filesystem paths and
internal exception text are never included.

```json
{
  "success": false,
  "error": {
    "code": "INVALID_INPUT",
    "message": "Invalid Base64 input. Expected only A-Z, a-z, 0-9, '+', '/' and correct '=' padding."
  }
}
```

| Code | HTTP | Meaning |
| --- | --- | --- |
| `INVALID_INPUT` | 400 | Missing, malformed or out-of-range field |
| `INVALID_ENCODING` | 400 | Malformed Base64 or hexadecimal |
| `DECRYPTION_FAILED` | 400 | Authentication failed, wrong key, or tampered data |
| `NONCE_REUSE` | 400 | A GCM nonce would have repeated under the same key |
| `PLAINTEXT_TOO_LARGE` | 400 | Plaintext exceeds the RSA-OAEP capacity |
| `PASSWORD_TOO_LONG` | 400 | Password exceeds bcrypt's 72-byte input limit |
| `ALGORITHM_DISABLED` | 400 | Algorithm is intentionally not executable (DES) |
| `UNSUPPORTED_OPERATION` | 400 | Algorithm does not offer that operation |
| `INTERNAL_ERROR` | 500 | Unexpected failure, details withheld |

---

## Supported algorithms

### Encode

| Algorithm | Operations | Status |
| --- | --- | --- |
| Base64 | encode, decode | Encoding, not encryption |
| Hexadecimal | encode, decode | Encoding, not encryption |

### Encryption

| Algorithm | Operations | Status |
| --- | --- | --- |
| AES-256-GCM | encrypt, decrypt | Recommended |
| ChaCha20-Poly1305 | encrypt, decrypt | Recommended |
| RSA-2048 (OAEP, MGF1, SHA-256) | generate_key_pair, encrypt, decrypt | Recommended, 190-byte limit |
| Caesar cipher | encrypt, decrypt | Educational, not secure |
| DES | none, execution disabled | Legacy, insecure |

### Hash

| Algorithm | Operations | Status |
| --- | --- | --- |
| MD5 | generate | Legacy, cryptographically broken |
| SHA-256 | generate | Recommended |
| SHA-512 | generate | Recommended |
| bcrypt | generate, verify | Recommended for passwords |

---

## Security considerations

**No hand-written cryptography.** AES, ChaCha20, Poly1305, RSA, OAEP, MGF1 and
bcrypt all come from `cryptography` and `bcrypt`. CipherForge writes no cipher
primitives.

**Secure randomness.** Every key, nonce and salt is generated with
`secrets.token_bytes()`, which reads from the operating system CSPRNG. The
`random` module is never used for security-relevant values.

**No nonce reuse.** AES-GCM nonces are 96 bits and randomly generated per
request. `app/crypto/aes.py` keeps an in-process ledger keyed by a SHA-256
fingerprint of the key and raises `NONCE_REUSE` if a (key, nonce) pair repeats.
A test covers this behaviour.

**Authenticated encryption only.** Both symmetric ciphers are AEAD
constructions, so the 128-bit tag is verified on every decryption and any
modification is rejected with `DECRYPTION_FAILED`.

**Passwords.** Plaintext passwords are used transiently and are never logged,
never persisted and never returned. Only the bcrypt hash or a boolean match
reaches the client. bcrypt's 72-byte input limit is validated explicitly rather
than silently truncated, because truncation would let two different long
passwords authenticate each other.

**Key handling.** Keys and nonces are returned to the caller because CipherForge
is an interactive toolkit with no server-side key store. They are never written
to logs, never hardcoded and never committed.

**Error hygiene.** Exceptions are converted to structured JSON by the handlers
in `app/main.py`. Unexpected errors return a generic `INTERNAL_ERROR` and are
logged by exception class name only. Validation summaries deliberately omit
submitted values so passwords and key material cannot leak through an error.

**No ECB.** AES is only offered in GCM mode. ECB is never implemented because it
leaks plaintext structure.

**No PKCS#1 v1.5 for RSA.** Only OAEP is available. PKCS#1 v1.5 encryption is
vulnerable to Bleichenbacher-style padding oracles.

### Why AES-GCM is preferred

AES is a block cipher, so the mode of operation decides its safety. GCM turns
AES into an authenticated stream cipher and supplies three properties at once:

- **Confidentiality.** The counter-mode keystream hides plaintext.
- **Integrity.** The GHASH tag detects any change to the ciphertext.
- **Authentication.** The tag proves the ciphertext came from a holder of the
  key, so an attacker cannot forge messages.

A 256-bit key gives a security margin far beyond brute-force reach, and hardware
AES instructions make it fast. GCM's only real weakness is nonce reuse, which
leaks the authentication subkey and allows tag forgery. CipherForge generates a
fresh random nonce for every encryption and refuses to repeat one under the same
key.

### Why DES is legacy

DES uses a 64-bit key of which only 56 bits carry entropy; the other 8 bits are
fixed parity. That key space is exhaustible in hours on commodity hardware, so
DES provides no practical confidentiality. Its 64-bit block size also causes
collisions after roughly 2^32 blocks under one key.

Presenting DES as usable would defeat the educational goal, so
`app/crypto/des.py` exposes its security facts and every encrypt/decrypt call
raises `ALGORITHM_DISABLED`. `GET /api/algorithms` reports it with
`"operations": []` and `"disabled": true`, and the frontend renders the reason
instead of an input form. Modern replacements are 3AES for compatibility and
AES-256-GCM for new systems.

### Why MD5 is legacy

MD5 has practical collision attacks: two different inputs can be crafted to
produce the same digest, and chosen-prefix collisions are cheap enough to mount
against real systems. A digest is therefore not evidence that data was produced
by a trusted party. MD5 must not be used for signatures, certificates,
anti-tampering or integrity guarantees.

MD5 is also far too fast for password hashing, since GPUs try billions of
candidates per second. CipherForge still ships it because it is a useful teaching
example of a broken digest, but the API marks it `"security_status": "broken"`
and uses `usedforsecurity=False` so the intent is explicit and the call remains
valid on FIPS-restricted builds.

### RSA limitations

RSA is a key transport primitive, not a bulk cipher. With a 2048-bit modulus and
OAEP/SHA-256, padding consumes 2 x 32 + 2 = 66 bytes, so the maximum plaintext is
**190 bytes**. Encrypting anything larger fails with `PLAINTEXT_TOO_LARGE`.

RSA is also 1000x slower than a symmetric cipher and its security rests entirely
on key distribution. The correct pattern is hybrid encryption: generate a random
AES key, encrypt the data with AES-GCM, then encrypt that key with RSA-OAEP.

CipherForge also does not claim RSA provides integrity. OAEP is not a MAC, so a
message could be replayed; sign the ciphertext or use AES-GCM if you need
authenticated encryption.

---

## Input limits

| Input | Limit |
| --- | --- |
| Text (encode, hash, encryption input) | 1 MiB (1,048,576 bytes UTF-8) |
| Password | 1,024 characters, then bcrypt's 72-byte limit applies |
| RSA PEM key | 16,384 characters |
| AES or ChaCha20 key | 512 characters, must decode to 32 bytes |
| AES or ChaCha20 nonce | 256 characters, must decode to 12 bytes |
| Base64 ciphertext | 2,097,152 characters |
| Caesar shift | -1,000,000 to 1,000,000, normalised mod 26 |
| bcrypt work factor | 4 to 31, default 12 |

Limits are declared in `app/schemas/crypto.py`. Unknown request fields are
rejected (`extra="forbid"`) so a typo cannot silently change behaviour.

---

## Testing

163 tests cover the service layer and the HTTP layer.

```bash
cd CipherVault-Backend
source .venv/bin/activate

pip install pytest httpx

python -m pytest -q                       # whole suite
python -m pytest tests/test_hashing.py    # single module
python -m pytest -v --tb=short            # verbose, short tracebacks
python -m pytest --cov=app                # with coverage, if pytest-cov is installed
```

Coverage by area:

| File | What is verified |
| --- | --- |
| `test_encoding.py` | Base64 and hex encode/decode, known values, invalid input, non-UTF-8 payloads |
| `test_crypto_symmetric.py` | AES and ChaCha20 round trips, wrong key, wrong nonce, tampered ciphertext, invalid key sizes, nonce reuse refusal |
| `test_crypto_rsa.py` | Key generation, PEM format, 2048-bit size, round trip, 190-byte boundary, oversized plaintext, invalid and non-RSA keys, wrong private key |
| `test_caesar.py` | Known vectors, wrap-around, case and punctuation, every shift round trip |
| `test_des.py` | Legacy facts, disabled encrypt/decrypt |
| `test_hashing.py` | MD5, SHA-256 and SHA-512 published known-answer vectors, bcrypt hashing, verification, wrong password, salting, 72-byte limit |
| `test_api.py` | Every endpoint, status codes, error envelopes, size limits, and that passwords never appear in responses |

Known-answer vectors used:

| Input | Algorithm | Expected digest |
| --- | --- | --- |
| `""` | MD5 | `d41d8cd98f00b204e9800998ecf8427e` |
| `"abc"` | MD5 | `900150983cd24fb0d6963f7d28e17f72` |
| `""` | SHA-256 | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| `"abc"` | SHA-256 | `ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad` |
| `"abc"` | SHA-512 | `ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a...` |
| `""` | SHA-512 | `cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce...` |

bcrypt is tested behaviourally rather than against a vector, because it salts
every hash. Correctness is confirmed by generating a hash and verifying the
matching and non-matching passwords.

---

## Example API requests

Health check:

```bash
curl http://127.0.0.1:8000/api/health
```

Base64 round trip:

```bash
curl -X POST http://127.0.0.1:8000/api/encode \
  -H 'Content-Type: application/json' \
  -d '{"algorithm":"base64","operation":"encode","input":"CipherForge"}'
# {"success":true,"algorithm":"base64","operation":"encode","output":"Q2lwaGVyRm9yZ2U="}
```

Hexadecimal:

```bash
curl -X POST http://127.0.0.1:8000/api/encode \
  -H 'Content-Type: application/json' \
  -d '{"algorithm":"hex","operation":"decode","input":"0x61 0x62 0x63"}'
# {"success":true,"algorithm":"hex","operation":"decode","output":"abc"}
```

AES-256-GCM, encrypt then decrypt:

```bash
curl -X POST http://127.0.0.1:8000/api/encryption \
  -H 'Content-Type: application/json' \
  -d '{"algorithm":"aes","operation":"encrypt","input":"Attack at dawn"}'
```

```json
{
  "success": true,
  "algorithm": "aes",
  "operation": "encrypt",
  "ciphertext": "K1oQ4YQ2k1Fh9N0y1a1CkA==",
  "key": "a061c7bb64cafd00e9136ce46551a7771f13b3a98870ad292ed37d5ee7210f56",
  "nonce": "f6627e8467e3108e020b62bb"
}
```

```bash
curl -X POST http://127.0.0.1:8000/api/encryption \
  -H 'Content-Type: application/json' \
  -d '{
        "algorithm": "aes",
        "operation": "decrypt",
        "ciphertext": "K1oQ4YQ2k1Fh9N0y1a1CkA==",
        "key": "a061c7bb64cafd00e9136ce46551a7771f13b3a98870ad292ed37d5ee7210f56",
        "nonce": "f6627e8467e3108e020b62bb"
      }'
# {"success":true,"algorithm":"aes","operation":"decrypt","output":"Attack at dawn"}
```

ChaCha20-Poly1305 uses the same shape with `"algorithm":"chacha20"`.

RSA key pair, then encrypt and decrypt:

```bash
curl -X POST http://127.0.0.1:8000/api/encryption \
  -H 'Content-Type: application/json' \
  -d '{"algorithm":"rsa","operation":"generate_key_pair"}'
```

```bash
curl -X POST http://127.0.0.1:8000/api/encryption \
  -H 'Content-Type: application/json' \
  -d '{"algorithm":"rsa","operation":"encrypt","input":"Short secret","public_key":"-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n"}'
```

```bash
curl -X POST http://127.0.0.1:8000/api/encryption \
  -H 'Content-Type: application/json' \
  -d '{"algorithm":"rsa","operation":"decrypt","ciphertext":"<base64>","private_key":"-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----\n"}'
```

Caesar cipher:

```bash
curl -X POST http://127.0.0.1:8000/api/encryption \
  -H 'Content-Type: application/json' \
  -d '{"algorithm":"caesar","operation":"encrypt","input":"Hello, World!","shift":3}'
# {"success":true,...,"output":"Khoor, Zruog!","work_note":"Educational classical cipher..."}
```

Hashing:

```bash
curl -X POST http://127.0.0.1:8000/api/hash \
  -H 'Content-Type: application/json' \
  -d '{"algorithm":"sha256","input":"abc"}'
# {"success":true,"algorithm":"sha256","operation":"generate","hash":"ba7816bf...15ad","digest_size_bits":256,"work_factor":null}
```

bcrypt password hashing and verification:

```bash
curl -X POST http://127.0.0.1:8000/api/hash \
  -H 'Content-Type: application/json' \
  -d '{"algorithm":"bcrypt","input":"s3cret-pass","work_factor":12}'
# {"success":true,"algorithm":"bcrypt","operation":"generate","hash":"$2b$12$...","digest_size_bits":480,"work_factor":12}
```

```bash
curl -X POST http://127.0.0.1:8000/api/hash/bcrypt/verify \
  -H 'Content-Type: application/json' \
  -d '{"password":"s3cret-pass","hash":"$2b$12$..."}'
# {"success":true,"algorithm":"bcrypt","operation":"verify","verified":true}
```

DES is intentionally rejected:

```bash
curl -X POST http://127.0.0.1:8000/api/encryption \
  -H 'Content-Type: application/json' \
  -d '{"algorithm":"des","operation":"encrypt","input":"Hello"}'
```

```json
{
  "success": false,
  "error": {
    "code": "INVALID_INPUT",
    "message": "DES execution is disabled. DES has a 56-bit effective key size, can be brute-forced in hours on commodity hardware, and must not be used in modern applications. Use AES-256-GCM instead."
  }
}
```

---

## Scope of version 1

CipherForge is intentionally a local, client-facing toolkit. There are no user
accounts, no database, no payments, no cloud storage and no AI features. Every
operation is stateless and runs in the request.

## License

MIT. See [LICENSE](LICENSE).