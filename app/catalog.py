"""Single source of truth for algorithm metadata.

`GET /api/algorithms` serialises this catalogue. The frontend renders its
category tabs, algorithm lists, operation toggles, security badges and the
security information panel straight from this data, so algorithm definitions
are never duplicated in the client.
"""

from __future__ import annotations

from typing import Any, Literal

SecurityStatus = Literal[
    "recommended",
    "encoding",
    "educational",
    "legacy",
    "broken",
]


def _algorithm(
    *,
    id: str,
    name: str,
    category: str,
    operations: list[str],
    security_status: SecurityStatus,
    summary: str,
    security_info: dict[str, Any],
    default_operation: str | None = None,
    disabled: bool = False,
    disabled_reason: str | None = None,
) -> dict[str, Any]:
    """Build a catalogue entry with a consistent shape for every algorithm."""
    return {
        "id": id,
        "name": name,
        "category": category,
        "operations": operations,
        "default_operation": default_operation or (operations[0] if operations else None),
        "security_status": security_status,
        "disabled": disabled,
        "disabled_reason": disabled_reason,
        "description": summary,
        "security_info": security_info,
    }


ALGORITHM_CATALOG: dict[str, list[dict[str, Any]]] = {
    "encode": [
        _algorithm(
            id="base64",
            name="Base64",
            category="encode",
            operations=["encode", "decode"],
            security_status="encoding",
            summary="Binary-to-text encoding. Not encryption.",
            security_info={
                "type": "Encoding",
                "encryption": False,
                "reversible": True,
                "lossless": True,
                "provides": ["Transport safety", "Binary to text conversion"],
                "not_provided": ["Confidentiality", "Integrity", "Authentication"],
                "warning": "Base64 does NOT provide confidentiality. Anyone can decode it.",
            },
        ),
        _algorithm(
            id="hex",
            name="Hexadecimal",
            category="encode",
            operations=["encode", "decode"],
            security_status="encoding",
            summary="Byte-to-hexadecimal representation. Not encryption.",
            security_info={
                "type": "Encoding",
                "encryption": False,
                "reversible": True,
                "lossless": True,
                "provides": ["Readable byte representation", "Key and nonce display"],
                "not_provided": ["Confidentiality", "Integrity", "Authentication"],
                "warning": "Hexadecimal is a printable representation only. It hides nothing.",
            },
        ),
    ],
    "encryption": [
        _algorithm(
            id="aes",
            name="AES-256-GCM",
            category="encryption",
            operations=["encrypt", "decrypt"],
            security_status="recommended",
            summary="Symmetric authenticated encryption with a 256-bit key and a random 96-bit nonce.",
            security_info={
                "type": "Symmetric authenticated encryption (AEAD)",
                "key_size": "256-bit",
                "nonce_size": "96-bit (random, never reused with the same key)",
                "mode": "GCM (Galois/Counter Mode)",
                "authenticated": True,
                "provides": ["Confidentiality", "Integrity", "Authentication"],
                "not_provided": [],
                "warning": "Reusing a GCM nonce with the same key destroys both confidentiality and authenticity.",
                "notes": "Ciphertext always includes the 128-bit GCM authentication tag, so tampering is detected on decryption.",
            },
        ),
        _algorithm(
            id="chacha20",
            name="ChaCha20-Poly1305",
            category="encryption",
            operations=["encrypt", "decrypt"],
            security_status="recommended",
            summary="Symmetric authenticated encryption, fast and constant time on platforms without AES hardware.",
            security_info={
                "type": "Symmetric authenticated encryption (AEAD)",
                "key_size": "256-bit",
                "nonce_size": "96-bit",
                "authenticated": True,
                "provides": ["Confidentiality", "Integrity", "Authentication"],
                "not_provided": [],
                "warning": "Never reuse a (key, nonce) pair with ChaCha20-Poly1305.",
                "notes": "Always use the Poly1305 variant; raw ChaCha20 provides no integrity protection.",
            },
        ),
        _algorithm(
            id="rsa",
            name="RSA-2048 (OAEP)",
            category="encryption",
            operations=["generate_key_pair", "encrypt", "decrypt"],
            default_operation="generate_key_pair",
            security_status="recommended",
            summary="Asymmetric encryption with RSA-OAEP (MGF1, SHA-256) and freshly generated 2048-bit key pairs.",
            security_info={
                "type": "Asymmetric encryption",
                "key_size": "2048-bit",
                "padding": "OAEP with MGF1 and SHA-256",
                "authenticated": False,
                "provides": ["Confidentiality", "Public-key key distribution"],
                "not_provided": ["Integrity", "Authentication"],
                "warning": "Maximum plaintext is 190 bytes for a 2048-bit key. RSA cannot encrypt files or long messages; use a hybrid scheme or a symmetric cipher for bulk data.",
                "notes": "PKCS#1 v1.5 padding is intentionally not offered because it is vulnerable to Bleichenbacher style padding oracles.",
            },
        ),
        _algorithm(
            id="caesar",
            name="Caesar Cipher",
            category="encryption",
            operations=["encrypt", "decrypt"],
            security_status="educational",
            summary="Classical substitution cipher with a user supplied shift.",
            security_info={
                "type": "Classical substitution cipher",
                "key_size": "Shift value only",
                "authenticated": False,
                "provides": ["Demonstration of substitution ciphers"],
                "not_provided": ["Confidentiality", "Integrity", "Authentication"],
                "warning": "Educational only. Not cryptographically secure: only 25 meaningful keys exist and it is trivially broken by frequency analysis.",
            },
        ),
        _algorithm(
            id="des",
            name="DES",
            category="encryption",
            operations=[],
            security_status="legacy",
            disabled=True,
            disabled_reason=(
                "Encryption disabled. DES has a 56-bit effective key size and can be brute-forced in hours on commodity hardware. "
                "It must not be used in modern applications."
            ),
            summary="Legacy block cipher retained for education. Execution is disabled.",
            security_info={
                "type": "Symmetric block cipher (legacy)",
                "key_size": "56-bit effective (64 bits including parity bits)",
                "block_size": "64-bit",
                "authenticated": False,
                "provides": [],
                "not_provided": ["Confidentiality", "Integrity", "Authentication"],
                "warning": "LEGACY / INSECURE. The 56-bit key space is small enough to brute-force, and DES is also vulnerable to analytic attacks.",
                "notes": "Replacements: 3DES or AES. AES-256-GCM is the recommended choice.",
            },
        ),
    ],
    "hash": [
        _algorithm(
            id="md5",
            name="MD5",
            category="hash",
            operations=["generate"],
            security_status="broken",
            summary="128-bit legacy digest. Shown for education only.",
            security_info={
                "type": "One-way hash function (legacy)",
                "digest_size": "128-bit",
                "collision_resistant": False,
                "provides": ["Fast non-reversible digest", "Legacy checksum demonstration"],
                "not_provided": ["Collision resistance", "Password storage suitability"],
                "warning": "LEGACY / CRYPTOGRAPHICALLY BROKEN. Practical collision attacks exist, so MD5 must not be used for signatures, certificates or integrity where collision resistance matters.",
                "notes": "MD5 is also far too fast for password hashing. Use bcrypt.",
            },
        ),
        _algorithm(
            id="sha256",
            name="SHA-256",
            category="hash",
            operations=["generate"],
            security_status="recommended",
            summary="256-bit SHA-2 digest for integrity checks and general purpose hashing.",
            security_info={
                "type": "Cryptographic hash function (SHA-2 family)",
                "digest_size": "256-bit",
                "collision_resistant": True,
                "provides": ["Integrity verification", "Content fingerprinting"],
                "not_provided": ["Password storage (unsalted and far too fast)"],
                "warning": "Never store passwords with a plain SHA-2 hash. Use bcrypt.",
            },
        ),
        _algorithm(
            id="sha512",
            name="SHA-512",
            category="hash",
            operations=["generate"],
            security_status="recommended",
            summary="512-bit SHA-2 digest, a larger output than SHA-256 for the same algorithm family.",
            security_info={
                "type": "Cryptographic hash function (SHA-2 family)",
                "digest_size": "512-bit",
                "collision_resistant": True,
                "provides": ["Integrity verification", "Content fingerprinting"],
                "not_provided": ["Password storage (unsalted and far too fast)"],
                "warning": "Never store passwords with a plain SHA-2 hash. Use bcrypt.",
            },
        ),
        _algorithm(
            id="bcrypt",
            name="bcrypt",
            category="hash",
            operations=["generate", "verify"],
            security_status="recommended",
            summary="Adaptive password hashing with a configurable work factor and per-password salt.",
            security_info={
                "type": "Password hashing function",
                "digest_size": "184-bit output including salt",
                "collision_resistant": True,
                "provides": ["Password storage", "Slow hashing resists brute force", "Automatic salting"],
                "not_provided": [],
                "warning": "bcrypt truncates input at 72 bytes. Passwords are never logged, stored in plaintext or returned by this API.",
                "notes": "Cost is stored inside the hash, so raising the work factor later still verifies old hashes.",
            },
        ),
    ],
}


CATEGORY_ORDER: list[str] = ["encode", "encryption", "hash"]


def _copy_entry(entry: dict[str, Any]) -> dict[str, Any]:
    """Return a shallow copy of an entry with copied nested containers."""
    return {
        **entry,
        "operations": list(entry["operations"]),
        "security_info": dict(entry["security_info"]),
    }


def get_catalog() -> dict[str, list[dict[str, Any]]]:
    """Return the catalogue as a copy so callers cannot mutate the original."""
    return {category: [_copy_entry(entry) for entry in entries] for category, entries in ALGORITHM_CATALOG.items()}


def find_algorithm(category: str, algorithm_id: str) -> dict[str, Any] | None:
    """Look up a catalogue entry by category and algorithm id."""
    for entry in ALGORITHM_CATALOG.get(category, []):
        if entry["id"] == algorithm_id:
            return entry
    return None