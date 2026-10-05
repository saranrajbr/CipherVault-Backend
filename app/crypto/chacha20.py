"""ChaCha20-Poly1305 authenticated encryption service.

CipherForge only offers the AEAD construction. Raw ChaCha20 is a stream cipher
without integrity protection, so encrypting with it alone would leave ciphertext
malleable and forgeable.
"""

from __future__ import annotations

import base64
import binascii
import secrets
from dataclasses import dataclass

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from ..errors import DecryptionError, InvalidInputError

KEY_SIZE_BYTES = 32
NONCE_SIZE_BYTES = 12
POLY1305_TAG_SIZE_BYTES = 16


@dataclass(frozen=True, slots=True)
class ChaChaParameters:
    """A freshly generated ChaCha20 key and nonce pair."""

    key: bytes
    nonce: bytes

    @property
    def key_hex(self) -> str:
        """Key as lowercase hexadecimal, for frontend display."""
        return self.key.hex()

    @property
    def nonce_hex(self) -> str:
        """Nonce as lowercase hexadecimal, for frontend display."""
        return self.nonce.hex()


@dataclass(frozen=True, slots=True)
class ChaChaResult:
    """Output of a ChaCha20-Poly1305 encryption operation."""

    ciphertext_b64: str
    key_hex: str
    nonce_hex: str


def generate_parameters() -> ChaChaParameters:
    """Generate a cryptographically secure 256-bit key and 96-bit nonce."""
    return ChaChaParameters(
        key=secrets.token_bytes(KEY_SIZE_BYTES),
        nonce=secrets.token_bytes(NONCE_SIZE_BYTES),
    )


def decode_hex_field(value: str, expected_bytes: int, field_name: str) -> bytes:
    """Decode a hexadecimal request field into exactly ``expected_bytes`` bytes.

    Args:
        value: The hexadecimal string supplied by the client.
        expected_bytes: Required byte length of the decoded value.
        field_name: Human readable field name used in the error message.

    Returns:
        The decoded bytes.

    Raises:
        InvalidInputError: If the field is not valid hexadecimal or has the
            wrong length.
    """
    candidate = value.strip()
    if candidate.lower().startswith("0x"):
        candidate = candidate[2:]
    try:
        raw = bytes.fromhex(candidate)
    except (binascii.Error, ValueError) as exc:
        raise InvalidInputError(f"Invalid {field_name}: expected a hexadecimal string.") from exc
    if len(raw) != expected_bytes:
        raise InvalidInputError(
            f"Invalid {field_name}: expected {expected_bytes} bytes "
            f"({expected_bytes * 2} hexadecimal characters), received {len(raw)} bytes."
        )
    return raw


def decode_ciphertext(value: str) -> bytes:
    """Decode Base64 ciphertext supplied by the client.

    Args:
        value: Standard Base64 ciphertext including the Poly1305 tag.

    Returns:
        The decoded ciphertext bytes.

    Raises:
        InvalidInputError: If the value is not valid Base64.
    """
    candidate = "".join(character for character in value.strip() if not character.isspace())
    if not candidate:
        raise InvalidInputError("Invalid ciphertext: value is empty.")
    try:
        return base64.b64decode(candidate, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise InvalidInputError("Invalid ciphertext: expected valid Base64.") from exc


def encrypt(plaintext: str, key: bytes, nonce: bytes) -> ChaChaResult:
    """Encrypt UTF-8 text with ChaCha20-Poly1305.

    Args:
        plaintext: Text to encrypt.
        key: 32-byte key.
        nonce: 12-byte nonce, unique for this key.

    Returns:
        The Base64 ciphertext (with appended Poly1305 tag) plus key and nonce.

    Raises:
        InvalidInputError: If the key or nonce length is incorrect.
    """
    if len(key) != KEY_SIZE_BYTES:
        raise InvalidInputError(
            f"Invalid key: ChaCha20-Poly1305 requires a {KEY_SIZE_BYTES}-byte key."
        )
    if len(nonce) != NONCE_SIZE_BYTES:
        raise InvalidInputError(
            f"Invalid nonce: ChaCha20-Poly1305 requires a {NONCE_SIZE_BYTES}-byte nonce."
        )
    sealed = ChaCha20Poly1305(key).encrypt(nonce, plaintext.encode("utf-8"), None)
    return ChaChaResult(
        ciphertext_b64=base64.b64encode(sealed).decode("ascii"),
        key_hex=key.hex(),
        nonce_hex=nonce.hex(),
    )


def decrypt(ciphertext_b64: str, key: bytes, nonce: bytes) -> str:
    """Decrypt and authenticate ChaCha20-Poly1305 ciphertext.

    Args:
        ciphertext_b64: Base64 ciphertext including the Poly1305 tag.
        key: The 32-byte key used to encrypt.
        nonce: The 12-byte nonce used to encrypt.

    Returns:
        The decrypted UTF-8 text.

    Raises:
        DecryptionError: If authentication fails, or if the key, nonce or
            ciphertext is incorrect.
    """
    if len(key) != KEY_SIZE_BYTES:
        raise InvalidInputError(
            f"Invalid key: ChaCha20-Poly1305 requires a {KEY_SIZE_BYTES}-byte key."
        )
    if len(nonce) != NONCE_SIZE_BYTES:
        raise InvalidInputError(
            f"Invalid nonce: ChaCha20-Poly1305 requires a {NONCE_SIZE_BYTES}-byte nonce."
        )
    ciphertext = decode_ciphertext(ciphertext_b64)
    if len(ciphertext) < POLY1305_TAG_SIZE_BYTES:
        raise DecryptionError(
            "Invalid ciphertext: too short to contain a Poly1305 authentication tag."
        )
    try:
        plaintext = ChaCha20Poly1305(key).decrypt(nonce, ciphertext, None)
    except InvalidTag as exc:
        raise DecryptionError(
            "Authentication failed: the ciphertext, key or nonce is incorrect, or the data was tampered with."
        ) from exc
    try:
        return plaintext.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise DecryptionError("Decryption succeeded but the result is not valid UTF-8 text.") from exc