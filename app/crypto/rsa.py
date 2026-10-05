"""RSA-2048 key generation and RSA-OAEP encryption service.

Design constraints:
    * Only OAEP padding is offered. RSAES-PKCS1-v1_5 is vulnerable to padding
      oracle attacks and is intentionally unsupported.
    * OAEP with MGF1 and SHA-256 on a 2048-bit modulus leaves at most
      2 * 32 + 2 = 66 bytes of padding overhead, so a single message is limited
      to 190 bytes. RSA is a key transport primitive, not a bulk cipher.
"""

from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PrivateFormat,
    PublicFormat,
)

from ..errors import DecryptionError, InvalidInputError

KEY_SIZE_BITS = 2048
HASH_ALGORITHM = hashes.SHA256()
_OAEP_PADDING = padding.OAEP(
    mgf=padding.MGF1(algorithm=hashes.SHA256()),
    algorithm=hashes.SHA256(),
    label=None,
)
_DIGEST_SIZE_BYTES = 32
MAX_PLAINTEXT_BYTES = KEY_SIZE_BITS // 8 - 2 * _DIGEST_SIZE_BYTES - 2


@dataclass(frozen=True, slots=True)
class RsaKeyPair:
    """An RSA key pair serialised as PEM text for transport."""

    public_key_pem: str
    private_key_pem: str


def maximum_plaintext_bytes(key_size_bits: int = KEY_SIZE_BITS) -> int:
    """Return the largest plaintext an OAEP/SHA-256 block can carry.

    Args:
        key_size_bits: Modulus size in bits.

    Returns:
        Maximum plaintext length in bytes.
    """
    return key_size_bits // 8 - 2 * _DIGEST_SIZE_BYTES - 2


def generate_key_pair(key_size: int = KEY_SIZE_BITS) -> RsaKeyPair:
    """Generate a fresh RSA key pair.

    Args:
        key_size: Modulus size in bits. Defaults to 2048.

    Returns:
        The PEM encoded public and private keys.

    Raises:
        InvalidInputError: If the requested modulus size is outside the
            documented range.
    """
    if not 2048 <= key_size <= 4096:
        raise InvalidInputError("Invalid key size: RSA keys must be between 2048 and 4096 bits.")
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    private_pem = private_key.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("ascii")
    public_pem = (
        private_key.public_key()
        .public_bytes(encoding=Encoding.PEM, format=PublicFormat.SubjectPublicKeyInfo)
        .decode("ascii")
    )
    return RsaKeyPair(public_key_pem=public_pem, private_key_pem=private_pem)


def _load_public_key(pem: str):
    """Load a PEM public key, rejecting anything that is not an RSA key."""
    try:
        key = serialization.load_pem_public_key(pem.encode("ascii"))
    except (ValueError, UnicodeEncodeError, binascii.Error) as exc:
        raise InvalidInputError("Invalid public key: expected a PEM encoded RSA public key.") from exc
    except UnsupportedAlgorithm as exc:
        raise InvalidInputError("Invalid public key: unsupported key algorithm.") from exc
    if not isinstance(key, rsa.RSAPublicKey):
        raise InvalidInputError("Invalid public key: the supplied key is not an RSA public key.")
    return key


def _load_private_key(pem: str):
    """Load a PEM private key, rejecting anything that is not an RSA key."""
    try:
        key = serialization.load_pem_private_key(pem.encode("ascii"), password=None)
    except (ValueError, TypeError, UnicodeEncodeError, binascii.Error) as exc:
        raise InvalidInputError("Invalid private key: expected an unencrypted PEM RSA private key.") from exc
    except UnsupportedAlgorithm as exc:
        raise InvalidInputError("Invalid private key: unsupported key algorithm.") from exc
    if not isinstance(key, rsa.RSAPrivateKey):
        raise InvalidInputError("Invalid private key: the supplied key is not an RSA private key.")
    return key


def encrypt(plaintext: str, public_key_pem: str) -> str:
    """Encrypt UTF-8 text with RSA-OAEP (MGF1, SHA-256).

    Args:
        plaintext: Text to encrypt. Limited to 190 bytes for a 2048-bit key.
        public_key_pem: PEM encoded RSA public key.

    Returns:
        Base64 ciphertext.

    Raises:
        InvalidInputError: If the key is malformed or not RSA, or if the
            plaintext exceeds the OAEP capacity of the key.
    """
    public_key = _load_public_key(public_key_pem)
    payload = plaintext.encode("utf-8")
    limit = maximum_plaintext_bytes(public_key.key_size)
    if len(payload) > limit:
        raise InvalidInputError(
            f"Plaintext too large: this {public_key.key_size}-bit key accepts at most "
            f"{limit} bytes ({len(payload)} provided). RSA cannot encrypt arbitrary size data; "
            "encrypt a symmetric key with RSA and the data with AES or ChaCha20-Poly1305.",
            code="PLAINTEXT_TOO_LARGE",
        )
    ciphertext = public_key.encrypt(payload, _OAEP_PADDING)
    return base64.b64encode(ciphertext).decode("ascii")


def decrypt(ciphertext_b64: str, private_key_pem: str) -> str:
    """Decrypt RSA-OAEP ciphertext.

    Args:
        ciphertext_b64: Base64 ciphertext produced by :func:`encrypt`.
        private_key_pem: PEM encoded RSA private key.

    Returns:
        The decrypted UTF-8 text.

    Raises:
        InvalidInputError: If the key or ciphertext is malformed.
        DecryptionError: If decryption fails, including a wrong key.
    """
    private_key = _load_private_key(private_key_pem)
    candidate = "".join(character for character in ciphertext_b64.strip() if not character.isspace())
    if not candidate:
        raise InvalidInputError("Invalid ciphertext: value is empty.")
    try:
        ciphertext = base64.b64decode(candidate, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise InvalidInputError("Invalid ciphertext: expected valid Base64.") from exc
    try:
        plaintext = private_key.decrypt(ciphertext, _OAEP_PADDING)
    except ValueError as exc:
        raise DecryptionError(
            "Decryption failed: the ciphertext does not match this private key."
        ) from exc
    try:
        return plaintext.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise DecryptionError("Decryption succeeded but the result is not valid UTF-8 text.") from exc