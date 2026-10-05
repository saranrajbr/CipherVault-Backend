"""DES: legacy algorithm metadata with execution disabled.

DES is never used to process data in CipherForge. It is represented so the
frontend can teach *why* it is obsolete:

    * The 64-bit key carries only 56 bits of entropy; the remaining 8 bits are
      fixed parity. That is far below any modern security margin.
    * The full key space can be searched in hours on commodity hardware, so the
      cipher offers no practical confidentiality.
    * It is also vulnerable to analytic differential cryptanalysis.
    * Its 64-bit block size makes it susceptible to birthday-bound collisions
      when many blocks are encrypted under one key.

Presenting DES as usable would undermine the point of the project, so
:func:`encrypt` and :func:`decrypt` always raise
:class:`~app.errors.AlgorithmDisabledError`.
"""

from __future__ import annotations

from ..errors import AlgorithmDisabledError

KEY_SIZE_BITS = 56
BLOCK_SIZE_BITS = 64
KEY_SIZE_HEX_CHARS = 16

DISABLED_MESSAGE = (
    "DES execution is disabled. DES has a 56-bit effective key size, can be brute-forced "
    "in hours on commodity hardware, and must not be used in modern applications. "
    "Use AES-256-GCM instead."
)

SECURITY_FACTS: dict[str, str] = {
    "type": "Symmetric block cipher (legacy)",
    "key_size": "56-bit effective key (64 bits with parity bits)",
    "block_size": "64-bit",
    "status": "Legacy / Insecure",
    "brute_force": "A 56-bit key space is exhaustible in hours on modern hardware.",
    "known_attacks": "Analytic differential cryptanalysis reduces the practical attack cost further.",
    "replacement": "3DES for legacy compatibility, AES-256-GCM for anything new.",
}


def security_information() -> dict[str, str]:
    """Return the legacy security facts for the frontend information panel."""
    return dict(SECURITY_FACTS)


def encrypt(plaintext: str, key: str) -> str:
    """Always fail: DES encryption is disabled.

    Args:
        plaintext: Unused.
        key: Unused.

    Raises:
        AlgorithmDisabledError: Always.
    """
    raise AlgorithmDisabledError(DISABLED_MESSAGE)


def decrypt(ciphertext: str, key: str) -> str:
    """Always fail: DES decryption is disabled.

    Args:
        ciphertext: Unused.
        key: Unused.

    Raises:
        AlgorithmDisabledError: Always.
    """
    raise AlgorithmDisabledError(DISABLED_MESSAGE)