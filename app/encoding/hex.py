"""Hexadecimal encoding service.

Hexadecimal is a printable byte representation. It is not encryption and hides
no information: keys, nonces and ciphertext are all trivially recoverable.
"""

from __future__ import annotations

import binascii
import re

from ..errors import InvalidEncodingError

_HEX_PATTERN = re.compile(r"\A[0-9a-fA-F]*\Z")


def encode(data: str) -> str:
    """Encode UTF-8 text as lowercase hexadecimal.

    Args:
        data: Plain text to encode.

    Returns:
        Two hexadecimal characters per input byte.

    Raises:
        InvalidEncodingError: If ``data`` cannot be represented as UTF-8.
    """
    try:
        raw = data.encode("utf-8")
    except UnicodeEncodeError as exc:  # pragma: no cover - str input is always encodable
        raise InvalidEncodingError("Input could not be encoded as UTF-8 text.") from exc
    return raw.hex()


def decode(data: str) -> str:
    """Decode hexadecimal text back into UTF-8 text.

    Args:
        data: Hexadecimal text, with or without ``0x`` prefixes on each byte.

    Returns:
        The decoded UTF-8 text.

    Raises:
        InvalidEncodingError: If the input contains non-hexadecimal characters,
            has an odd length, or decodes to bytes that are not UTF-8 text.
    """
    candidate = _strip_prefixes(data)
    if not candidate:
        raise InvalidEncodingError("Hexadecimal input is empty.")
    if not _HEX_PATTERN.match(candidate):
        raise InvalidEncodingError("Invalid hexadecimal input. Expected characters 0-9 and a-f only.")
    if len(candidate) % 2 != 0:
        raise InvalidEncodingError("Invalid hexadecimal input. Length must be even (two characters per byte).")
    try:
        raw = bytes.fromhex(candidate)
    except (binascii.Error, ValueError) as exc:  # pragma: no cover - guarded by the checks above
        raise InvalidEncodingError("Invalid hexadecimal input.") from exc
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise InvalidEncodingError(
            "The hexadecimal payload decoded successfully but is not valid UTF-8 text."
        ) from exc


def _strip_prefixes(data: str) -> str:
    """Remove whitespace and any ``0x``/``0X`` byte prefixes."""
    without_space = "".join(character for character in data if not character.isspace())
    return without_space.replace("0x", "").replace("0X", "")