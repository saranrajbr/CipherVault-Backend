"""Base64 encoding service.

Base64 is a transport encoding, not encryption: it is fully reversible by
anyone and provides no confidentiality, integrity or authenticity.
"""

from __future__ import annotations

import base64 as _base64
import binascii

from ..errors import InvalidEncodingError

_SEPARATOR_PATTERN = "".join(("", "\n", "\r", " ", "\t"))


def _strip_whitespace(value: str) -> str:
    """Remove the whitespace that line-wrapped Base64 commonly contains."""
    return "".join(character for character in value if character not in _SEPARATOR_PATTERN)


def encode(data: str) -> str:
    """Encode UTF-8 text as standard Base64.

    Args:
        data: Plain text to encode.

    Returns:
        The Base64 representation of ``data`` encoded as UTF-8 bytes.

    Raises:
        InvalidEncodingError: If ``data`` cannot be represented as UTF-8.
    """
    try:
        raw = data.encode("utf-8")
    except UnicodeEncodeError as exc:  # pragma: no cover - str input is always encodable
        raise InvalidEncodingError("Input could not be encoded as UTF-8 text.") from exc
    return _base64.b64encode(raw).decode("ascii")


def decode(data: str) -> str:
    """Decode standard Base64 back into UTF-8 text.

    Args:
        data: Base64 text. Internal line breaks and spaces are tolerated.

    Returns:
        The decoded UTF-8 text.

    Raises:
        InvalidEncodingError: If the input is not valid Base64, has incorrect
            padding, or decodes to bytes that are not valid UTF-8 text.
    """
    candidate = _strip_whitespace(data)
    if not candidate:
        raise InvalidEncodingError("Base64 input is empty.")
    try:
        raw = _base64.b64decode(candidate, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise InvalidEncodingError(
            "Invalid Base64 input. Expected only A-Z, a-z, 0-9, '+', '/' and correct '=' padding."
        ) from exc
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise InvalidEncodingError(
            "The Base64 payload decoded successfully but is not valid UTF-8 text."
        ) from exc