"""SHA-512 hashing service (SHA-2 family)."""

from __future__ import annotations

import hashlib

from ..errors import InvalidInputError

ALGORITHM_NAME = "sha512"
DIGEST_SIZE_BITS = 512


def hash_text(text: str) -> str:
    """Compute the SHA-512 digest of UTF-8 text.

    Args:
        text: Text to hash.

    Returns:
        The 128 character lowercase hexadecimal digest.

    Raises:
        InvalidInputError: If the text cannot be encoded as UTF-8.
    """
    try:
        payload = text.encode("utf-8")
    except UnicodeEncodeError as exc:  # pragma: no cover - str input is always encodable
        raise InvalidInputError("Input could not be encoded as UTF-8 text.") from exc
    return hashlib.new(ALGORITHM_NAME, payload).hexdigest()