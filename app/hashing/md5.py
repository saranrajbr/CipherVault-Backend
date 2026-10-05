"""MD5 hashing service (legacy demonstration only).

MD5 is cryptographically broken. Practical collision attacks have been public
since 2004 and chosen-prefix collisions are cheap, so MD5 must never be used for
digital signatures, certificates, or any integrity guarantee where collision
resistance matters. It is also far too fast to store passwords.

``usedforsecurity=False`` marks the intent explicitly so the call still works
under FIPS-restricted builds that refuse MD5 by default.
"""

from __future__ import annotations

import hashlib

from ..errors import InvalidInputError

ALGORITHM_NAME = "md5"
DIGEST_SIZE_BITS = 128


def hash_text(text: str) -> str:
    """Compute the MD5 digest of UTF-8 text.

    Args:
        text: Text to hash.

    Returns:
        The 32 character lowercase hexadecimal digest.

    Raises:
        InvalidInputError: If the text cannot be encoded as UTF-8.
    """
    try:
        payload = text.encode("utf-8")
    except UnicodeEncodeError as exc:  # pragma: no cover - str input is always encodable
        raise InvalidInputError("Input could not be encoded as UTF-8 text.") from exc
    digest = hashlib.new(ALGORITHM_NAME, payload, usedforsecurity=False)
    return digest.hexdigest()