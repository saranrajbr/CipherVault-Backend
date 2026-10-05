"""bcrypt password hashing service.

bcrypt is the only algorithm in CipherForge that is intended for passwords:
it is deliberately slow, it salts every password automatically, and the cost
factor is stored inside the hash so it can be raised over time.

Hard rules enforced here:
    * Passwords are never logged, never persisted and never returned.
    * Only the resulting bcrypt hash (or a boolean match result) leaves this
      module.
    * The 72 byte bcrypt input limit is validated explicitly instead of being
      silently truncated, because truncation would let two different long
      passwords authenticate each other.
"""

from __future__ import annotations

import bcrypt

from ..errors import InvalidInputError

MIN_WORK_FACTOR = 4
MAX_WORK_FACTOR = 31
DEFAULT_WORK_FACTOR = 12
MAX_PASSWORD_BYTES = 72


def validate_work_factor(work_factor: int) -> int:
    """Check a bcrypt cost value.

    Args:
        work_factor: Cost between 4 and 31.

    Returns:
        The validated work factor.

    Raises:
        InvalidInputError: If the cost is outside the supported range.
    """
    if not MIN_WORK_FACTOR <= work_factor <= MAX_WORK_FACTOR:
        raise InvalidInputError(
            f"Invalid work factor: must be between {MIN_WORK_FACTOR} and {MAX_WORK_FACTOR}."
        )
    return work_factor


def _encode_password(password: str) -> bytes:
    """Validate and encode a password for bcrypt.

    Args:
        password: The plaintext password, used transiently only.

    Returns:
        UTF-8 encoded password bytes.

    Raises:
        InvalidInputError: If the password is empty or longer than bcrypt allows.
    """
    if not password:
        raise InvalidInputError("Invalid password: value must not be empty.")
    payload = password.encode("utf-8")
    if len(payload) > MAX_PASSWORD_BYTES:
        raise InvalidInputError(
            f"Invalid password: bcrypt only processes the first {MAX_PASSWORD_BYTES} bytes "
            f"({len(payload)} bytes provided). Shorten the password, because bytes beyond "
            "that limit would be silently ignored.",
            code="PASSWORD_TOO_LONG",
        )
    return payload


def hash_password(password: str, work_factor: int = DEFAULT_WORK_FACTOR) -> str:
    """Hash a password with bcrypt.

    Args:
        password: Plaintext password. Never stored or logged.
        work_factor: bcrypt cost factor. Defaults to 12.

    Returns:
        The bcrypt hash, including algorithm version, cost and salt.

    Raises:
        InvalidInputError: If the password or work factor is invalid.
    """
    validate_work_factor(work_factor)
    payload = _encode_password(password)
    return bcrypt.hashpw(payload, bcrypt.gensalt(rounds=work_factor)).decode("ascii")


def verify_password(password: str, password_hash: str) -> bool:
    """Verify a password against a bcrypt hash.

    Args:
        password: Candidate plaintext password. Never stored or logged.
        password_hash: A previously produced bcrypt hash.

    Returns:
        ``True`` when the password matches, otherwise ``False``.

    Raises:
        InvalidInputError: If the password is invalid or the hash is malformed.
    """
    payload = _encode_password(password)
    candidate_hash = password_hash.strip().encode("ascii", errors="replace")
    if not candidate_hash:
        raise InvalidInputError("Invalid bcrypt hash: value must not be empty.")
    try:
        return bcrypt.checkpw(payload, candidate_hash)
    except (ValueError, TypeError) as exc:
        raise InvalidInputError(
            "Invalid bcrypt hash: expected a hash produced by bcrypt (for example $2b$12$...)."
        ) from exc