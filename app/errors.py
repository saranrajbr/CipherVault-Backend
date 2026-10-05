"""Domain-level errors raised by the service layers.

These exceptions are transport agnostic: they carry a stable machine readable
code and an HTTP status hint, but they never mention HTTP themselves. The API
layer is responsible for translating them into structured JSON responses, which
keeps FastAPI out of the service modules entirely.
"""

from __future__ import annotations


class CipherForgeError(Exception):
    """Base class for every error raised by CipherForge services."""

    code: str = "INTERNAL_ERROR"
    status_code: int = 400

    def __init__(
        self,
        message: str,
        *,
        code: str | None = None,
        status_code: int | None = None,
    ) -> None:
        """Store a user-safe message and an optional code/status override."""
        super().__init__(message)
        self.message = message
        if code is not None:
            self.code = code
        if status_code is not None:
            self.status_code = status_code


class InvalidInputError(CipherForgeError):
    """The caller supplied input the service cannot work with."""

    code = "INVALID_INPUT"
    status_code = 400


class InvalidEncodingError(InvalidInputError):
    """Encoded input was malformed (bad Base64, bad hexadecimal, ...)."""

    code = "INVALID_ENCODING"


class DecryptionError(CipherForgeError):
    """Decryption failed, most often because authentication failed."""

    code = "DECRYPTION_FAILED"
    status_code = 400


class AlgorithmDisabledError(CipherForgeError):
    """The requested algorithm is intentionally not executable."""

    code = "ALGORITHM_DISABLED"
    status_code = 400


class UnsupportedOperationError(CipherForgeError):
    """The algorithm does not support the requested operation."""

    code = "UNSUPPORTED_OPERATION"
    status_code = 400


class PayloadTooLargeError(InvalidInputError):
    """Input exceeded the documented size limit."""

    code = "PAYLOAD_TOO_LARGE"
    status_code = 413