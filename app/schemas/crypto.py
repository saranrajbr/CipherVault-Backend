"""Pydantic request and response models for every CipherForge endpoint.

All size limits live here so the validation policy is visible in one place:

    * ``MAX_TEXT_BYTES`` (1 MiB) caps any user supplied text.
    * ``MAX_PASSWORD_CHARS`` caps password input before bcrypt's own 72 byte
      check runs.
    * ``MAX_KEY_CHARS`` caps PEM key material.
    * ``MAX_CIPHERTEXT_CHARS`` caps Base64 ciphertext, sized to hold the Base64
      form of a 1 MiB plaintext plus an authentication tag.
"""

from __future__ import annotations

from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

MAX_TEXT_BYTES = 1_048_576
MAX_PASSWORD_CHARS = 1024
MAX_KEY_CHARS = 16_384
MAX_CIPHERTEXT_CHARS = 2_097_152
MAX_SHIFT_ABSOLUTE = 1_000_000

EncodeAlgorithm = Literal["base64", "hex"]
EncodeOperation = Literal["encode", "decode"]

EncryptionAlgorithm = Literal["aes", "chacha20", "rsa", "caesar", "des"]
EncryptionOperation = Literal["encrypt", "decrypt", "generate_key_pair"]

HashAlgorithm = Literal["md5", "sha256", "sha512", "bcrypt"]
HashOperation = Literal["generate", "verify"]

NonEmptyText = Annotated[str, Field(min_length=1, max_length=MAX_TEXT_BYTES)]
HexKeyField = Annotated[
    str,
    Field(min_length=1, max_length=512, description="Hexadecimal key material."),
]
HexNonceField = Annotated[
    str,
    Field(min_length=1, max_length=256, description="Hexadecimal nonce material."),
]
PemKeyField = Annotated[
    str,
    Field(min_length=1, max_length=MAX_KEY_CHARS, description="PEM encoded RSA key."),
]
CiphertextField = Annotated[
    str,
    Field(min_length=1, max_length=MAX_CIPHERTEXT_CHARS, description="Base64 ciphertext."),
]
PasswordField = Annotated[
    str,
    Field(min_length=1, max_length=MAX_PASSWORD_CHARS, description="Plaintext password."),
]
WorkFactorField = Annotated[int, Field(ge=4, le=31, description="bcrypt cost factor.")]


def _enforce_utf8_size(value: str, max_bytes: int, field_name: str) -> str:
    """Reject text whose UTF-8 encoding exceeds ``max_bytes``.

    Args:
        value: The validated string.
        max_bytes: Maximum allowed encoded size.
        field_name: Field name used in the error message.

    Returns:
        The unchanged string when it is within the limit.

    Raises:
        ValueError: If the encoded text is too large.
    """
    if len(value.encode("utf-8")) > max_bytes:
        raise ValueError(f"{field_name} exceeds the maximum size of {max_bytes} bytes.")
    return value


class ApiErrorDetail(BaseModel):
    """Machine readable error payload."""

    code: str = Field(examples=["INVALID_INPUT"])
    message: str = Field(examples=["Invalid Base64 input."])


class ErrorResponse(BaseModel):
    """Structured error envelope returned for every failure."""

    success: Literal[False] = False
    error: ApiErrorDetail


class HealthResponse(BaseModel):
    """Service health payload."""

    status: Literal["ok"] = "ok"
    service: str = "cipherforge"
    version: str


class EncodeRequest(BaseModel):
    """Request body for ``POST /api/encode``."""

    model_config = ConfigDict(extra="forbid")

    algorithm: EncodeAlgorithm
    operation: EncodeOperation
    input: NonEmptyText = Field(description="Text to encode or Base64/hex to decode.")

    @field_validator("input")
    @classmethod
    def _limit_input_size(cls, value: str) -> str:
        """Enforce the 1 MiB UTF-8 limit on user text."""
        return _enforce_utf8_size(value, MAX_TEXT_BYTES, "input")


class EncodeResponse(BaseModel):
    """Successful encode or decode result."""

    success: Literal[True] = True
    algorithm: EncodeAlgorithm
    operation: EncodeOperation
    output: str = Field(description="Result of the requested operation.")


class EncryptionRequest(BaseModel):
    """Request body for ``POST /api/encryption``.

    One model covers every algorithm so the frontend can post a uniform
    payload. A model validator then enforces the fields each algorithm
    actually requires, which keeps failures precise and descriptive.
    """

    model_config = ConfigDict(extra="forbid")

    algorithm: EncryptionAlgorithm
    operation: EncryptionOperation
    input: str | None = Field(
        default=None,
        max_length=MAX_TEXT_BYTES,
        description="Plaintext to encrypt, or ciphertext to decrypt.",
    )
    key: str | None = Field(
        default=None,
        max_length=512,
        description="Hexadecimal key for AES-256-GCM or ChaCha20-Poly1305.",
    )
    nonce: str | None = Field(
        default=None,
        max_length=256,
        description="Hexadecimal nonce for AES-256-GCM or ChaCha20-Poly1305.",
    )
    ciphertext: str | None = Field(
        default=None,
        max_length=MAX_CIPHERTEXT_CHARS,
        description="Base64 ciphertext to decrypt. Required when decrypting AES or ChaCha20.",
    )
    public_key: PemKeyField | None = Field(
        default=None,
        description="PEM encoded RSA public key, required to encrypt with RSA.",
    )
    private_key: PemKeyField | None = Field(
        default=None,
        description="PEM encoded RSA private key, required to decrypt with RSA.",
    )
    shift: int | None = Field(
        default=None,
        ge=-MAX_SHIFT_ABSOLUTE,
        le=MAX_SHIFT_ABSOLUTE,
        description="Caesar shift value. Wraps around a 26 letter alphabet.",
    )
    key_size: int | None = Field(
        default=None,
        ge=2048,
        le=4096,
        description="Optional RSA modulus size. Defaults to 2048.",
    )

    @field_validator("input")
    @classmethod
    def _limit_input_size(cls, value: str | None) -> str | None:
        """Enforce the 1 MiB UTF-8 limit on user text."""
        if value is None:
            return None
        return _enforce_utf8_size(value, MAX_TEXT_BYTES, "input")

    @model_validator(mode="after")
    def _check_required_fields(self) -> "EncryptionRequest":
        """Ensure the requested combination of algorithm and operation is complete.

        Returns:
            The validated model.

        Raises:
            ValueError: With a message naming exactly the missing field.
        """
        if self.operation == "generate_key_pair":
            if self.algorithm != "rsa":
                raise ValueError(
                    "Operation 'generate_key_pair' is only supported for the 'rsa' algorithm."
                )
            return self

        if self.algorithm == "des":
            raise ValueError(
                "DES execution is disabled. DES has a 56-bit effective key size, can be brute-forced "
                "in hours on commodity hardware, and must not be used in modern applications. "
                "Use AES-256-GCM instead."
            )

        if self.algorithm == "caesar":
            if self.shift is None:
                raise ValueError("A Caesar cipher operation requires the 'shift' field.")
            self._require_input("input")
            return self

        if self.algorithm == "rsa":
            if self.operation == "encrypt":
                if not self.public_key:
                    raise ValueError("RSA encryption requires the 'public_key' field.")
                self._require_input("input")
            else:
                if not self.private_key:
                    raise ValueError("RSA decryption requires the 'private_key' field.")
                if not self.ciphertext:
                    raise ValueError("RSA decryption requires the 'ciphertext' field.")
            return self

        if self.operation == "encrypt":
            self._require_input("input")
        else:
            if not self.ciphertext:
                raise ValueError(
                    "Decryption requires the 'ciphertext' field holding the Base64 ciphertext."
                )

        if self.operation == "decrypt":
            if not self.key:
                raise ValueError("Decryption requires the 'key' field as hexadecimal.")
            if not self.nonce:
                raise ValueError("Decryption requires the 'nonce' field as hexadecimal.")
        return self

    def _require_input(self, field_name: str) -> None:
        """Raise a descriptive error when a required text field is missing.

        Args:
            field_name: Name of the field that must be present.

        Raises:
            ValueError: If the field is empty.
        """
        if not self.input:
            raise ValueError(f"Field '{field_name}' must not be empty for this operation.")


class EncryptionResponse(BaseModel):
    """Successful encryption result.

    Only the fields relevant to the requested operation are populated. Keys and
    nonces are returned because CipherForge is an interactive toolkit with no
    server-side key storage; they are never logged.
    """

    success: Literal[True] = True
    algorithm: EncryptionAlgorithm
    operation: EncryptionOperation
    output: str | None = Field(default=None, description="Decrypted plaintext.")
    ciphertext: str | None = Field(default=None, description="Base64 ciphertext.")
    key: str | None = Field(default=None, description="Hexadecimal key, when generated.")
    nonce: str | None = Field(default=None, description="Hexadecimal nonce, when generated.")
    public_key: str | None = Field(default=None, description="PEM encoded RSA public key.")
    private_key: str | None = Field(default=None, description="PEM encoded RSA private key.")
    work_note: str | None = Field(
        default=None,
        description="Educational note about the algorithm in use.",
    )


class HashRequest(BaseModel):
    """Request body for ``POST /api/hash``."""

    model_config = ConfigDict(extra="forbid")

    algorithm: HashAlgorithm
    operation: HashOperation = "generate"
    input: NonEmptyText = Field(description="Text to hash.")
    work_factor: WorkFactorField | None = Field(
        default=None,
        description="bcrypt cost factor. Defaults to 12 when omitted.",
    )

    @field_validator("input")
    @classmethod
    def _limit_input_size(cls, value: str) -> str:
        """Enforce the 1 MiB UTF-8 limit on hashed text."""
        return _enforce_utf8_size(value, MAX_TEXT_BYTES, "input")

    @model_validator(mode="after")
    def _check_supported_combination(self) -> "HashRequest":
        """Reject hash operations that the selected algorithm does not support.

        Returns:
            The validated model.

        Raises:
            ValueError: If the algorithm does not support the operation.
        """
        supported: dict[str, set[str]] = {
            "md5": {"generate"},
            "sha256": {"generate"},
            "sha512": {"generate"},
            "bcrypt": {"generate"},
        }
        if self.operation not in supported[self.algorithm]:
            raise ValueError(
                f"Algorithm '{self.algorithm}' supports only {sorted(supported[self.algorithm])}. "
                "Use POST /api/hash/bcrypt/verify to check a bcrypt hash."
            )
        if self.work_factor is not None and self.algorithm != "bcrypt":
            raise ValueError(f"Field 'work_factor' only applies to bcrypt, not '{self.algorithm}'.")
        return self


class HashResponse(BaseModel):
    """Successful hash generation result."""

    success: Literal[True] = True
    algorithm: HashAlgorithm
    operation: HashOperation
    hash: str = Field(description="Lowercase hexadecimal digest, or a bcrypt hash.")
    digest_size_bits: int = Field(description="Digest size in bits. For bcrypt this is the mod encoded length.")
    work_factor: int | None = Field(default=None, description="bcrypt cost factor applied.")


class BcryptVerifyRequest(BaseModel):
    """Request body for ``POST /api/hash/bcrypt/verify``."""

    model_config = ConfigDict(extra="forbid")

    password: PasswordField
    hash: Annotated[
        str,
        Field(min_length=1, max_length=512, description="bcrypt hash to verify against."),
    ]


class BcryptVerifyResponse(BaseModel):
    """bcrypt verification result.

    A non-matching password is a successful ``verified: false`` response, not an
    error: telling a caller that a password is wrong is a valid, safe outcome.
    """

    success: Literal[True] = True
    algorithm: Literal["bcrypt"] = "bcrypt"
    operation: Literal["verify"] = "verify"
    verified: bool = Field(description="True when the password matches the supplied hash.")


class AlgorithmInfo(BaseModel):
    """One algorithm entry from the catalogue."""

    id: str
    name: str
    category: Literal["encode", "encryption", "hash"]
    operations: list[str]
    default_operation: str | None = None
    security_status: str
    disabled: bool
    disabled_reason: str | None = None
    description: str
    security_info: dict[str, Any] = Field(description="Content for the security information panel.")


class AlgorithmsResponse(BaseModel):
    """Response body for ``GET /api/algorithms``."""

    categories: list[str] = Field(description="Ordered category tabs for the SPA.")
    encode: list[AlgorithmInfo]
    encryption: list[AlgorithmInfo]
    hash: list[AlgorithmInfo]