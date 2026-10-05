"""Encryption endpoints. Dispatches to the app.crypto services.

No cryptographic primitive is implemented here: this module only validates the
request shape, routes it to the correct service and formats the response.
"""

from __future__ import annotations

from fastapi import APIRouter, status

from ..crypto import aes, caesar, chacha20, des, rsa
from ..errors import InvalidInputError, UnsupportedOperationError
from ..schemas.crypto import EncryptionRequest, EncryptionResponse

router = APIRouter(tags=["encryption"])

_CAESAR_WORK_NOTE = (
    "Educational classical cipher. Not cryptographically secure: the shift is the only "
    "secret and there are just 25 meaningful keys."
)
_DES_WORK_NOTE = des.DISABLED_MESSAGE
_RSA_WORK_NOTE = (
    "RSA-OAEP with a 2048-bit key accepts at most 190 bytes of plaintext. It is designed to "
    "wrap symmetric keys, not to encrypt files or long messages."
)


@router.post(
    "/encryption",
    response_model=EncryptionResponse,
    status_code=status.HTTP_200_OK,
    summary="Encrypt or decrypt with AES-256-GCM, ChaCha20-Poly1305, RSA-OAEP or Caesar",
)
def run_encryption(payload: EncryptionRequest) -> EncryptionResponse:
    """Run the requested encryption operation.

    Args:
        payload: Validated request. Its model validator has already ensured the
            fields required by this algorithm and operation are present.

    Returns:
        A response containing the ciphertext, plaintext and any generated
        parameters or keys.

    Raises:
        UnsupportedOperationError: If the algorithm or operation is unknown.
        CipherForgeError: Any error raised by the underlying crypto service,
            translated into a structured response by the global handlers.
    """
    if payload.algorithm == "aes":
        return _run_aes(payload)
    if payload.algorithm == "chacha20":
        return _run_chacha20(payload)
    if payload.algorithm == "rsa":
        return _run_rsa(payload)
    if payload.algorithm == "caesar":
        return _run_caesar(payload)
    if payload.algorithm == "des":
        return _run_des(payload)
    raise UnsupportedOperationError(f"Unsupported encryption algorithm '{payload.algorithm}'.")


def _run_aes(payload: EncryptionRequest) -> EncryptionResponse:
    """Handle AES-256-GCM requests.

    Args:
        payload: Validated AES request.

    Returns:
        Response with ciphertext and, on encryption, the generated key and nonce.
    """
    if payload.operation == "encrypt":
        parameters = aes.generate_parameters()
        result = aes.encrypt(payload.input or "", parameters.key, parameters.nonce)
        return EncryptionResponse(
            algorithm="aes",
            operation="encrypt",
            ciphertext=result.ciphertext_b64,
            key=result.key_hex,
            nonce=result.nonce_hex,
        )
    key = aes.decode_hex_field(payload.key or "", aes.KEY_SIZE_BYTES, "key")
    nonce = aes.decode_hex_field(payload.nonce or "", aes.NONCE_SIZE_BYTES, "nonce")
    plaintext = aes.decrypt(payload.ciphertext or "", key, nonce)
    return EncryptionResponse(algorithm="aes", operation="decrypt", output=plaintext)


def _run_chacha20(payload: EncryptionRequest) -> EncryptionResponse:
    """Handle ChaCha20-Poly1305 requests.

    Args:
        payload: Validated ChaCha20 request.

    Returns:
        Response with ciphertext and, on encryption, the generated key and nonce.
    """
    if payload.operation == "encrypt":
        parameters = chacha20.generate_parameters()
        result = chacha20.encrypt(payload.input or "", parameters.key, parameters.nonce)
        return EncryptionResponse(
            algorithm="chacha20",
            operation="encrypt",
            ciphertext=result.ciphertext_b64,
            key=result.key_hex,
            nonce=result.nonce_hex,
        )
    key = chacha20.decode_hex_field(payload.key or "", chacha20.KEY_SIZE_BYTES, "key")
    nonce = chacha20.decode_hex_field(payload.nonce or "", chacha20.NONCE_SIZE_BYTES, "nonce")
    plaintext = chacha20.decrypt(payload.ciphertext or "", key, nonce)
    return EncryptionResponse(algorithm="chacha20", operation="decrypt", output=plaintext)


def _run_rsa(payload: EncryptionRequest) -> EncryptionResponse:
    """Handle RSA-2048 OAEP requests, including key generation.

    Args:
        payload: Validated RSA request.

    Returns:
        Response with a key pair, ciphertext or plaintext depending on the
        operation.
    """
    if payload.operation == "generate_key_pair":
        key_pair = rsa.generate_key_pair(payload.key_size or rsa.KEY_SIZE_BITS)
        return EncryptionResponse(
            algorithm="rsa",
            operation="generate_key_pair",
            public_key=key_pair.public_key_pem,
            private_key=key_pair.private_key_pem,
            work_note=_RSA_WORK_NOTE,
        )
    if payload.operation == "encrypt":
        ciphertext = rsa.encrypt(payload.input or "", payload.public_key or "")
        return EncryptionResponse(
            algorithm="rsa",
            operation="encrypt",
            ciphertext=ciphertext,
            work_note=_RSA_WORK_NOTE,
        )
    plaintext = rsa.decrypt(payload.ciphertext or "", payload.private_key or "")
    return EncryptionResponse(algorithm="rsa", operation="decrypt", output=plaintext)


def _run_caesar(payload: EncryptionRequest) -> EncryptionResponse:
    """Handle Caesar cipher requests.

    Args:
        payload: Validated Caesar request.

    Returns:
        Response with the transformed text.
    """
    shift = payload.shift or 0
    text = payload.input or ""
    if payload.operation == "encrypt":
        return EncryptionResponse(
            algorithm="caesar",
            operation="encrypt",
            output=caesar.encrypt(text, shift),
            work_note=_CAESAR_WORK_NOTE,
        )
    if payload.operation == "decrypt":
        return EncryptionResponse(
            algorithm="caesar",
            operation="decrypt",
            output=caesar.decrypt(text, shift),
            work_note=_CAESAR_WORK_NOTE,
        )
    raise UnsupportedOperationError(
        f"The Caesar cipher supports encrypt and decrypt only, not '{payload.operation}'."
    )


def _run_des(payload: EncryptionRequest) -> EncryptionResponse:
    """Refuse every DES request with the legacy explanation.

    DES cannot be reached through the schema validator, so this guard exists to
    keep the failure explicit if that validation ever changes.

    Args:
        payload: Validated DES request.

    Returns:
        Never returns.

    Raises:
        InvalidInputError: Always, explaining why DES is disabled.
    """
    raise InvalidInputError(_DES_WORK_NOTE, code="ALGORITHM_DISABLED")