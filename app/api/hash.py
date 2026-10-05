"""Hashing endpoints, including bcrypt password hashing and verification.

Passwords pass through the request and the bcrypt service and are never logged,
persisted or echoed back. Only the resulting hash or a boolean verdict is
returned.
"""

from __future__ import annotations

from fastapi import APIRouter, status

from ..errors import UnsupportedOperationError
from ..hashing import bcrypt as bcrypt_service
from ..hashing import md5, sha256, sha512
from ..schemas.crypto import (
    BcryptVerifyRequest,
    BcryptVerifyResponse,
    HashRequest,
    HashResponse,
)

router = APIRouter(tags=["hash"])


@router.post(
    "/hash",
    response_model=HashResponse,
    status_code=status.HTTP_200_OK,
    summary="Hash text with MD5, SHA-256, SHA-512 or bcrypt",
)
def run_hash(payload: HashRequest) -> HashResponse:
    """Hash the supplied text with the requested algorithm.

    Args:
        payload: Validated request containing the algorithm and input text.

    Returns:
        Response with the hexadecimal digest or the bcrypt hash.

    Raises:
        UnsupportedOperationError: If the algorithm or operation is unknown.
    """
    if payload.algorithm == "md5":
        return HashResponse(
            algorithm="md5",
            operation="generate",
            hash=md5.hash_text(payload.input),
            digest_size_bits=md5.DIGEST_SIZE_BITS,
        )
    if payload.algorithm == "sha256":
        return HashResponse(
            algorithm="sha256",
            operation="generate",
            hash=sha256.hash_text(payload.input),
            digest_size_bits=sha256.DIGEST_SIZE_BITS,
        )
    if payload.algorithm == "sha512":
        return HashResponse(
            algorithm="sha512",
            operation="generate",
            hash=sha512.hash_text(payload.input),
            digest_size_bits=sha512.DIGEST_SIZE_BITS,
        )
    if payload.algorithm == "bcrypt":
        work_factor = payload.work_factor or bcrypt_service.DEFAULT_WORK_FACTOR
        password_hash = bcrypt_service.hash_password(payload.input, work_factor)
        return HashResponse(
            algorithm="bcrypt",
            operation="generate",
            hash=password_hash,
            digest_size_bits=len(password_hash) * 8,
            work_factor=work_factor,
        )
    raise UnsupportedOperationError(f"Unsupported hash algorithm '{payload.algorithm}'.")


@router.post(
    "/hash/bcrypt/verify",
    response_model=BcryptVerifyResponse,
    status_code=status.HTTP_200_OK,
    summary="Verify a password against an existing bcrypt hash",
)
def verify_bcrypt(payload: BcryptVerifyRequest) -> BcryptVerifyResponse:
    """Check a candidate password against a bcrypt hash.

    Args:
        payload: Validated request containing the password and the hash. The
            password is used transiently and is never stored or logged.

    Returns:
        Response reporting whether the password matches.
    """
    matched = bcrypt_service.verify_password(payload.password, payload.hash)
    return BcryptVerifyResponse(verified=matched)