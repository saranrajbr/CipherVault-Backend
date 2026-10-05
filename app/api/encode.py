"""Encoding endpoints. HTTP concerns only; encoding logic lives in app.encoding."""

from __future__ import annotations

from fastapi import APIRouter, status

from ..encoding import base64 as base64_service
from ..encoding import hex as hex_service
from ..errors import UnsupportedOperationError
from ..schemas.crypto import EncodeRequest, EncodeResponse

router = APIRouter(tags=["encode"])

_ENCODERS = {
    "base64": base64_service,
    "hex": hex_service,
}


@router.post(
    "/encode",
    response_model=EncodeResponse,
    status_code=status.HTTP_200_OK,
    summary="Encode or decode text with Base64 or hexadecimal",
)
def run_encode(payload: EncodeRequest) -> EncodeResponse:
    """Encode or decode text using the requested reversible encoding.

    Args:
        payload: Validated request containing the algorithm, operation and input.

    Returns:
        The encoded or decoded result.

    Raises:
        UnsupportedOperationError: If the algorithm or operation is unknown.
        InvalidEncodingError: If the input is malformed for that encoding.
    """
    service = _ENCODERS.get(payload.algorithm)
    if service is None:
        raise UnsupportedOperationError(f"Unsupported encoding algorithm '{payload.algorithm}'.")
    if payload.operation == "encode":
        output = service.encode(payload.input)
    elif payload.operation == "decode":
        output = service.decode(payload.input)
    else:
        raise UnsupportedOperationError(f"Unsupported operation '{payload.operation}'.")
    return EncodeResponse(
        algorithm=payload.algorithm,
        operation=payload.operation,
        output=output,
    )