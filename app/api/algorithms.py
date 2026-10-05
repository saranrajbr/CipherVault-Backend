"""Algorithm catalogue endpoint.

The frontend calls this once and derives its category tabs, algorithm lists,
operation toggles, security badges and information panels from the response.
The SPA therefore has no duplicated algorithm definitions to drift out of sync
with the backend.
"""

from __future__ import annotations

from fastapi import APIRouter, status

from ..catalog import CATEGORY_ORDER, get_catalog
from ..schemas.crypto import AlgorithmsResponse

router = APIRouter(tags=["algorithms"])


@router.get(
    "/algorithms",
    response_model=AlgorithmsResponse,
    status_code=status.HTTP_200_OK,
    summary="List every algorithm with its operations and security metadata",
)
def list_algorithms() -> AlgorithmsResponse:
    """Return the full algorithm catalogue.

    Returns:
        Response containing the three categories and, for each algorithm, its
        operations, security status, warnings and information panel content.
    """
    catalog = get_catalog()
    return AlgorithmsResponse(
        categories=list(CATEGORY_ORDER),
        encode=catalog["encode"],
        encryption=catalog["encryption"],
        hash=catalog["hash"],
    )