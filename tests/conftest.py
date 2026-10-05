"""Shared pytest fixtures.

``tests`` is not a package, so the backend directory is added to ``sys.path``
here to keep ``from app...`` imports working regardless of the working
directory pytest is launched from.
"""

from __future__ import annotations

import base64
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

BACKEND_ROOT = Path(__file__).resolve().parents[1]
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from app.crypto import aes  # noqa: E402
from app.main import app  # noqa: E402


@pytest.fixture(autouse=True)
def reset_nonce_registry() -> None:
    """Keep the AES nonce reuse ledger isolated between tests."""
    aes.reset_nonce_registry()


@pytest.fixture()
def client() -> TestClient:
    """Return a TestClient bound to the CipherForge application."""
    return TestClient(app)


def flip_ciphertext_byte(ciphertext_b64: str) -> str:
    """Return the ciphertext with one bit flipped in the first byte.

    Args:
        ciphertext_b64: The Base64 ciphertext to corrupt.

    Returns:
        A tampered Base64 ciphertext that must fail authentication.
    """
    raw = bytearray(base64.b64decode(ciphertext_b64))
    raw[0] ^= 0x01
    return base64.b64encode(bytes(raw)).decode("ascii")