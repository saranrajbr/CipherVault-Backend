"""DES tests: legacy metadata is exposed, execution is disabled."""

from __future__ import annotations

import pytest

from app.crypto import des
from app.errors import AlgorithmDisabledError


def test_security_facts_explain_the_weakness() -> None:
    facts = des.security_information()
    assert facts["key_size"].startswith("56-bit")
    assert facts["status"] == "Legacy / Insecure"
    assert "exhaustible" in facts["brute_force"]
    assert "AES-256-GCM" in facts["replacement"]


def test_key_size_is_56_bits() -> None:
    assert des.KEY_SIZE_BITS == 56
    assert des.BLOCK_SIZE_BITS == 64


def test_encrypt_is_disabled() -> None:
    with pytest.raises(AlgorithmDisabledError, match="56-bit"):
        des.encrypt("CipherForge", "0123456789abcdef")


def test_decrypt_is_disabled() -> None:
    with pytest.raises(AlgorithmDisabledError):
        des.decrypt("0e8f1a2b", "0123456789abcdef")


def test_disabled_message_mentions_modern_replacement() -> None:
    assert "AES-256-GCM" in des.DISABLED_MESSAGE
    assert "disabled" in des.DISABLED_MESSAGE.lower()


def test_security_information_returns_a_copy() -> None:
    facts = des.security_information()
    facts["status"] = "tampered"
    assert des.security_information()["status"] == "Legacy / Insecure"