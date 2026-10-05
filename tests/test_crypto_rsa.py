"""RSA-2048 OAEP tests: key generation, round trip and failure modes."""

from __future__ import annotations

import base64

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from app.crypto import rsa
from app.errors import DecryptionError, InvalidInputError

PLAINTEXT = "CipherForge uses RSA-OAEP."


@pytest.fixture(scope="module")
def key_pair() -> rsa.RsaKeyPair:
    """Generate one key pair for the module; RSA key generation is slow."""
    return rsa.generate_key_pair()


class TestKeyGeneration:
    def test_public_and_private_keys_are_pem_encoded(self, key_pair: rsa.RsaKeyPair) -> None:
        assert key_pair.public_key_pem.startswith("-----BEGIN PUBLIC KEY-----")
        assert key_pair.private_key_pem.startswith("-----BEGIN PRIVATE KEY-----")

    def test_generated_key_is_2048_bits(self, key_pair: rsa.RsaKeyPair) -> None:
        loaded = serialization.load_pem_public_key(key_pair.public_key_pem.encode("ascii"))
        assert loaded.key_size == 2048

    def test_generated_keys_are_unique(self) -> None:
        first = rsa.generate_key_pair()
        second = rsa.generate_key_pair()
        assert first.private_key_pem != second.private_key_pem

    def test_invalid_key_size_is_rejected(self) -> None:
        with pytest.raises(InvalidInputError, match="2048 and 4096"):
            rsa.generate_key_pair(1024)


class TestEncryption:
    def test_encrypt_decrypt_round_trip(self, key_pair: rsa.RsaKeyPair) -> None:
        ciphertext = rsa.encrypt(PLAINTEXT, key_pair.public_key_pem)
        assert rsa.decrypt(ciphertext, key_pair.private_key_pem) == PLAINTEXT

    def test_ciphertext_is_base64_and_differs_from_plaintext(
        self, key_pair: rsa.RsaKeyPair
    ) -> None:
        ciphertext = rsa.encrypt(PLAINTEXT, key_pair.public_key_pem)
        assert base64.b64decode(ciphertext) != PLAINTEXT.encode("utf-8")

    def test_maximum_plaintext_is_accepted(self, key_pair: rsa.RsaKeyPair) -> None:
        payload = "A" * rsa.maximum_plaintext_bytes()
        assert rsa.decrypt(rsa.encrypt(payload, key_pair.public_key_pem), key_pair.private_key_pem) == payload

    def test_maximum_plaintext_bytes_is_190_for_2048_bit_key(self) -> None:
        assert rsa.maximum_plaintext_bytes() == 190

    def test_oversized_plaintext_is_rejected(self, key_pair: rsa.RsaKeyPair) -> None:
        with pytest.raises(InvalidInputError, match="too large"):
            rsa.encrypt("A" * (rsa.maximum_plaintext_bytes() + 1), key_pair.public_key_pem)

    def test_invalid_public_key_is_rejected(self) -> None:
        with pytest.raises(InvalidInputError, match="public key"):
            rsa.encrypt(PLAINTEXT, "-----BEGIN PUBLIC KEY-----\nnope\n-----END PUBLIC KEY-----")

    def test_non_rsa_public_key_is_rejected(self) -> None:
        ec_pem = (
            ec.generate_private_key(ec.SECP256R1())
            .public_key()
            .public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            .decode("ascii")
        )
        with pytest.raises(InvalidInputError, match="not an RSA public key"):
            rsa.encrypt(PLAINTEXT, ec_pem)

    def test_private_key_used_as_public_key_is_rejected(self, key_pair: rsa.RsaKeyPair) -> None:
        with pytest.raises(InvalidInputError, match="Invalid public key"):
            rsa.encrypt(PLAINTEXT, key_pair.private_key_pem)


class TestDecryption:
    def test_wrong_private_key_is_rejected(self, key_pair: rsa.RsaKeyPair) -> None:
        ciphertext = rsa.encrypt(PLAINTEXT, key_pair.public_key_pem)
        other = rsa.generate_key_pair()
        with pytest.raises(DecryptionError):
            rsa.decrypt(ciphertext, other.private_key_pem)

    def test_invalid_private_key_is_rejected(self, key_pair: rsa.RsaKeyPair) -> None:
        ciphertext = rsa.encrypt(PLAINTEXT, key_pair.public_key_pem)
        with pytest.raises(InvalidInputError, match="private key"):
            rsa.decrypt(ciphertext, "not a pem block")

    def test_malformed_ciphertext_is_rejected(self, key_pair: rsa.RsaKeyPair) -> None:
        with pytest.raises(InvalidInputError, match="Base64"):
            rsa.decrypt("%%%%", key_pair.private_key_pem)

    def test_empty_ciphertext_is_rejected(self, key_pair: rsa.RsaKeyPair) -> None:
        with pytest.raises(InvalidInputError, match="empty"):
            rsa.decrypt("   ", key_pair.private_key_pem)

    def test_tampered_ciphertext_is_rejected(self, key_pair: rsa.RsaKeyPair) -> None:
        raw = bytearray(base64.b64decode(rsa.encrypt(PLAINTEXT, key_pair.public_key_pem)))
        raw[-1] ^= 0xFF
        tampered = base64.b64encode(bytes(raw)).decode("ascii")
        with pytest.raises(DecryptionError):
            rsa.decrypt(tampered, key_pair.private_key_pem)