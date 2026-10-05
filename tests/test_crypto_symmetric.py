"""AES-256-GCM and ChaCha20-Poly1305 service tests."""

from __future__ import annotations

import base64

import pytest

from app.crypto import aes, chacha20
from app.errors import DecryptionError, InvalidInputError

from .conftest import flip_ciphertext_byte

PLAINTEXT = "Attack at dawn. 0600. Encode. Encrypt. Hash."


class TestAes:
    def test_generated_parameters_have_correct_sizes(self) -> None:
        parameters = aes.generate_parameters()
        assert len(parameters.key) == 32
        assert len(parameters.nonce) == 12
        assert len(parameters.key_hex) == 64
        assert len(parameters.nonce_hex) == 24

    def test_generated_parameters_are_unique(self) -> None:
        first = aes.generate_parameters()
        second = aes.generate_parameters()
        assert first.key != second.key
        assert first.nonce != second.nonce

    def test_encrypt_decrypt_round_trip(self) -> None:
        parameters = aes.generate_parameters()
        result = aes.encrypt(PLAINTEXT, parameters.key, parameters.nonce)
        assert result.key_hex == parameters.key_hex
        assert result.nonce_hex == parameters.nonce_hex
        assert aes.decrypt(result.ciphertext_b64, parameters.key, parameters.nonce) == PLAINTEXT

    def test_ciphertext_differs_from_plaintext(self) -> None:
        parameters = aes.generate_parameters()
        result = aes.encrypt(PLAINTEXT, parameters.key, parameters.nonce)
        assert PLAINTEXT.encode("utf-8") not in base64.b64decode(result.ciphertext_b64)

    def test_encrypting_twice_with_same_key_produces_different_ciphertext(self) -> None:
        parameters = aes.generate_parameters()
        first = aes.encrypt(PLAINTEXT, parameters.key, aes.generate_parameters().nonce)
        second = aes.encrypt(PLAINTEXT, parameters.key, aes.generate_parameters().nonce)
        assert first.ciphertext_b64 != second.ciphertext_b64

    def test_wrong_key_is_rejected(self) -> None:
        parameters = aes.generate_parameters()
        result = aes.encrypt(PLAINTEXT, parameters.key, parameters.nonce)
        with pytest.raises(DecryptionError):
            aes.decrypt(result.ciphertext_b64, aes.generate_parameters().key, parameters.nonce)

    def test_wrong_nonce_is_rejected(self) -> None:
        parameters = aes.generate_parameters()
        result = aes.encrypt(PLAINTEXT, parameters.key, parameters.nonce)
        with pytest.raises(DecryptionError):
            aes.decrypt(result.ciphertext_b64, parameters.key, aes.generate_parameters().nonce)

    def test_tampered_ciphertext_is_rejected(self) -> None:
        parameters = aes.generate_parameters()
        result = aes.encrypt(PLAINTEXT, parameters.key, parameters.nonce)
        tampered = flip_ciphertext_byte(result.ciphertext_b64)
        with pytest.raises(DecryptionError, match="Authentication failed"):
            aes.decrypt(tampered, parameters.key, parameters.nonce)

    def test_invalid_key_length_is_rejected(self) -> None:
        parameters = aes.generate_parameters()
        with pytest.raises(InvalidInputError, match="key"):
            aes.encrypt(PLAINTEXT, b"\x00" * 16, parameters.nonce)

    def test_invalid_nonce_length_is_rejected(self) -> None:
        parameters = aes.generate_parameters()
        with pytest.raises(InvalidInputError, match="nonce"):
            aes.encrypt(PLAINTEXT, parameters.key, b"\x00" * 8)

    def test_malformed_key_hex_is_rejected(self) -> None:
        with pytest.raises(InvalidInputError, match="hexadecimal"):
            aes.decode_hex_field("zzzz", aes.KEY_SIZE_BYTES, "key")

    def test_key_hex_of_wrong_size_is_rejected(self) -> None:
        with pytest.raises(InvalidInputError, match="expected 32 bytes"):
            aes.decode_hex_field("00ff", aes.KEY_SIZE_BYTES, "key")

    def test_nonce_reuse_with_same_key_is_refused(self) -> None:
        parameters = aes.generate_parameters()
        aes.encrypt(PLAINTEXT, parameters.key, parameters.nonce)
        with pytest.raises(InvalidInputError, match="reuse"):
            aes.encrypt("Different plaintext", parameters.key, parameters.nonce)

    def test_same_nonce_with_different_key_is_allowed(self) -> None:
        nonce = aes.generate_parameters().nonce
        aes.encrypt(PLAINTEXT, aes.generate_parameters().key, nonce)
        aes.encrypt(PLAINTEXT, aes.generate_parameters().key, nonce)

    def test_non_base64_ciphertext_is_rejected(self) -> None:
        parameters = aes.generate_parameters()
        with pytest.raises(InvalidInputError, match="Base64"):
            aes.decrypt("this is not base64!", parameters.key, parameters.nonce)

    def test_ciphertext_shorter_than_tag_is_rejected(self) -> None:
        parameters = aes.generate_parameters()
        short = base64.b64encode(b"\x00" * 4).decode("ascii")
        with pytest.raises(DecryptionError, match="too short"):
            aes.decrypt(short, parameters.key, parameters.nonce)


class TestChaCha20:
    def test_generated_parameters_have_correct_sizes(self) -> None:
        parameters = chacha20.generate_parameters()
        assert len(parameters.key) == 32
        assert len(parameters.nonce) == 12

    def test_encrypt_decrypt_round_trip(self) -> None:
        parameters = chacha20.generate_parameters()
        result = chacha20.encrypt(PLAINTEXT, parameters.key, parameters.nonce)
        assert chacha20.decrypt(result.ciphertext_b64, parameters.key, parameters.nonce) == PLAINTEXT

    def test_wrong_key_is_rejected(self) -> None:
        parameters = chacha20.generate_parameters()
        result = chacha20.encrypt(PLAINTEXT, parameters.key, parameters.nonce)
        with pytest.raises(DecryptionError):
            chacha20.decrypt(result.ciphertext_b64, chacha20.generate_parameters().key, parameters.nonce)

    def test_wrong_nonce_is_rejected(self) -> None:
        parameters = chacha20.generate_parameters()
        result = chacha20.encrypt(PLAINTEXT, parameters.key, parameters.nonce)
        with pytest.raises(DecryptionError):
            chacha20.decrypt(result.ciphertext_b64, parameters.key, chacha20.generate_parameters().nonce)

    def test_tampered_ciphertext_is_rejected(self) -> None:
        parameters = chacha20.generate_parameters()
        result = chacha20.encrypt(PLAINTEXT, parameters.key, parameters.nonce)
        with pytest.raises(DecryptionError, match="Authentication failed"):
            chacha20.decrypt(flip_ciphertext_byte(result.ciphertext_b64), parameters.key, parameters.nonce)

    @pytest.mark.parametrize("key_size", [0, 16, 31, 33])
    def test_invalid_key_length_is_rejected(self, key_size: int) -> None:
        parameters = chacha20.generate_parameters()
        with pytest.raises(InvalidInputError):
            chacha20.encrypt(PLAINTEXT, b"\x00" * key_size, parameters.nonce)

    def test_invalid_nonce_length_is_rejected(self) -> None:
        parameters = chacha20.generate_parameters()
        with pytest.raises(InvalidInputError):
            chacha20.encrypt(PLAINTEXT, parameters.key, b"\x00" * 16)

    def test_malformed_key_hex_is_rejected(self) -> None:
        with pytest.raises(InvalidInputError, match="hexadecimal"):
            chacha20.decode_hex_field("nothex", chacha20.KEY_SIZE_BYTES, "key")

    def test_ciphertext_shorter_than_tag_is_rejected(self) -> None:
        parameters = chacha20.generate_parameters()
        short = base64.b64encode(b"\x00" * 8).decode("ascii")
        with pytest.raises(DecryptionError, match="too short"):
            chacha20.decrypt(short, parameters.key, parameters.nonce)