"""Hash service tests using published known-answer vectors, plus bcrypt."""

from __future__ import annotations

import pytest

from app.errors import InvalidInputError
from app.hashing import bcrypt as bcrypt_service
from app.hashing import md5, sha256, sha512

EMPTY = {
    "md5": "d41d8cd98f00b204e9800998ecf8427e",
    "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "sha512": (
        "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
        "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
    ),
}

ABC = {
    "md5": "900150983cd24fb0d6963f7d28e17f72",
    "sha256": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    "sha512": (
        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
        "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
    ),
}


class TestMd5:
    def test_empty_string_known_vector(self) -> None:
        assert md5.hash_text("") == EMPTY["md5"]

    def test_abc_known_vector(self) -> None:
        assert md5.hash_text("abc") == ABC["md5"]

    def test_digest_is_32_hex_characters(self) -> None:
        assert len(md5.hash_text("CipherForge")) == 32


class TestSha256:
    def test_empty_string_known_vector(self) -> None:
        assert sha256.hash_text("") == EMPTY["sha256"]

    def test_abc_known_vector(self) -> None:
        assert sha256.hash_text("abc") == ABC["sha256"]

    def test_digest_is_64_hex_characters(self) -> None:
        assert len(sha256.hash_text("CipherForge")) == 64


class TestSha512:
    def test_empty_string_known_vector(self) -> None:
        assert sha512.hash_text("") == EMPTY["sha512"]

    def test_abc_known_vector(self) -> None:
        assert sha512.hash_text("abc") == ABC["sha512"]

    def test_digest_is_128_hex_characters(self) -> None:
        assert len(sha512.hash_text("CipherForge")) == 128


class TestBcrypt:
    def test_hash_uses_bcrypt_prefix_and_cost(self) -> None:
        password_hash = bcrypt_service.hash_password("correct horse battery staple", 4)
        assert password_hash.startswith("$2b$04$")

    def test_hash_is_not_the_plaintext_password(self) -> None:
        password = "SuperSecret123!"
        password_hash = bcrypt_service.hash_password(password, 4)
        assert password not in password_hash
        assert password_hash != password

    def test_salted_hashes_differ_for_the_same_password(self) -> None:
        first = bcrypt_service.hash_password("same-password", 4)
        second = bcrypt_service.hash_password("same-password", 4)
        assert first != second

    def test_correct_password_verifies(self) -> None:
        password_hash = bcrypt_service.hash_password("correct horse battery staple", 4)
        assert bcrypt_service.verify_password("correct horse battery staple", password_hash) is True

    def test_wrong_password_does_not_verify(self) -> None:
        password_hash = bcrypt_service.hash_password("correct horse battery staple", 4)
        assert bcrypt_service.verify_password("wrong password", password_hash) is False

    def test_empty_password_is_rejected(self) -> None:
        with pytest.raises(InvalidInputError, match="must not be empty"):
            bcrypt_service.hash_password("", 4)

    def test_password_longer_than_72_bytes_is_rejected(self) -> None:
        with pytest.raises(InvalidInputError, match="72 bytes"):
            bcrypt_service.hash_password("A" * 73, 4)

    def test_password_of_exactly_72_bytes_is_accepted(self) -> None:
        password_hash = bcrypt_service.hash_password("A" * 72, 4)
        assert bcrypt_service.verify_password("A" * 72, password_hash) is True

    def test_malformed_hash_is_rejected(self) -> None:
        with pytest.raises(InvalidInputError, match="Invalid bcrypt hash"):
            bcrypt_service.verify_password("password", "definitely-not-a-bcrypt-hash")

    def test_empty_hash_is_rejected(self) -> None:
        with pytest.raises(InvalidInputError, match="must not be empty"):
            bcrypt_service.verify_password("password", "  ")

    @pytest.mark.parametrize("work_factor", [0, 3, 32, -1])
    def test_invalid_work_factor_is_rejected(self, work_factor: int) -> None:
        with pytest.raises(InvalidInputError, match="work factor"):
            bcrypt_service.hash_password("password", work_factor)

    def test_default_work_factor_is_documented(self) -> None:
        assert bcrypt_service.DEFAULT_WORK_FACTOR == 12