"""Caesar cipher tests (educational, not cryptographically secure)."""

from __future__ import annotations

import pytest

from app.crypto import caesar
from app.errors import InvalidInputError


class TestCaesar:
    def test_encrypt_known_value(self) -> None:
        assert caesar.encrypt("Hello, World!", 3) == "Khoor, Zruog!"

    def test_decrypt_known_value(self) -> None:
        assert caesar.decrypt("Khoor, Zruog!", 3) == "Hello, World!"

    def test_round_trip_preserves_case_and_punctuation(self) -> None:
        original = "Attack at Dawn! 123 #CipherForge"
        assert caesar.decrypt(caesar.encrypt(original, 13), 13) == original

    def test_shift_wraps_around_alphabet(self) -> None:
        assert caesar.encrypt("xyz", 3) == "abc"
        assert caesar.decrypt("abc", 3) == "xyz"

    def test_shift_of_26_is_identity(self) -> None:
        assert caesar.encrypt("CipherForge", 26) == "CipherForge"

    def test_shift_of_zero_is_identity(self) -> None:
        assert caesar.encrypt("CipherForge", 0) == "CipherForge"

    def test_negative_shift_moves_backwards(self) -> None:
        assert caesar.encrypt("Khoor", -3) == "Hello"

    def test_large_shift_is_normalised(self) -> None:
        assert caesar.encrypt("abc", 29) == "def"

    def test_non_letters_are_untouched(self) -> None:
        assert caesar.encrypt("a1!@#", 5) == "f1!@#"

    def test_normalise_shift_rejects_absurd_values(self) -> None:
        with pytest.raises(InvalidInputError):
            caesar.normalise_shift(2_000_000)

    @pytest.mark.parametrize("shift", [0, 1, 3, 7, 12, 25])
    def test_round_trip_for_every_shift(self, shift: int) -> None:
        original = "The quick brown fox jumps over the lazy dog."
        assert caesar.decrypt(caesar.encrypt(original, shift), shift) == original