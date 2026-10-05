"""Base64 and hexadecimal encoding tests, including invalid input handling."""

from __future__ import annotations

import pytest

from app.encoding import base64 as base64_service
from app.encoding import hex as hex_service
from app.errors import InvalidEncodingError


class TestBase64:
    def test_encode_known_value(self) -> None:
        assert base64_service.encode("CipherForge") == "Q2lwaGVyRm9yZ2U="

    def test_encode_empty_string(self) -> None:
        assert base64_service.encode("") == ""

    def test_encode_handles_unicode(self) -> None:
        assert base64_service.encode("héllo") == "aMOpbGxv"

    def test_round_trip(self) -> None:
        original = "Encode. Encrypt. Hash. 🚀"
        assert base64_service.decode(base64_service.encode(original)) == original

    def test_decode_known_value(self) -> None:
        assert base64_service.decode("Q2lwaGVyRm9yZ2U=") == "CipherForge"

    def test_decode_tolerates_line_breaks(self) -> None:
        assert base64_service.decode("Q2lw\naGVy\nRm9y\nZ2U=") == "CipherForge"

    @pytest.mark.parametrize("value", ["not base64!", "Q2lwaGVyRm9yZ2U", "@@@@", "a"])
    def test_decode_invalid_input(self, value: str) -> None:
        with pytest.raises(InvalidEncodingError):
            base64_service.decode(value)

    def test_decode_empty_input(self) -> None:
        with pytest.raises(InvalidEncodingError):
            base64_service.decode("   ")

    def test_decode_non_utf8_payload_reports_clear_error(self) -> None:
        with pytest.raises(InvalidEncodingError, match="not valid UTF-8"):
            base64_service.decode("//79")


class TestHex:
    def test_encode_known_value(self) -> None:
        assert hex_service.encode("abc") == "616263"

    def test_encode_empty_string(self) -> None:
        assert hex_service.encode("") == ""

    def test_decode_known_value(self) -> None:
        assert hex_service.decode("616263") == "abc"

    def test_decode_accepts_prefixes_and_spaces(self) -> None:
        assert hex_service.decode("0x61 0x62 0x63") == "abc"

    def test_round_trip(self) -> None:
        original = "CipherForge"
        assert hex_service.decode(hex_service.encode(original)) == original

    @pytest.mark.parametrize("value", ["zz", "61626", "0g", "61 62 6"])
    def test_decode_invalid_input(self, value: str) -> None:
        with pytest.raises(InvalidEncodingError):
            hex_service.decode(value)

    def test_decode_empty_input(self) -> None:
        with pytest.raises(InvalidEncodingError):
            hex_service.decode("  ")

    def test_decode_non_utf8_payload_reports_clear_error(self) -> None:
        with pytest.raises(InvalidEncodingError, match="not valid UTF-8"):
            hex_service.decode("fffe")