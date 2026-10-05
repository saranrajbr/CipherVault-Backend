"""Caesar cipher service for educational purposes.

NOT CRYPTOGRAPHICALLY SECURE.

The Caesar cipher shifts letters by a fixed amount, so it has only 25 meaningful
keys. It is broken instantly by brute force and by frequency analysis. It exists
in CipherForge purely to demonstrate classical substitution ciphers.
"""

from __future__ import annotations

from ..errors import InvalidInputError

ALPHABET_SIZE = 26
UPPERCASE_START = ord("A")
LOWERCASE_START = ord("a")


def normalise_shift(shift: int) -> int:
    """Reduce any integer shift to the range ``0..25``.

    Args:
        shift: Raw shift value supplied by the user.

    Returns:
        The equivalent shift inside ``0..25``.

    Raises:
        InvalidInputError: If the shift is absurdly large.
    """
    if abs(shift) > 1_000_000:
        raise InvalidInputError("Invalid shift: value is out of the supported range.")
    return shift % ALPHABET_SIZE


def _shift_character(character: str, offset: int) -> str:
    """Shift a single ASCII letter, leaving every other character untouched."""
    if "A" <= character <= "Z":
        return chr((ord(character) - UPPERCASE_START + offset) % ALPHABET_SIZE + UPPERCASE_START)
    if "a" <= character <= "z":
        return chr((ord(character) - LOWERCASE_START + offset) % ALPHABET_SIZE + LOWERCASE_START)
    return character


def encrypt(text: str, shift: int) -> str:
    """Shift every letter forward by ``shift`` positions.

    Case is preserved and non-alphabetic characters are left unchanged.

    Args:
        text: Plaintext to transform.
        shift: Shift value. Wraps around the alphabet.

    Returns:
        The shifted text.
    """
    offset = normalise_shift(shift)
    return "".join(_shift_character(character, offset) for character in text)


def decrypt(text: str, shift: int) -> str:
    """Shift every letter backward by ``shift`` positions.

    Args:
        text: Ciphertext to transform.
        shift: The shift that was used to encrypt.

    Returns:
        The recovered plaintext.
    """
    return encrypt(text, -normalise_shift(shift))