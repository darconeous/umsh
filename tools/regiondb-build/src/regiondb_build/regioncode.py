"""Radio-facing region identity: ARNCE/HAM-16 short codes and hashed names.

This is a port of `umsh_core::RegionCode`, and a port is a liability: a region
database whose codes disagree with the radios reading them is worse than no
database at all. The Rust implementation stays canonical. What keeps the two
honest is `regions/tests/regioncode-vectors.json`, which carries a digest over
every one of the 47,988 short codes computed on the Rust side; the test suite
recomputes that table here and compares. See
`crates/umsh-regiondb/examples/gen_region_vectors.rs`.
"""

from __future__ import annotations

import hashlib

# ARNCE/HAM-16 packs three characters into one 16-bit chunk, base 40, most
# significant first. Index 0 is the absent character, so a one- or two-
# character code simply leaves the trailing positions at zero.
ARNCE_ALPHABET = "\0ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/-^"
_ARNCE_INDEX = {char: index for index, char in enumerate(ARNCE_ALPHABET)}

LETTER_MIN = 1
LETTER_MAX = 26

TRANSFORM_BASE = 27 * 1600  # 0xA8C0
TWO_LETTER_BASE = TRANSFORM_BASE + 26**3  # 0xED68
ONE_LETTER_BASE = TWO_LETTER_BASE + 26**2  # 0xF00C

SHORT_CODE_MAX_LEN = 3
REGION_NAME_MAX_LEN = 24


class RegionCodeError(ValueError):
    """A string cannot be encoded as the region identity it was asked for."""


def is_short_code_form(text: str) -> bool:
    """Whether `text` occupies the short-code input space.

    One to three ASCII alphanumerics are *always* read as a short code by the
    runtime — there is no way to spell such a name and get a hash instead. A
    custom region whose radio name has this shape has silently claimed an IATA
    or ISO code, which is why the builder rejects one unless the source says
    the short-code identity is deliberate.
    """
    return 1 <= len(text) <= SHORT_CODE_MAX_LEN and all(c.isascii() and c.isalnum() for c in text)


def from_short_code(code: str) -> int:
    """Encode one to three ASCII alphanumerics with ARNCE/HAM-16."""
    if not code:
        raise RegionCodeError("region short code is empty")
    if len(code) > SHORT_CODE_MAX_LEN:
        raise RegionCodeError(f"region short code {code!r} exceeds {SHORT_CODE_MAX_LEN} characters")
    if not all(c.isascii() and c.isalnum() for c in code):
        raise RegionCodeError(f"region short code {code!r} is not ASCII alphanumeric")

    value = 0
    for position in range(SHORT_CODE_MAX_LEN):
        index = _ARNCE_INDEX[code[position].upper()] if position < len(code) else 0
        value = value * 40 + index
    return value


def transform_letter_chunk(encoded: int) -> int:
    """Move an all-letter ARNCE chunk out of the space short codes own.

    Ported verbatim from the protocol spec (`docs/protocol/src/packet-options.md`).
    """
    a = encoded // 1600
    b = (encoded // 40) % 40
    c = encoded % 40

    def is_letter(value: int) -> bool:
        return LETTER_MIN <= value <= LETTER_MAX

    if not is_letter(a):
        return encoded
    if is_letter(b) and is_letter(c):
        return TRANSFORM_BASE + (a - 1) * 26 * 26 + (b - 1) * 26 + (c - 1)
    if is_letter(b) and c == 0:
        return TWO_LETTER_BASE + (a - 1) * 26 + (b - 1)
    if b == 0 and c == 0:
        return ONE_LETTER_BASE + (a - 1)
    return encoded


def fold(name: str) -> str:
    """ASCII-fold a region name.

    Folding stops at ASCII on purpose: correct case folding over the full
    Unicode range is locale-dependent, and a name that folded one way here and
    another way on a radio would be two regions on one mesh.
    """
    return "".join(chr(ord(c) + 32) if "A" <= c <= "Z" else c for c in name)


def from_name(name: str) -> int:
    """Hash a human-readable region name into its 16-bit code."""
    digest = hashlib.sha256(fold(name).encode("utf-8")).digest()
    return transform_letter_chunk(int.from_bytes(digest[:2], "big"))


def from_string(text: str) -> int:
    """Derive the code the runtime would derive for `text`.

    Short-code form wins unconditionally, matching `RegionCode::from_str`.
    """
    text = text.strip()
    if not text:
        raise RegionCodeError("region name is empty")
    if len(text.encode("utf-8")) > REGION_NAME_MAX_LEN:
        raise RegionCodeError(f"region name {text!r} exceeds {REGION_NAME_MAX_LEN} bytes UTF-8")
    if is_short_code_form(text):
        return from_short_code(text)
    return from_name(text)


def letters(code: int) -> str | None:
    """Decode `code` back to an all-letter short code, if it is one.

    Digit-bearing short codes decode faithfully but deliberately return None:
    the same value may equally have come from a hashed name, so displaying one
    as text would name a region it might not be.
    """
    chars = [code // 1600, (code // 40) % 40, code % 40]
    seen_end = False
    out = []
    for index in chars:
        if index == 0:
            seen_end = True
            continue
        if seen_end or not (LETTER_MIN <= index <= LETTER_MAX):
            return None
        out.append(ARNCE_ALPHABET[index])
    return "".join(out) if out else None
