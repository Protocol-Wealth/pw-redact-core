# Copyright 2026 Protocol Wealth LLC
# Licensed under the MIT License
# https://github.com/Protocol-Wealth/pw-redact-core

"""Canonical text for detection, with a map back to the caller's offsets.

Detection patterns are written with ASCII separators (``-`` and space). Text
that uses a look-alike separator (a non-breaking hyphen in an SSN, NBSPs in a
card number) or hides an invisible character inside a value (a zero-width
space, a soft hyphen) would otherwise not match at all. Unicode normalization
(NFC, even NFKC) does not fix this: it leaves U+2011, U+2212, U+00A0 handling
and U+200B / U+00AD untouched for these purposes.

``canonicalize`` maps every look-alike dash to ``-``, every look-alike space
to `` ``, and drops invisible characters. Each output character comes from
exactly one input character, so ``index_map[i]`` is the input offset of output
character ``i``, and a span found in the canonical text maps back to the exact
span of the caller's text, including any characters that were dropped inside
it.
"""

from __future__ import annotations

# Dashes and minus signs that read as "-".
DASHES = frozenset(
    "\u2010"  # hyphen
    "\u2011"  # non-breaking hyphen
    "\u2012"  # figure dash
    "\u2013"  # en dash
    "\u2014"  # em dash
    "\u2015"  # horizontal bar
    "\u2212"  # minus sign
    "\ufe58"  # small em dash
    "\ufe63"  # small hyphen-minus
    "\uff0d"  # fullwidth hyphen-minus
)

# Spaces that read as " ".
SPACES = frozenset(
    "\u00a0"  # no-break space
    "\u1680"  # ogham space mark
    "\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a"  # en quad .. hair space
    "\u202f"  # narrow no-break space
    "\u205f"  # medium mathematical space
    "\u3000"  # ideographic space
)

# Invisible characters, dropped. Mirrors security/input_validator.py, so the
# library path gets the same treatment the HTTP path gets before redaction.
INVISIBLE = frozenset(
    "\u00ad"  # soft hyphen
    "\u034f"  # combining grapheme joiner
    "\u061c"  # arabic letter mark
    "\u115f\u1160"  # hangul fillers
    "\u17b4\u17b5"  # khmer vowel inherent
    "\u180e"  # mongolian vowel separator
    "\u200b\u200c\u200d\u200e\u200f"  # zero-width space, ZWNJ, ZWJ, LRM, RLM
    "\u202a\u202b\u202c\u202d\u202e"  # bidi embedding / override
    "\u2060\u2061\u2062\u2063\u2064"  # word joiner, invisible operators
    "\u2066\u2067\u2068\u2069"  # bidi isolates
    "\u206a\u206b\u206c\u206d\u206e\u206f"  # deprecated formatting
    "\ufeff"  # BOM / zero-width no-break space
    "\ufff9\ufffa\ufffb"  # interlinear annotations
)


def canonicalize(text: str) -> tuple[str, list[int]]:
    """Return ``(canonical_text, index_map)``.

    ``index_map`` has one entry per canonical character (its offset in
    ``text``) plus a final entry equal to ``len(text)``.
    """
    out: list[str] = []
    index_map: list[int] = []
    for i, ch in enumerate(text):
        if ch in INVISIBLE:
            continue
        if ch in DASHES:
            ch = "-"
        elif ch in SPACES:
            ch = " "
        out.append(ch)
        index_map.append(i)
    index_map.append(len(text))
    return "".join(out), index_map


def to_original_span(index_map: list[int], start: int, end: int) -> tuple[int, int]:
    """Map a canonical ``[start, end)`` span to the matching span of the input."""
    if end <= start:
        pos = index_map[start]
        return pos, pos
    return index_map[start], index_map[end - 1] + 1
