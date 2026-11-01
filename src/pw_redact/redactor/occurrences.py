# Copyright 2026 Protocol Wealth LLC
# Licensed under the MIT License
# https://github.com/Protocol-Wealth/pw-redact-core

"""Find every occurrence of a value, ignoring case, look-alikes and spacing.

A detector may catch "John Smith" once and miss "JOHN SMITH" later, or catch
"AB123456" and miss "ab123456" or a copy written with a non-breaking hyphen.
Both the engine (to replace every occurrence) and the output leak check (to
find what is left) need the same notion of "the same value", so it lives here.

Two strings are the same value when they are equal after ``canonicalize()``
(look-alike dashes and spaces mapped, invisible characters dropped), Unicode
case folding, and collapsing every whitespace run to one space.
"""

from __future__ import annotations

from .unicode_canon import canonicalize

# Values shorter than this are not searched for: "Mr", "TX" or "Al" would match
# ordinary text. The engine and the leak check share it, so every value the
# leak check looks for has already been replaced everywhere by the engine.
MIN_MATCH_LENGTH = 5


def fold(text: str) -> tuple[str, list[int]]:
    """Return ``(folded_text, index_map)``.

    ``index_map[i]`` is the offset in ``text`` of folded character ``i``; a
    final entry equals ``len(text)``. Case folding can expand one character
    ("ß" -> "ss"); every resulting character maps to the same source offset.
    """
    canon, canon_map = canonicalize(text)
    out: list[str] = []
    index_map: list[int] = []
    for j, ch in enumerate(canon):
        if ch.isspace():
            if out and out[-1] == " ":
                continue
            out.append(" ")
            index_map.append(canon_map[j])
            continue
        for folded_ch in ch.casefold():
            out.append(folded_ch)
            index_map.append(canon_map[j])
    index_map.append(len(text))
    return "".join(out), index_map


def _is_word(ch: str) -> bool:
    return ch.isalnum() or ch == "_"


def find_occurrences(
    value: str, text: str, folded: tuple[str, list[int]] | None = None
) -> list[tuple[int, int]]:
    """Return the ``[start, end)`` spans of ``text`` that are the same value.

    Pass ``folded=fold(text)`` to reuse the folding across many values.
    """
    folded_value = fold(value)[0].strip(" ")
    if not folded_value:
        return []
    folded_text, index_map = folded if folded is not None else fold(text)
    # Word guards only at ends that are word characters, so "Smith" does not
    # match inside "Blacksmith" but "(212) 555-0199" still matches after a
    # space. str.find keeps this linear and fast for many values on long text.
    guard_start = _is_word(folded_value[0])
    guard_end = _is_word(folded_value[-1])
    n = len(folded_value)
    spans = []
    pos = folded_text.find(folded_value)
    while pos != -1:
        end = pos + n
        if not (guard_start and pos > 0 and _is_word(folded_text[pos - 1])) and not (
            guard_end and end < len(folded_text) and _is_word(folded_text[end])
        ):
            spans.append((index_map[pos], index_map[end - 1] + 1))
        pos = folded_text.find(folded_value, pos + 1)
    return spans
