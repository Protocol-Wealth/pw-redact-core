# Copyright 2026 Protocol Wealth LLC
# Licensed under the MIT License
# https://github.com/Protocol-Wealth/pw-redact-core

"""Every third-party module the package imports is a declared dependency."""

from __future__ import annotations

import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _declared() -> set[str]:
    deps = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]["dependencies"]
    names = set()
    for dep in deps:
        name = dep.split(";")[0]
        for sep in "<>=!~[ ":
            name = name.split(sep)[0]
        names.add(name.strip().lower())
    return names


def test_regex_is_declared():
    # regex_patterns.py imports the third-party "regex" module for possessive
    # quantifiers; it used to be present only as a transitive dependency.
    assert "import regex" in (ROOT / "src/pw_redact/redactor/regex_patterns.py").read_text()
    assert "regex" in _declared()
