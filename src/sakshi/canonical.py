"""Canonical JSON: one object, exactly one byte representation.

Signatures are over bytes, so two parties must serialise the same object
identically, or a perfectly valid signature fails to verify. Rules:

* keys sorted, no insignificant whitespace, UTF-8
* floats are rejected: 0.1 + 0.2 style rounding and differing float printers
  across languages make them unsafe to sign. Money is a decimal *string*
  ("499.00"), as in ONDC; times are integer unix seconds.
"""

from __future__ import annotations

import json
from typing import Any


def _check(value: Any, path: str = "$") -> None:
    if isinstance(value, float):
        raise TypeError(f"float at {path}: use a decimal string or integer instead")
    if isinstance(value, dict):
        for k, v in value.items():
            if not isinstance(k, str):
                raise TypeError(f"non-string key at {path}")
            _check(v, f"{path}.{k}")
    elif isinstance(value, (list, tuple)):
        for i, v in enumerate(value):
            _check(v, f"{path}[{i}]")
    elif not (value is None or isinstance(value, (str, int, bool))):
        raise TypeError(f"unsupported type {type(value).__name__} at {path}")


def canonical_json(value: Any) -> bytes:
    _check(value)
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
