"""Small helpers: placeholder expansion and text encodings."""

from __future__ import annotations

import base64
import binascii

_LEET = str.maketrans({"a": "4", "e": "3", "i": "1", "o": "0", "s": "5",
                       "t": "7", "b": "8", "g": "9"})


def leetspeak(text: str) -> str:
    return text.translate(_LEET)


def to_hex(text: str) -> str:
    return binascii.hexlify(text.encode("utf-8")).decode("ascii")


def to_b64(text: str) -> str:
    return base64.b64encode(text.encode("utf-8")).decode("ascii")


def expand_template(template: str, goal: str) -> str:
    """Fill runtime placeholders in an attack template."""
    tokens = {
        "{goal}": goal,
        "{goal_base64}": to_b64(goal),
        "{goal_hex}": to_hex(goal),
        "{goal_leetspeak}": leetspeak(goal),
    }
    out = template
    for token, value in tokens.items():
        out = out.replace(token, value)
    return out