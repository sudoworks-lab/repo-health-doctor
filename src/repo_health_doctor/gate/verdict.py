"""Gate verdict precedence helpers."""

from __future__ import annotations


VERDICT_ORDER = {
    "allow_limited": 0,
    "warn": 1,
    "unknown": 2,
    "quarantine": 3,
    "block": 4,
}


def strongest_verdict(candidates: list[str]) -> str:
    if not candidates:
        return "allow_limited"
    return max(candidates, key=lambda value: VERDICT_ORDER.get(value, -1))
