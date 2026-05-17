from __future__ import annotations

import time
from contextlib import contextmanager
from typing import Any, Dict, Iterator

from primitives.hash import sha256_bytes


class TimingTracker:
    def __init__(self) -> None:
        self.timings: Dict[str, float] = {}

    @contextmanager
    def measure(self, label: str) -> Iterator[None]:
        start = time.perf_counter()
        yield
        elapsed = time.perf_counter() - start
        self.timings[label] = self.timings.get(label, 0.0) + elapsed

    def reset(self) -> None:
        self.timings.clear()

    def get(self, label: str) -> float:
        return self.timings.get(label, 0.0)

    def total(self) -> float:
        return sum(self.timings.values())

    def report(self) -> str:
        lines = []
        column_width = max((len(label) for label in self.timings), default=0)
        for label in sorted(self.timings):
            seconds = self.timings[label]
            lines.append(f"  {label.ljust(column_width)}  {seconds:8.4f} s")
        lines.append(f"  {'TOTAL'.ljust(column_width)}  {self.total():8.4f} s")
        return "\n".join(lines)


def safe_int_to_bytes(value: int, length: int = 32) -> bytes:
    return (value % (1 << (8 * length))).to_bytes(length, "big")


def commitment_digest(payload: bytes) -> bytes:
    return sha256_bytes(payload)


def derive_voter_identifier(index: int, registration_salt: bytes) -> bytes:
    return sha256_bytes(registration_salt + index.to_bytes(8, "big"))


def derive_pseudonym(identifier: bytes, public_key_digest: bytes) -> bytes:
    return sha256_bytes(identifier + public_key_digest)


def format_timing_dict(timings: Dict[str, float]) -> str:
    lines = []
    column_width = max((len(label) for label in timings), default=0)
    for label, seconds in sorted(timings.items()):
        lines.append(f"  {label.ljust(column_width)}  {seconds:8.4f} s")
    return "\n".join(lines)
