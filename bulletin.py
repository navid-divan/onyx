from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List

from primitives.hash import sha256_bytes


@dataclass
class BulletinBoardEntry:
    sequence_index: int
    entry_type: str
    payload: Any
    digest: bytes


@dataclass
class BulletinBoard:
    entries: List[BulletinBoardEntry] = field(default_factory=list)

    def post(self, entry_type: str, payload: Any) -> BulletinBoardEntry:
        sequence_index = len(self.entries)
        digest_input = (
            sequence_index.to_bytes(8, "big")
            + entry_type.encode("utf-8")
            + str(payload).encode("utf-8", errors="replace")
        )
        digest = sha256_bytes(digest_input)
        entry = BulletinBoardEntry(
            sequence_index=sequence_index, entry_type=entry_type, payload=payload, digest=digest
        )
        self.entries.append(entry)
        return entry

    def all_entries(self) -> List[BulletinBoardEntry]:
        return list(self.entries)

    def filter_by_type(self, entry_type: str) -> List[BulletinBoardEntry]:
        return [entry for entry in self.entries if entry.entry_type == entry_type]

    def board_digest(self) -> bytes:
        accumulator = b""
        for entry in self.entries:
            accumulator += entry.digest
        return sha256_bytes(accumulator)

    def publish(self) -> List[BulletinBoardEntry]:
        return self.all_entries()
