from __future__ import annotations

from dataclasses import dataclass
from typing import List, Sequence, Tuple

from onyx.dfhe import DeniableCiphertext, DeniableFHE, DeniablePublicKey
from primitives.hash import sha256_bytes


@dataclass
class SortedEntry:
    vote_ciphertext: DeniableCiphertext
    position_ciphertext: DeniableCiphertext
    credential_ciphertext: DeniableCiphertext
    sort_key: int
    secondary_sort_key: int = 0

    def composite_key(self) -> tuple:
        return (self.sort_key, self.secondary_sort_key)


@dataclass
class SortTranscript:
    comparison_count: int
    transcript_digest: bytes


class OddEvenMergeSort:
    def __init__(self, comparator):
        self.comparator = comparator
        self.compare_count = 0

    def sort(self, entries: List[SortedEntry]) -> Tuple[List[SortedEntry], SortTranscript]:
        sorted_entries = list(entries)
        length = len(sorted_entries)
        if length <= 1:
            return sorted_entries, SortTranscript(comparison_count=0, transcript_digest=sha256_bytes(b"empty"))
        self.compare_count = 0
        padded_length = 1
        while padded_length < length:
            padded_length *= 2
        sentinel_key = max(entry.composite_key() for entry in sorted_entries)
        sentinel_key = (sentinel_key[0] + 10**18, sentinel_key[1] + 10**18)
        sentinel_template = sorted_entries[0]
        padding = [
            SortedEntry(
                vote_ciphertext=sentinel_template.vote_ciphertext,
                position_ciphertext=sentinel_template.position_ciphertext,
                credential_ciphertext=sentinel_template.credential_ciphertext,
                sort_key=sentinel_key[0],
                secondary_sort_key=sentinel_key[1],
            )
            for _ in range(padded_length - length)
        ]
        padded_entries = sorted_entries + padding
        self._batcher_sort(padded_entries, padded_length)
        sorted_entries = padded_entries[:length]
        digest_input = b"".join(
            entry.credential_ciphertext.aggregated.component_c0.to_bytes()
            for entry in sorted_entries
        )
        transcript = SortTranscript(
            comparison_count=self.compare_count, transcript_digest=sha256_bytes(digest_input)
        )
        return sorted_entries, transcript

    def _batcher_sort(self, entries: List[SortedEntry], length: int) -> None:
        block_size = 2
        while block_size <= length:
            half_block = block_size // 2
            step = half_block
            while step >= 1:
                for index in range(length):
                    partner = index ^ step
                    if partner > index:
                        if (index & block_size) == 0:
                            self._compare_and_swap(entries, index, partner, ascending=True)
                        else:
                            self._compare_and_swap(entries, index, partner, ascending=False)
                step //= 2
            block_size *= 2

    def _compare_and_swap(self, entries: List[SortedEntry], left_index: int, right_index: int, ascending: bool = True) -> None:
        if left_index >= len(entries) or right_index >= len(entries):
            return
        self.compare_count += 1
        left_key = entries[left_index].composite_key()
        right_key = entries[right_index].composite_key()
        if ascending:
            if left_key > right_key:
                entries[left_index], entries[right_index] = entries[right_index], entries[left_index]
        else:
            if left_key < right_key:
                entries[left_index], entries[right_index] = entries[right_index], entries[left_index]


class CleansingPipeline:
    def __init__(
        self,
        dfhe: DeniableFHE,
        public_key: DeniablePublicKey,
        equality_gate,
        and_gate,
        conditional_gate,
    ):
        self.dfhe = dfhe
        self.public_key = public_key
        self.equality_gate = equality_gate
        self.and_gate = and_gate
        self.conditional_gate = conditional_gate

    def run(
        self,
        sorted_entries: Sequence[SortedEntry],
        position_marker_ciphertext: DeniableCiphertext,
    ) -> List[DeniableCiphertext]:
        cleaned_votes: List[DeniableCiphertext] = []
        length = len(sorted_entries)
        for index in range(length):
            if index + 1 >= length:
                cleaned_votes.append(
                    self.dfhe.encrypt_constant_with_fixed_randomness(self.public_key, 0)
                )
                continue
            current_entry = sorted_entries[index]
            next_entry = sorted_entries[index + 1]
            equality_credential = self.equality_gate.evaluate(
                current_entry.credential_ciphertext, next_entry.credential_ciphertext
            )
            equality_marker = self.equality_gate.evaluate(
                next_entry.position_ciphertext, position_marker_ciphertext
            )
            combined_condition = self.and_gate.evaluate(equality_credential, equality_marker)
            cleaned_vote = self.conditional_gate.evaluate(
                current_entry.vote_ciphertext, combined_condition
            )
            cleaned_votes.append(cleaned_vote)
        return cleaned_votes
