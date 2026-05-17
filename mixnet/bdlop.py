from __future__ import annotations

from dataclasses import dataclass
from typing import List, Sequence

from oper.polynomial import Polynomial
from primitives.hash import serialize_polynomial, sha256_bytes
from primitives.samplers import (
    sample_ternary_polynomial,
    sample_uniform_polynomial,
)


@dataclass
class BDLOPPublicKey:
    matrix_a1: List[List[Polynomial]]
    matrix_a2: List[List[Polynomial]]
    degree: int
    modulus: int


@dataclass
class BDLOPCommitment:
    commitment_top: List[Polynomial]
    commitment_bottom: List[Polynomial]
    randomness: List[Polynomial]


class BDLOPScheme:
    def __init__(self, degree: int, modulus: int, rank: int, width: int, message_length: int):
        self.degree = degree
        self.modulus = modulus
        self.rank = rank
        self.width = width
        self.message_length = message_length

    def setup(self) -> BDLOPPublicKey:
        matrix_a1 = [
            [sample_uniform_polynomial(self.degree, self.modulus) for _ in range(self.width)]
            for _ in range(self.rank)
        ]
        matrix_a2 = [
            [sample_uniform_polynomial(self.degree, self.modulus) for _ in range(self.width)]
            for _ in range(self.message_length)
        ]
        return BDLOPPublicKey(
            matrix_a1=matrix_a1, matrix_a2=matrix_a2, degree=self.degree, modulus=self.modulus
        )

    def commit(self, public_key: BDLOPPublicKey, message: Sequence[Polynomial]) -> BDLOPCommitment:
        randomness = [sample_ternary_polynomial(self.degree, self.modulus) for _ in range(self.width)]
        commitment_top = []
        for row in public_key.matrix_a1:
            accumulator = Polynomial.zero(self.degree, self.modulus)
            for entry, value in zip(row, randomness):
                accumulator = accumulator + (entry * value)
            commitment_top.append(accumulator)
        commitment_bottom = []
        for row, message_entry in zip(public_key.matrix_a2, message):
            accumulator = Polynomial.zero(self.degree, self.modulus)
            for entry, value in zip(row, randomness):
                accumulator = accumulator + (entry * value)
            accumulator = accumulator + message_entry
            commitment_bottom.append(accumulator)
        return BDLOPCommitment(
            commitment_top=commitment_top,
            commitment_bottom=commitment_bottom,
            randomness=randomness,
        )

    def open(
        self,
        public_key: BDLOPPublicKey,
        commitment: BDLOPCommitment,
        message: Sequence[Polynomial],
    ) -> bool:
        for row, expected_value in zip(public_key.matrix_a1, commitment.commitment_top):
            accumulator = Polynomial.zero(self.degree, self.modulus)
            for entry, value in zip(row, commitment.randomness):
                accumulator = accumulator + (entry * value)
            if accumulator != expected_value:
                return False
        for row, expected_value, message_entry in zip(
            public_key.matrix_a2, commitment.commitment_bottom, message
        ):
            accumulator = Polynomial.zero(self.degree, self.modulus)
            for entry, value in zip(row, commitment.randomness):
                accumulator = accumulator + (entry * value)
            accumulator = accumulator + message_entry
            if accumulator != expected_value:
                return False
        return True

    def commitment_digest(self, commitment: BDLOPCommitment) -> bytes:
        pieces = []
        for entry in commitment.commitment_top:
            pieces.append(serialize_polynomial(entry))
        for entry in commitment.commitment_bottom:
            pieces.append(serialize_polynomial(entry))
        return sha256_bytes(b"".join(pieces))
