from __future__ import annotations

from dataclasses import dataclass
from typing import List, Sequence

from oper.polynomial import Polynomial
from nizk.trapdoor import (
    CommonReferenceString,
    EquivocationTrapdoor,
    encode_witness_to_polynomials,
    matrix_multiply,
)
from primitives.hash import hash_to_polynomial, serialize_polynomial, sha256_bytes
from primitives.samplers import (
    sample_gaussian_polynomial,
    sample_ternary_polynomial,
)


@dataclass
class NIZKProof:
    commitment_vector: List[Polynomial]
    response_vector: List[Polynomial]
    relation_proof: bytes
    statement_digest: bytes


def serialize_matrix(matrix: List[List[Polynomial]]) -> bytes:
    pieces = []
    for row in matrix:
        for entry in row:
            pieces.append(serialize_polynomial(entry))
    return b"".join(pieces)


def matrix_vector_multiply(
    matrix: List[List[Polynomial]],
    vector: Sequence[Polynomial],
    degree: int,
    modulus: int,
) -> List[Polynomial]:
    result = []
    for row in matrix:
        accumulator = Polynomial.zero(degree, modulus)
        for entry, value in zip(row, vector):
            accumulator = accumulator + (entry * value)
        result.append(accumulator)
    return result


def add_polynomial_vectors(
    left: Sequence[Polynomial],
    right: Sequence[Polynomial],
) -> List[Polynomial]:
    return [a + b for a, b in zip(left, right)]


def subtract_polynomial_vectors(
    left: Sequence[Polynomial],
    right: Sequence[Polynomial],
) -> List[Polynomial]:
    return [a - b for a, b in zip(left, right)]


def scale_polynomial_vector(vector: Sequence[Polynomial], scalar: Polynomial) -> List[Polynomial]:
    return [entry * scalar for entry in vector]


def serialize_vector(vector: Sequence[Polynomial]) -> bytes:
    return b"".join(serialize_polynomial(entry) for entry in vector)


class NIZKProver:
    def __init__(self, crs: CommonReferenceString):
        self.crs = crs
        self.parameters = crs.parameters
        self.modulus = (1 << crs.parameters.log_modulus) - 1
        self.degree = crs.parameters.ring_degree

    def derive_challenge(self, statement_bytes: bytes, commitment_vector: Sequence[Polynomial]) -> Polynomial:
        challenge_input = self.crs.challenge_hash_key + statement_bytes + serialize_vector(commitment_vector)
        return hash_to_polynomial(challenge_input, self.degree, self.modulus)

    def commit_to_witness(self, witness_bytes: bytes, commitment_randomness: Sequence[Polynomial]) -> tuple[List[Polynomial], List[Polynomial]]:
        encoded_witness = encode_witness_to_polynomials(witness_bytes, self.degree, self.modulus, self.parameters.mlwe_rank)
        commitment = matrix_vector_multiply(
            self.crs.matrices.matrix_a_com,
            commitment_randomness,
            self.degree,
            self.modulus,
        )
        encoded_term = matrix_vector_multiply(
            self.crs.matrices.matrix_b_com_prime,
            encoded_witness,
            self.degree,
            self.modulus,
        )
        commitment = add_polynomial_vectors(commitment, encoded_term)
        return commitment, encoded_witness

    def prove(self, statement_bytes: bytes, witness_bytes: bytes) -> tuple[NIZKProof, List[Polynomial], List[Polynomial]]:
        commitment_randomness = [
            sample_ternary_polynomial(self.degree, self.modulus)
            for _ in range(self.parameters.mlwe_rank)
        ]
        masking_vector = [
            sample_gaussian_polynomial(self.degree, self.modulus, 10.0, 200)
            for _ in range(self.parameters.mlwe_rank)
        ]
        commitment, encoded_witness = self.commit_to_witness(witness_bytes, commitment_randomness)
        challenge = self.derive_challenge(statement_bytes, commitment)
        response = []
        for randomness_entry, mask_entry, witness_entry in zip(commitment_randomness, masking_vector, encoded_witness):
            response_entry = randomness_entry + mask_entry + (challenge * witness_entry)
            response.append(response_entry)
        relation_proof_input = (
            statement_bytes
            + serialize_vector(commitment)
            + serialize_vector(response)
            + serialize_polynomial(challenge)
        )
        relation_proof = sha256_bytes(relation_proof_input)
        statement_digest = sha256_bytes(statement_bytes)
        proof = NIZKProof(
            commitment_vector=commitment,
            response_vector=response,
            relation_proof=relation_proof,
            statement_digest=statement_digest,
        )
        return proof, commitment_randomness, masking_vector
