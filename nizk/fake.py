from __future__ import annotations

from typing import List, Sequence

from oper.polynomial import Polynomial
from nizk.prover import (
    NIZKProof,
    NIZKProver,
    add_polynomial_vectors,
    matrix_vector_multiply,
    subtract_polynomial_vectors,
    serialize_vector,
)
from nizk.trapdoor import (
    CommonReferenceString,
    EquivocationTrapdoor,
    encode_witness_to_polynomials,
)
from primitives.hash import hash_to_polynomial, serialize_polynomial, sha256_bytes
from primitives.samplers import sample_gaussian_polynomial


class NIZKFaker:
    def __init__(self, crs: CommonReferenceString, trapdoor: EquivocationTrapdoor):
        self.crs = crs
        self.trapdoor = trapdoor
        self.parameters = crs.parameters
        self.modulus = (1 << crs.parameters.log_modulus) - 1
        self.degree = crs.parameters.ring_degree

    def fake(
        self,
        statement_bytes: bytes,
        original_witness_bytes: bytes,
        target_witness_bytes: bytes,
        original_commitment_randomness: Sequence[Polynomial],
        original_masking_vector: Sequence[Polynomial],
        original_proof: NIZKProof,
    ) -> tuple[NIZKProof, List[Polynomial], List[Polynomial]]:
        encoded_original = encode_witness_to_polynomials(
            original_witness_bytes, self.degree, self.modulus, self.parameters.mlwe_rank
        )
        encoded_target = encode_witness_to_polynomials(
            target_witness_bytes, self.degree, self.modulus, self.parameters.mlwe_rank
        )
        differential = subtract_polynomial_vectors(encoded_target, encoded_original)
        adjustment = matrix_vector_multiply(
            self.trapdoor.trapdoor_matrix,
            differential,
            self.degree,
            self.modulus,
        )
        new_commitment_randomness = []
        for index in range(self.parameters.mlwe_rank):
            base_randomness = original_commitment_randomness[index] if index < len(original_commitment_randomness) else Polynomial.zero(self.degree, self.modulus)
            adjustment_entry = adjustment[index] if index < len(adjustment) else Polynomial.zero(self.degree, self.modulus)
            new_commitment_randomness.append(base_randomness + adjustment_entry)
        prover = NIZKProver(self.crs)
        commitment, _ = prover.commit_to_witness(target_witness_bytes, new_commitment_randomness)
        challenge = prover.derive_challenge(statement_bytes, commitment)
        new_masking_vector = [
            sample_gaussian_polynomial(self.degree, self.modulus, 10.0, 200)
            for _ in range(self.parameters.mlwe_rank)
        ]
        response = []
        for randomness_entry, mask_entry, witness_entry in zip(new_commitment_randomness, new_masking_vector, encoded_target):
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
        return proof, new_commitment_randomness, new_masking_vector
