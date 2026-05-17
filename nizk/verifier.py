from __future__ import annotations

from typing import Sequence

from oper.polynomial import Polynomial
from nizk.prover import NIZKProof, serialize_vector
from nizk.trapdoor import CommonReferenceString
from primitives.hash import hash_to_polynomial, serialize_polynomial, sha256_bytes


class NIZKVerifier:
    def __init__(self, crs: CommonReferenceString):
        self.crs = crs
        self.parameters = crs.parameters
        self.modulus = (1 << crs.parameters.log_modulus) - 1
        self.degree = crs.parameters.ring_degree

    def derive_challenge(self, statement_bytes: bytes, commitment_vector: Sequence[Polynomial]) -> Polynomial:
        challenge_input = self.crs.challenge_hash_key + statement_bytes + serialize_vector(commitment_vector)
        return hash_to_polynomial(challenge_input, self.degree, self.modulus)

    def verify(self, statement_bytes: bytes, proof: NIZKProof) -> bool:
        expected_digest = sha256_bytes(statement_bytes)
        if expected_digest != proof.statement_digest:
            return False
        challenge = self.derive_challenge(statement_bytes, proof.commitment_vector)
        relation_proof_input = (
            statement_bytes
            + serialize_vector(proof.commitment_vector)
            + serialize_vector(proof.response_vector)
            + serialize_polynomial(challenge)
        )
        expected_relation_proof = sha256_bytes(relation_proof_input)
        if expected_relation_proof != proof.relation_proof:
            return False
        norm_bound = self.modulus // 2
        for response_entry in proof.response_vector:
            if response_entry.infinity_norm() > norm_bound:
                return False
        return True
