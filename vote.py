from __future__ import annotations

from dataclasses import dataclass
from typing import List, Sequence

from oper.polynomial import Polynomial
from nizk.prover import NIZKProof, NIZKProver
from nizk.trapdoor import CommonReferenceString
from onyx.deniability import EncryptionRandomness
from onyx.dfhe import DeniableCiphertext, DeniableFHE
from parameters import SystemParameters
from primitives.hash import serialize_polynomial, sha256_bytes
from register import VoterRegistrationState
from setup import ElectionPublicParameters


@dataclass
class Ballot:
    vote_ciphertext: DeniableCiphertext
    credential_ciphertext: DeniableCiphertext
    nizk_proof: NIZKProof
    statement_bytes: bytes


@dataclass
class VoterLocalState:
    vote_value: int
    credential_value: int
    vote_randomness: EncryptionRandomness
    credential_randomness: EncryptionRandomness
    nizk_randomness: List[Polynomial]
    nizk_masking: List[Polynomial]
    ballot: Ballot


def build_statement_bytes(
    vote_ciphertext: DeniableCiphertext,
    credential_ciphertext: DeniableCiphertext,
    public_parameters: ElectionPublicParameters,
) -> bytes:
    aggregate = (
        serialize_polynomial(vote_ciphertext.aggregated.component_c0)
        + serialize_polynomial(vote_ciphertext.aggregated.component_c1)
        + serialize_polynomial(credential_ciphertext.aggregated.component_c0)
        + serialize_polynomial(credential_ciphertext.aggregated.component_c1)
        + public_parameters.election_identifier
    )
    return aggregate


def build_witness_bytes(
    vote_value: int, credential_value: int, vote_randomness: EncryptionRandomness, credential_randomness: EncryptionRandomness
) -> bytes:
    parts = [
        vote_value.to_bytes(4, "big", signed=False),
        credential_value.to_bytes(64, "big", signed=False),
    ]
    for polynomial in vote_randomness.message_randomness:
        parts.append(serialize_polynomial(polynomial))
    for component in vote_randomness.selector_randomness:
        for polynomial in component:
            parts.append(serialize_polynomial(polynomial))
    for value in vote_randomness.selector_message_values:
        parts.append(value.to_bytes(4, "big", signed=False))
    for polynomial in credential_randomness.message_randomness:
        parts.append(serialize_polynomial(polynomial))
    for component in credential_randomness.selector_randomness:
        for polynomial in component:
            parts.append(serialize_polynomial(polynomial))
    for value in credential_randomness.selector_message_values:
        parts.append(value.to_bytes(4, "big", signed=False))
    return b"".join(parts)


class VotingClient:
    def __init__(self, parameters: SystemParameters, dfhe: DeniableFHE, crs: CommonReferenceString):
        self.parameters = parameters
        self.dfhe = dfhe
        self.crs = crs
        self.prover = NIZKProver(crs)

    def cast_ballot(
        self,
        vote_value: int,
        voter_state: VoterRegistrationState,
    ) -> VoterLocalState:
        public_parameters = voter_state.public_parameters
        vote_ciphertext, vote_randomness = self.dfhe.encrypt(public_parameters.dfhe_public_key, vote_value)
        credential_plaintext = voter_state.credential.credential_id % self.parameters.dfhe.ring.plaintext_modulus
        credential_ciphertext, credential_randomness = self.dfhe.encrypt(
            public_parameters.dfhe_public_key, credential_plaintext
        )
        statement_bytes = build_statement_bytes(vote_ciphertext, credential_ciphertext, public_parameters)
        witness_bytes = build_witness_bytes(
            vote_value=vote_value,
            credential_value=credential_plaintext,
            vote_randomness=vote_randomness,
            credential_randomness=credential_randomness,
        )
        proof, commitment_randomness, masking_vector = self.prover.prove(statement_bytes, witness_bytes)
        ballot = Ballot(
            vote_ciphertext=vote_ciphertext,
            credential_ciphertext=credential_ciphertext,
            nizk_proof=proof,
            statement_bytes=statement_bytes,
        )
        local_state = VoterLocalState(
            vote_value=vote_value,
            credential_value=credential_plaintext,
            vote_randomness=vote_randomness,
            credential_randomness=credential_randomness,
            nizk_randomness=commitment_randomness,
            nizk_masking=masking_vector,
            ballot=ballot,
        )
        return local_state
