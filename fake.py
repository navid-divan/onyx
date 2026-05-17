from __future__ import annotations

from dataclasses import dataclass
from typing import List

from oper.polynomial import Polynomial
from nizk.fake import NIZKFaker
from nizk.trapdoor import CommonReferenceString, EquivocationTrapdoor
from onyx.deniability import EncryptionRandomness
from onyx.dfhe import DeniableFHE, DeniablePublicKey
from primitives.hash import serialize_polynomial
from setup import ElectionPublicParameters
from vote import Ballot, VoterLocalState, build_statement_bytes, build_witness_bytes


@dataclass
class FakeDisclosure:
    fake_vote_value: int
    fake_credential_value: int
    fake_vote_randomness: EncryptionRandomness
    fake_credential_randomness: EncryptionRandomness
    fake_nizk_randomness: List[Polynomial]
    fake_nizk_masking: List[Polynomial]
    original_ballot: Ballot


class FakingProcedure:
    def __init__(self, dfhe: DeniableFHE, crs: CommonReferenceString, trapdoor: EquivocationTrapdoor):
        self.dfhe = dfhe
        self.crs = crs
        self.faker = NIZKFaker(crs, trapdoor)

    def fake_vote(
        self,
        voter_state: VoterLocalState,
        fake_vote_value: int,
        fake_credential_value: int,
        public_parameters: ElectionPublicParameters,
    ) -> FakeDisclosure:
        fake_vote_randomness = self.dfhe.fake(
            public_parameters.dfhe_public_key,
            voter_state.vote_value,
            voter_state.vote_randomness,
            fake_vote_value,
        )
        fake_credential_randomness = self.dfhe.fake(
            public_parameters.dfhe_public_key,
            voter_state.credential_value,
            voter_state.credential_randomness,
            fake_credential_value,
        )
        original_witness_bytes = build_witness_bytes(
            vote_value=voter_state.vote_value,
            credential_value=voter_state.credential_value,
            vote_randomness=voter_state.vote_randomness,
            credential_randomness=voter_state.credential_randomness,
        )
        target_witness_bytes = build_witness_bytes(
            vote_value=fake_vote_value,
            credential_value=fake_credential_value,
            vote_randomness=fake_vote_randomness,
            credential_randomness=fake_credential_randomness,
        )
        fake_proof, fake_commitment_randomness, fake_masking_vector = self.faker.fake(
            statement_bytes=voter_state.ballot.statement_bytes,
            original_witness_bytes=original_witness_bytes,
            target_witness_bytes=target_witness_bytes,
            original_commitment_randomness=voter_state.nizk_randomness,
            original_masking_vector=voter_state.nizk_masking,
            original_proof=voter_state.ballot.nizk_proof,
        )
        return FakeDisclosure(
            fake_vote_value=fake_vote_value,
            fake_credential_value=fake_credential_value,
            fake_vote_randomness=fake_vote_randomness,
            fake_credential_randomness=fake_credential_randomness,
            fake_nizk_randomness=fake_commitment_randomness,
            fake_nizk_masking=fake_masking_vector,
            original_ballot=voter_state.ballot,
        )
