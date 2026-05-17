from __future__ import annotations

from typing import Iterable

from bulletin import BulletinBoard, BulletinBoardEntry
from nizk.trapdoor import CommonReferenceString
from nizk.verifier import NIZKVerifier
from primitives.hash import serialize_polynomial, sha256_bytes
from vote import Ballot


class BallotValidator:
    def __init__(self, crs: CommonReferenceString):
        self.verifier = NIZKVerifier(crs)

    def is_unique(self, ballot: Ballot, bulletin_board: BulletinBoard) -> bool:
        candidate_digest = sha256_bytes(
            serialize_polynomial(ballot.vote_ciphertext.aggregated.component_c0)
            + serialize_polynomial(ballot.credential_ciphertext.aggregated.component_c0)
        )
        for entry in bulletin_board.filter_by_type("ballot"):
            existing_ballot = entry.payload
            if not isinstance(existing_ballot, Ballot):
                continue
            existing_digest = sha256_bytes(
                serialize_polynomial(existing_ballot.vote_ciphertext.aggregated.component_c0)
                + serialize_polynomial(existing_ballot.credential_ciphertext.aggregated.component_c0)
            )
            if existing_digest == candidate_digest:
                return False
        return True

    def validate(self, ballot: Ballot, bulletin_board: BulletinBoard) -> bool:
        if not self.verifier.verify(ballot.statement_bytes, ballot.nizk_proof):
            return False
        if not self.is_unique(ballot, bulletin_board):
            return False
        return True
