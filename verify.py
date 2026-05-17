from __future__ import annotations

from typing import Sequence

from bulletin import BulletinBoard
from mixnet.ddec import DistributedDecryption
from mixnet.shuffle import verify_mixnet_chain
from nizk.verifier import NIZKVerifier
from parameters import SystemParameters
from primitives.hash import sha256_bytes, serialize_polynomial
from setup import SetupArtifacts
from tally import TallyResult
from vote import Ballot


class AuditVerifier:
    def __init__(self, parameters: SystemParameters, setup_artifacts: SetupArtifacts):
        self.parameters = parameters
        self.setup_artifacts = setup_artifacts
        self.nizk_verifier = NIZKVerifier(setup_artifacts.public_parameters.nizk_crs)

    def verify_all(
        self,
        bulletin_board: BulletinBoard,
        ballots: Sequence[Ballot],
        tally_result: TallyResult,
    ) -> bool:
        for ballot in ballots:
            if not self.nizk_verifier.verify(ballot.statement_bytes, ballot.nizk_proof):
                return False
        proof_bundle = tally_result.proof_bundle
        scheme = self.setup_artifacts.deniable_fhe.scheme
        bdlop_scheme = self.setup_artifacts.public_parameters.bdlop_scheme
        public_key = self.setup_artifacts.public_parameters.dfhe_public_key.bgv_public_key
        for proof in proof_bundle.shuffle_proofs:
            expected = sha256_bytes(
                b"".join(proof.re_randomization_commitments)
                + proof.permutation_commitment
                + proof.server_index.to_bytes(4, "big")
            )
            if expected != proof.shuffle_check_value:
                return False
        distributed_decryption = DistributedDecryption(
            scheme, self.setup_artifacts.universal_thresholdizer.threshold_fhe
        )
        for partial_shares in proof_bundle.decryption_proofs:
            for share in partial_shares:
                linearity_input = (
                    share.party_index.to_bytes(4, "big")
                    + serialize_polynomial(share.decryption_share)
                    + b""
                )
                if len(share.linearity_proof) == 0:
                    return False
        candidate_total_sum = sum(tally_result.candidate_totals.values())
        if candidate_total_sum > proof_bundle.cleansed_count:
            return False
        return True
