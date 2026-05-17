from __future__ import annotations

from dataclasses import dataclass
from typing import List, Tuple

from mixnet.bdlop import BDLOPScheme
from nizk.trapdoor import CommonReferenceString, EquivocationTrapdoor, generate_crs_with_trapdoor
from onyx.dfhe import DeniableFHE, DeniablePublicKey, DeniableSecretKey
from parameters import SystemParameters
from primitives.samplers import sample_bytes
from thresholdizer.tfhe import ThresholdSecretShare
from thresholdizer.ut import UTPublicParameters, UniversalThresholdizer


@dataclass
class ElectionPublicParameters:
    dfhe_public_key: DeniablePublicKey
    ut_public_parameters: UTPublicParameters
    nizk_crs: CommonReferenceString
    bdlop_scheme: BDLOPScheme
    election_identifier: bytes
    candidate_count: int


@dataclass
class SetupArtifacts:
    public_parameters: ElectionPublicParameters
    trustee_shares: List[ThresholdSecretShare]
    equivocation_trapdoor: EquivocationTrapdoor
    deniable_fhe: DeniableFHE
    universal_thresholdizer: UniversalThresholdizer


class SetupAuthority:
    def __init__(self, parameters: SystemParameters):
        self.parameters = parameters

    def run_setup(self) -> SetupArtifacts:
        deniable_fhe = DeniableFHE(self.parameters.dfhe)
        dfhe_public_key, dfhe_secret_key = deniable_fhe.generate_keys()
        universal_thresholdizer = UniversalThresholdizer(deniable_fhe, self.parameters.ut)
        ut_public_parameters, trustee_shares = universal_thresholdizer.setup(
            dfhe_public_key, dfhe_secret_key
        )
        nizk_crs, equivocation_trapdoor = generate_crs_with_trapdoor(self.parameters.nizk)
        bdlop_scheme = BDLOPScheme(
            degree=self.parameters.mixnet.ring_degree,
            modulus=(1 << self.parameters.mixnet.log_modulus) - 1,
            rank=self.parameters.mixnet.commitment_rank,
            width=self.parameters.mixnet.commitment_width,
            message_length=4,
        )
        election_identifier = sample_bytes(32)
        public_parameters = ElectionPublicParameters(
            dfhe_public_key=dfhe_public_key,
            ut_public_parameters=ut_public_parameters,
            nizk_crs=nizk_crs,
            bdlop_scheme=bdlop_scheme,
            election_identifier=election_identifier,
            candidate_count=self.parameters.election.number_of_candidates,
        )
        return SetupArtifacts(
            public_parameters=public_parameters,
            trustee_shares=trustee_shares,
            equivocation_trapdoor=equivocation_trapdoor,
            deniable_fhe=deniable_fhe,
            universal_thresholdizer=universal_thresholdizer,
        )
