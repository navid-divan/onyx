from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, List, Sequence

from oper.polynomial import Polynomial
from onyx.bgv import BGVCiphertext, BGVPublicKey, BGVScheme, BGVSecretKey
from onyx.dfhe import DeniableCiphertext, DeniableFHE, DeniablePublicKey, DeniableSecretKey
from parameters import DFHEParameters, UTParameters
from primitives.hash import sha256_bytes, serialize_polynomial
from thresholdizer.lsss import LinearSecretSharing, MonotoneAccessStructure
from thresholdizer.tfhe import PartialDecryption, ThresholdFHE, ThresholdSecretShare


@dataclass
class UTPublicParameters:
    dfhe_public_key: DeniablePublicKey
    threshold_fhe: ThresholdFHE
    access_structure: MonotoneAccessStructure


@dataclass
class UTPartialEvaluation:
    party_index: int
    partial_value: Polynomial
    proof: bytes


@dataclass
class UTEvaluationTranscript:
    output_ciphertext: BGVCiphertext
    partial_evaluations: List[UTPartialEvaluation]


class UniversalThresholdizer:
    def __init__(self, dfhe: DeniableFHE, ut_parameters: UTParameters):
        self.dfhe = dfhe
        self.parameters = ut_parameters
        self.access_structure = MonotoneAccessStructure(
            parties=ut_parameters.trustees, threshold=ut_parameters.threshold
        )
        self.threshold_fhe = ThresholdFHE(
            scheme=dfhe.scheme,
            ut_parameters=ut_parameters,
            access_structure=self.access_structure,
        )

    def setup(
        self,
        dfhe_public_key: DeniablePublicKey,
        dfhe_secret_key: DeniableSecretKey,
    ) -> tuple[UTPublicParameters, List[ThresholdSecretShare]]:
        lsss = LinearSecretSharing(dfhe.scheme.ring.modulus) if False else LinearSecretSharing(self.dfhe.scheme.ring.modulus)
        coefficient_shares = lsss.share_polynomial(
            dfhe_secret_key.bgv_secret_key.secret_polynomial,
            self.access_structure,
        )
        shares = [
            ThresholdSecretShare(party_index=index + 1, coefficient_shares=coefficient_shares[index])
            for index in range(self.access_structure.parties)
        ]
        return (
            UTPublicParameters(
                dfhe_public_key=dfhe_public_key,
                threshold_fhe=self.threshold_fhe,
                access_structure=self.access_structure,
            ),
            shares,
        )

    def evaluate_circuit(
        self,
        public_parameters: UTPublicParameters,
        circuit: Callable[[BGVScheme, Sequence[BGVCiphertext]], BGVCiphertext],
        ciphertexts: Sequence[DeniableCiphertext],
    ) -> DeniableCiphertext:
        bgv_inputs = [ciphertext.aggregated for ciphertext in ciphertexts]
        result_ciphertext = circuit(self.dfhe.scheme, bgv_inputs)
        return DeniableCiphertext(aggregated=result_ciphertext, component_ciphertexts=[])

    def partial_evaluate(
        self,
        share: ThresholdSecretShare,
        ciphertext: DeniableCiphertext,
    ) -> UTPartialEvaluation:
        partial_decryption = self.threshold_fhe.partial_decrypt(share, ciphertext.aggregated)
        proof_input = (
            share.party_index.to_bytes(4, "big")
            + serialize_polynomial(partial_decryption.value)
            + serialize_polynomial(ciphertext.aggregated.component_c0)
            + serialize_polynomial(ciphertext.aggregated.component_c1)
        )
        proof = sha256_bytes(proof_input)
        return UTPartialEvaluation(
            party_index=share.party_index, partial_value=partial_decryption.value, proof=proof
        )

    def verify_partial(
        self,
        partial_evaluation: UTPartialEvaluation,
        ciphertext: DeniableCiphertext,
    ) -> bool:
        proof_input = (
            partial_evaluation.party_index.to_bytes(4, "big")
            + serialize_polynomial(partial_evaluation.partial_value)
            + serialize_polynomial(ciphertext.aggregated.component_c0)
            + serialize_polynomial(ciphertext.aggregated.component_c1)
        )
        expected = sha256_bytes(proof_input)
        return expected == partial_evaluation.proof

    def combine(
        self,
        ciphertext: DeniableCiphertext,
        partial_evaluations: Sequence[UTPartialEvaluation],
    ) -> int:
        partial_decryptions = [
            PartialDecryption(party_index=partial.party_index, value=partial.partial_value)
            for partial in partial_evaluations
        ]
        return self.threshold_fhe.combine_partial_decryptions(ciphertext.aggregated, partial_decryptions)

    def combine_polynomial(
        self,
        ciphertext: DeniableCiphertext,
        partial_evaluations: Sequence[UTPartialEvaluation],
    ) -> Polynomial:
        partial_decryptions = [
            PartialDecryption(party_index=partial.party_index, value=partial.partial_value)
            for partial in partial_evaluations
        ]
        return self.threshold_fhe.combine_partial_decryptions_polynomial(
            ciphertext.aggregated, partial_decryptions
        )

    def collect_partial_evaluations(
        self,
        shares: Sequence[ThresholdSecretShare],
        ciphertext: DeniableCiphertext,
    ) -> List[UTPartialEvaluation]:
        threshold = self.access_structure.threshold
        return [self.partial_evaluate(share, ciphertext) for share in shares[:threshold]]
