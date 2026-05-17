from __future__ import annotations

from dataclasses import dataclass
from typing import List, Sequence, Tuple

from oper.polynomial import Polynomial
from onyx.bgv import BGVCiphertext, BGVPublicKey, BGVScheme, BGVSecretKey
from parameters import RingParameters, UTParameters
from primitives.samplers import sample_gaussian_polynomial
from thresholdizer.lsss import LinearSecretSharing, MonotoneAccessStructure, ShamirShare


@dataclass
class ThresholdPublicKey:
    bgv_public_key: BGVPublicKey
    access_structure: MonotoneAccessStructure
    ring_parameters: RingParameters


@dataclass
class ThresholdSecretShare:
    party_index: int
    coefficient_shares: List[int]


@dataclass
class PartialDecryption:
    party_index: int
    value: Polynomial


class ThresholdFHE:
    def __init__(self, scheme: BGVScheme, ut_parameters: UTParameters, access_structure: MonotoneAccessStructure):
        self.scheme = scheme
        self.parameters = ut_parameters
        self.ring = scheme.ring
        self.lsss = LinearSecretSharing(self.ring.modulus)
        self.access_structure = access_structure

    def generate_distributed_keys(self) -> Tuple[ThresholdPublicKey, List[ThresholdSecretShare], BGVSecretKey]:
        public_key, secret_key = self.scheme.generate_keys()
        coefficient_shares = self.lsss.share_polynomial(secret_key.secret_polynomial, self.access_structure)
        shares = [
            ThresholdSecretShare(party_index=index + 1, coefficient_shares=coefficient_shares[index])
            for index in range(self.access_structure.parties)
        ]
        return (
            ThresholdPublicKey(
                bgv_public_key=public_key,
                access_structure=self.access_structure,
                ring_parameters=self.ring,
            ),
            shares,
            secret_key,
        )

    def partial_decrypt(self, share: ThresholdSecretShare, ciphertext: BGVCiphertext) -> PartialDecryption:
        share_polynomial = Polynomial(share.coefficient_shares, self.ring.degree, self.ring.modulus)
        partial_value = ciphertext.component_c1 * share_polynomial
        return PartialDecryption(party_index=share.party_index, value=partial_value)

    def combine_partial_decryptions(
        self,
        ciphertext: BGVCiphertext,
        partial_decryptions: Sequence[PartialDecryption],
    ) -> int:
        points = [decryption.party_index for decryption in partial_decryptions]
        from oper.lagrange import lagrange_coefficients
        lagrange = lagrange_coefficients(points, self.ring.modulus)
        aggregated_partial = Polynomial.zero(self.ring.degree, self.ring.modulus)
        for decryption in partial_decryptions:
            scaled = decryption.value.scale(lagrange[decryption.party_index])
            aggregated_partial = aggregated_partial + scaled
        inner_product = ciphertext.component_c0 - aggregated_partial
        lifted = inner_product.centered_lift()
        constant_term = lifted[0] % self.ring.plaintext_modulus
        return constant_term

    def combine_partial_decryptions_polynomial(
        self,
        ciphertext: BGVCiphertext,
        partial_decryptions: Sequence[PartialDecryption],
    ) -> Polynomial:
        points = [decryption.party_index for decryption in partial_decryptions]
        from oper.lagrange import lagrange_coefficients
        lagrange = lagrange_coefficients(points, self.ring.modulus)
        aggregated_partial = Polynomial.zero(self.ring.degree, self.ring.modulus)
        for decryption in partial_decryptions:
            scaled = decryption.value.scale(lagrange[decryption.party_index])
            aggregated_partial = aggregated_partial + scaled
        inner_product = ciphertext.component_c0 - aggregated_partial
        lifted = inner_product.centered_lift()
        reduced = [value % self.ring.plaintext_modulus for value in lifted]
        return Polynomial(reduced, self.ring.degree, self.ring.plaintext_modulus)
