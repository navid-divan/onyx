from __future__ import annotations

from dataclasses import dataclass
from typing import List, Sequence

from oper.polynomial import Polynomial
from onyx.bgv import BGVCiphertext, BGVScheme
from parameters import RingParameters
from primitives.hash import serialize_polynomial, sha256_bytes
from thresholdizer.lsss import LinearSecretSharing
from thresholdizer.tfhe import PartialDecryption, ThresholdFHE, ThresholdSecretShare


@dataclass
class PartialDecryptionShare:
    party_index: int
    decryption_share: Polynomial
    linearity_proof: bytes
    boundedness_proof: bytes


class DistributedDecryption:
    def __init__(self, scheme: BGVScheme, threshold_fhe: ThresholdFHE):
        self.scheme = scheme
        self.threshold_fhe = threshold_fhe
        self.ring = scheme.ring

    def partial_decrypt(
        self,
        share: ThresholdSecretShare,
        ciphertext: BGVCiphertext,
    ) -> PartialDecryptionShare:
        partial = self.threshold_fhe.partial_decrypt(share, ciphertext)
        linearity_input = (
            share.party_index.to_bytes(4, "big")
            + serialize_polynomial(partial.value)
            + serialize_polynomial(ciphertext.component_c1)
        )
        linearity_proof = sha256_bytes(linearity_input)
        boundedness_input = serialize_polynomial(partial.value) + b"bnd"
        boundedness_proof = sha256_bytes(boundedness_input)
        return PartialDecryptionShare(
            party_index=share.party_index,
            decryption_share=partial.value,
            linearity_proof=linearity_proof,
            boundedness_proof=boundedness_proof,
        )

    def verify_partial(
        self,
        partial_share: PartialDecryptionShare,
        ciphertext: BGVCiphertext,
    ) -> bool:
        linearity_input = (
            partial_share.party_index.to_bytes(4, "big")
            + serialize_polynomial(partial_share.decryption_share)
            + serialize_polynomial(ciphertext.component_c1)
        )
        if sha256_bytes(linearity_input) != partial_share.linearity_proof:
            return False
        boundedness_input = serialize_polynomial(partial_share.decryption_share) + b"bnd"
        if sha256_bytes(boundedness_input) != partial_share.boundedness_proof:
            return False
        return True

    def combine(
        self,
        ciphertext: BGVCiphertext,
        partial_shares: Sequence[PartialDecryptionShare],
    ) -> int:
        partial_decryptions = [
            PartialDecryption(party_index=share.party_index, value=share.decryption_share)
            for share in partial_shares
        ]
        return self.threshold_fhe.combine_partial_decryptions(ciphertext, partial_decryptions)

    def combine_polynomial(
        self,
        ciphertext: BGVCiphertext,
        partial_shares: Sequence[PartialDecryptionShare],
    ) -> Polynomial:
        partial_decryptions = [
            PartialDecryption(party_index=share.party_index, value=share.decryption_share)
            for share in partial_shares
        ]
        return self.threshold_fhe.combine_partial_decryptions_polynomial(ciphertext, partial_decryptions)
