from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Sequence

from primitives.hash import sha256_bytes, sha256_int, serialize_int
from primitives.samplers import sample_field_element
from vss.shamir import PolynomialShare, ShamirSecretSharing


@dataclass
class VSSShare:
    party_index: int
    secret_share: int
    randomizer: int


@dataclass
class VSSPublicProof:
    commitments: List[bytes]
    masked_polynomial_coefficients: List[int]


@dataclass
class VSSDealerOutput:
    shares: List[VSSShare]
    public_proof: VSSPublicProof


class HashBasedVSS:
    def __init__(self, modulus: int, parties: int, threshold: int, repetitions: int = 1):
        if parties < 2 * threshold + 1:
            parties = 2 * threshold + 1
        self.modulus = modulus
        self.parties = parties
        self.threshold = threshold
        self.repetitions = repetitions
        self.shamir = ShamirSecretSharing(modulus)

    def _commit(self, secret_share: int, randomizer: int) -> bytes:
        return sha256_bytes(serialize_int(secret_share) + serialize_int(randomizer))

    def share(self, secret: int) -> VSSDealerOutput:
        secret_shares, secret_polynomial = self.shamir.share(secret, self.parties, self.threshold)
        randomizers = [sample_field_element(self.modulus) for _ in range(self.parties)]
        randomizer_polynomial = self.shamir.random_polynomial_with_secret(0, self.threshold)
        commitments = []
        for share, randomizer in zip(secret_shares, randomizers):
            commitment = self._commit(share.value, randomizer)
            commitments.append(commitment)
        challenge_input = b"".join(commitments)
        challenge = sha256_int(challenge_input) % self.modulus
        masked_polynomial = []
        for coefficient_index in range(self.threshold + 1):
            secret_coefficient = secret_polynomial[coefficient_index] if coefficient_index < len(secret_polynomial) else 0
            randomizer_coefficient = randomizer_polynomial[coefficient_index] if coefficient_index < len(randomizer_polynomial) else 0
            masked = (randomizer_coefficient + challenge * secret_coefficient) % self.modulus
            masked_polynomial.append(masked)
        shares = [
            VSSShare(
                party_index=share.party_index,
                secret_share=share.value,
                randomizer=self.shamir.evaluate(randomizer_polynomial, share.party_index),
            )
            for share in secret_shares
        ]
        for share in shares:
            share.randomizer = randomizers[share.party_index - 1]
        public_proof = VSSPublicProof(
            commitments=commitments, masked_polynomial_coefficients=masked_polynomial
        )
        return VSSDealerOutput(shares=shares, public_proof=public_proof)

    def verify_share(self, party_index: int, share: VSSShare, public_proof: VSSPublicProof) -> bool:
        if share.party_index != party_index:
            return False
        if party_index < 1 or party_index > self.parties:
            return False
        expected_commitment = self._commit(share.secret_share, share.randomizer)
        if expected_commitment != public_proof.commitments[party_index - 1]:
            return False
        return True

    def reconstruct(self, shares: Sequence[VSSShare]) -> int:
        polynomial_shares = [
            PolynomialShare(party_index=share.party_index, value=share.secret_share) for share in shares
        ]
        return self.shamir.reconstruct(polynomial_shares)


def share_credential_polynomial(
    vss_protocol: HashBasedVSS, credential: int, length: int
) -> List[VSSDealerOutput]:
    outputs: List[VSSDealerOutput] = []
    chunks = [(credential >> (256 * index)) & ((1 << 256) - 1) for index in range(length)]
    for chunk in chunks:
        outputs.append(vss_protocol.share(chunk % vss_protocol.modulus))
    return outputs
