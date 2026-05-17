from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Sequence, Tuple

from oper.lagrange import lagrange_coefficients
from oper.polynomial import Polynomial
from primitives.samplers import sample_uniform_integer


@dataclass
class MonotoneAccessStructure:
    parties: int
    threshold: int

    def is_authorized(self, indices: Sequence[int]) -> bool:
        return len(set(indices)) >= self.threshold


@dataclass
class ShamirShare:
    party_index: int
    value: int


class LinearSecretSharing:
    def __init__(self, modulus: int):
        self.modulus = modulus

    def share(
        self,
        secret: int,
        access_structure: MonotoneAccessStructure,
    ) -> List[ShamirShare]:
        coefficients = [secret % self.modulus]
        for _ in range(access_structure.threshold - 1):
            coefficients.append(sample_uniform_integer(self.modulus))
        shares: List[ShamirShare] = []
        for party_index in range(1, access_structure.parties + 1):
            value = self._evaluate_polynomial(coefficients, party_index)
            shares.append(ShamirShare(party_index=party_index, value=value))
        return shares

    def share_polynomial(
        self,
        secret_polynomial: Polynomial,
        access_structure: MonotoneAccessStructure,
    ) -> List[List[int]]:
        coefficient_shares: List[List[int]] = [[] for _ in range(access_structure.parties)]
        for coefficient in secret_polynomial.to_list():
            shares = self.share(int(coefficient), access_structure)
            for party_index, share in enumerate(shares):
                coefficient_shares[party_index].append(share.value)
        return coefficient_shares

    def reconstruct(self, shares: Sequence[ShamirShare]) -> int:
        points = [share.party_index for share in shares]
        values = [share.value for share in shares]
        coefficients = lagrange_coefficients(points, self.modulus)
        accumulator = 0
        for index, value in zip(points, values):
            accumulator = (accumulator + coefficients[index] * value) % self.modulus
        return accumulator

    def reconstruct_polynomial(
        self,
        shares: Sequence[Tuple[int, List[int]]],
        degree: int,
        modulus: int,
    ) -> Polynomial:
        if not shares:
            raise ValueError("at least one share is required")
        coefficient_count = len(shares[0][1])
        result: List[int] = []
        for coefficient_index in range(coefficient_count):
            party_shares = [
                ShamirShare(party_index=party_index, value=coefficients_list[coefficient_index])
                for party_index, coefficients_list in shares
            ]
            value = self.reconstruct(party_shares)
            result.append(value)
        if len(result) < degree:
            result.extend([0] * (degree - len(result)))
        return Polynomial(result[:degree], degree, modulus)

    def _evaluate_polynomial(self, coefficients: Sequence[int], point: int) -> int:
        accumulator = 0
        power = 1
        for coefficient in coefficients:
            accumulator = (accumulator + coefficient * power) % self.modulus
            power = (power * point) % self.modulus
        return accumulator


class ZeroOneLSSS:
    def __init__(self, modulus: int):
        self.modulus = modulus
        self.shamir = LinearSecretSharing(modulus)

    def share(self, secret: int, access_structure: MonotoneAccessStructure) -> List[ShamirShare]:
        return self.shamir.share(secret, access_structure)

    def reconstruct(self, shares: Sequence[ShamirShare]) -> int:
        return self.shamir.reconstruct(shares)
