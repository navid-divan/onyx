from __future__ import annotations

from dataclasses import dataclass
from typing import List, Sequence, Tuple

from oper.lagrange import lagrange_coefficients
from primitives.samplers import sample_field_element


@dataclass
class PolynomialShare:
    party_index: int
    value: int


class ShamirSecretSharing:
    def __init__(self, modulus: int):
        self.modulus = modulus

    def random_polynomial_with_secret(self, secret: int, degree: int) -> List[int]:
        coefficients = [secret % self.modulus]
        for _ in range(degree):
            coefficients.append(sample_field_element(self.modulus))
        return coefficients

    def evaluate(self, coefficients: Sequence[int], point: int) -> int:
        accumulator = 0
        power = 1
        for coefficient in coefficients:
            accumulator = (accumulator + coefficient * power) % self.modulus
            power = (power * point) % self.modulus
        return accumulator

    def share(self, secret: int, parties: int, threshold: int) -> Tuple[List[PolynomialShare], List[int]]:
        coefficients = self.random_polynomial_with_secret(secret, threshold)
        shares = []
        for party_index in range(1, parties + 1):
            value = self.evaluate(coefficients, party_index)
            shares.append(PolynomialShare(party_index=party_index, value=value))
        return shares, coefficients

    def reconstruct(self, shares: Sequence[PolynomialShare]) -> int:
        points = [share.party_index for share in shares]
        values = [share.value for share in shares]
        coefficients = lagrange_coefficients(points, self.modulus)
        accumulator = 0
        for index, value in zip(points, values):
            accumulator = (accumulator + coefficients[index] * value) % self.modulus
        return accumulator
