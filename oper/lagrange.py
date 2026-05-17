from __future__ import annotations

from typing import Dict, Iterable, List, Sequence


def modular_inverse(value: int, modulus: int) -> int:
    return pow(value % modulus, -1, modulus)


def lagrange_coefficients(points: Sequence[int], modulus: int) -> Dict[int, int]:
    coefficients: Dict[int, int] = {}
    for index_outer in points:
        numerator = 1
        denominator = 1
        for index_inner in points:
            if index_inner == index_outer:
                continue
            numerator = (numerator * (-index_inner)) % modulus
            denominator = (denominator * (index_outer - index_inner)) % modulus
        coefficients[index_outer] = (numerator * modular_inverse(denominator, modulus)) % modulus
    return coefficients


def lagrange_interpolate(points: Sequence[int], values: Sequence[int], modulus: int) -> int:
    coefficients = lagrange_coefficients(points, modulus)
    accumulator = 0
    for index, value in zip(points, values):
        accumulator = (accumulator + coefficients[index] * value) % modulus
    return accumulator


def lagrange_evaluate(points: Sequence[int], values: Sequence[int], evaluation_point: int, modulus: int) -> int:
    accumulator = 0
    for index_outer, value_outer in zip(points, values):
        numerator = 1
        denominator = 1
        for index_inner in points:
            if index_inner == index_outer:
                continue
            numerator = (numerator * (evaluation_point - index_inner)) % modulus
            denominator = (denominator * (index_outer - index_inner)) % modulus
        term = (value_outer * numerator) % modulus
        term = (term * modular_inverse(denominator, modulus)) % modulus
        accumulator = (accumulator + term) % modulus
    return accumulator


def polynomial_evaluate(coefficients: Sequence[int], point: int, modulus: int) -> int:
    accumulator = 0
    power = 1
    for coefficient in coefficients:
        accumulator = (accumulator + coefficient * power) % modulus
        power = (power * point) % modulus
    return accumulator
