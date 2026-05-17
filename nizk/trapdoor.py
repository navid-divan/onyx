from __future__ import annotations

from dataclasses import dataclass
from typing import List, Tuple

from oper.polynomial import Polynomial
from parameters import NIZKParameters
from primitives.samplers import (
    sample_gaussian_polynomial,
    sample_ternary_polynomial,
    sample_uniform_polynomial,
)


@dataclass
class CommitmentMatrices:
    matrix_a_com: List[List[Polynomial]]
    matrix_b_com: List[List[Polynomial]]
    matrix_b_com_prime: List[List[Polynomial]]
    challenge_matrix: List[List[Polynomial]]


@dataclass
class EquivocationTrapdoor:
    trapdoor_matrix: List[List[Polynomial]]
    parameters: NIZKParameters


@dataclass
class CommonReferenceString:
    matrices: CommitmentMatrices
    challenge_hash_key: bytes
    parameters: NIZKParameters


def sample_random_polynomial_matrix(rows: int, columns: int, degree: int, modulus: int) -> List[List[Polynomial]]:
    return [
        [sample_uniform_polynomial(degree, modulus) for _ in range(columns)]
        for _ in range(rows)
    ]


def sample_ternary_polynomial_matrix(rows: int, columns: int, degree: int, modulus: int) -> List[List[Polynomial]]:
    return [
        [sample_ternary_polynomial(degree, modulus) for _ in range(columns)]
        for _ in range(rows)
    ]


def matrix_multiply(
    left: List[List[Polynomial]],
    right: List[List[Polynomial]],
    degree: int,
    modulus: int,
) -> List[List[Polynomial]]:
    rows_left = len(left)
    columns_left = len(left[0])
    rows_right = len(right)
    columns_right = len(right[0])
    if columns_left != rows_right:
        raise ValueError("matrix dimension mismatch")
    result = [
        [Polynomial.zero(degree, modulus) for _ in range(columns_right)]
        for _ in range(rows_left)
    ]
    for row_index in range(rows_left):
        for column_index in range(columns_right):
            accumulator = Polynomial.zero(degree, modulus)
            for inner_index in range(columns_left):
                accumulator = accumulator + (left[row_index][inner_index] * right[inner_index][column_index])
            result[row_index][column_index] = accumulator
    return result


def matrix_subtract(
    left: List[List[Polynomial]],
    right: List[List[Polynomial]],
) -> List[List[Polynomial]]:
    return [[left[row][column] - right[row][column] for column in range(len(left[0]))] for row in range(len(left))]


def generate_crs_with_trapdoor(parameters: NIZKParameters) -> Tuple[CommonReferenceString, EquivocationTrapdoor]:
    modulus = (1 << parameters.log_modulus) - 1
    degree = parameters.ring_degree
    matrix_a_com = sample_random_polynomial_matrix(parameters.msis_rank, parameters.mlwe_rank, degree, modulus)
    matrix_b_com = sample_random_polynomial_matrix(parameters.msis_rank, parameters.mlwe_rank, degree, modulus)
    trapdoor_matrix = [
        [sample_gaussian_polynomial(degree, modulus, 2.0, 5) for _ in range(parameters.mlwe_rank)]
        for _ in range(parameters.mlwe_rank)
    ]
    a_times_trapdoor = matrix_multiply(matrix_a_com, trapdoor_matrix, degree, modulus)
    matrix_b_com_prime = matrix_subtract(matrix_b_com, a_times_trapdoor)
    challenge_matrix = sample_random_polynomial_matrix(parameters.msis_rank, parameters.mlwe_rank, degree, modulus)
    matrices = CommitmentMatrices(
        matrix_a_com=matrix_a_com,
        matrix_b_com=matrix_b_com,
        matrix_b_com_prime=matrix_b_com_prime,
        challenge_matrix=challenge_matrix,
    )
    crs = CommonReferenceString(
        matrices=matrices,
        challenge_hash_key=b"onyx-crs-challenge-key",
        parameters=parameters,
    )
    trapdoor = EquivocationTrapdoor(trapdoor_matrix=trapdoor_matrix, parameters=parameters)
    return crs, trapdoor


def encode_witness_to_polynomials(witness_bytes: bytes, degree: int, modulus: int, count: int) -> List[Polynomial]:
    chunk_length = max((modulus.bit_length() + 7) // 8, 4)
    padded = witness_bytes + b"\x00" * (count * degree * chunk_length)
    polynomials = []
    offset = 0
    for _ in range(count):
        coefficients = []
        for _ in range(degree):
            chunk = padded[offset : offset + chunk_length]
            offset += chunk_length
            value = int.from_bytes(chunk, "big") % modulus
            coefficients.append(value)
        polynomials.append(Polynomial(coefficients, degree, modulus))
    return polynomials
