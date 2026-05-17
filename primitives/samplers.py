from __future__ import annotations

import math
import secrets
from typing import List

import numpy as np

from oper.polynomial import Polynomial


_NUMPY_RANDOM = np.random.default_rng(
    int.from_bytes(secrets.token_bytes(32), "big") & ((1 << 63) - 1)
)


def sample_uniform_integer(upper_bound: int) -> int:
    return secrets.randbelow(upper_bound)


def sample_field_element(modulus: int) -> int:
    return secrets.randbelow(modulus)


def sample_bytes(length: int) -> bytes:
    return secrets.token_bytes(length)


def sample_uniform_polynomial(degree: int, modulus: int) -> Polynomial:
    chunks = _NUMPY_RANDOM.integers(low=0, high=modulus, size=degree, dtype=np.int64)
    return Polynomial.from_numpy(chunks, degree, modulus)


def sample_ternary_polynomial(degree: int, modulus: int) -> Polynomial:
    raw = _NUMPY_RANDOM.integers(low=0, high=3, size=degree, dtype=np.int64)
    coefficients = np.where(raw == 2, modulus - 1, raw)
    return Polynomial.from_numpy(coefficients, degree, modulus)


def sample_binary_polynomial(degree: int, modulus: int) -> Polynomial:
    raw = _NUMPY_RANDOM.integers(low=0, high=2, size=degree, dtype=np.int64)
    return Polynomial.from_numpy(raw, degree, modulus)


def sample_gaussian_integer(standard_deviation: float, bound: int) -> int:
    while True:
        candidate = _NUMPY_RANDOM.normal(loc=0.0, scale=standard_deviation)
        rounded = int(round(candidate))
        if abs(rounded) <= bound:
            return rounded


def sample_gaussian_polynomial(degree: int, modulus: int, standard_deviation: float, bound: int) -> Polynomial:
    samples = _NUMPY_RANDOM.normal(loc=0.0, scale=standard_deviation, size=degree)
    rounded = np.rint(samples).astype(np.int64)
    clipped = np.clip(rounded, -bound, bound)
    coefficients = np.mod(clipped, modulus)
    return Polynomial.from_numpy(coefficients, degree, modulus)


def sample_centered_binomial(degree: int, modulus: int, parameter: int) -> Polynomial:
    positive = _NUMPY_RANDOM.integers(low=0, high=2, size=(parameter, degree), dtype=np.int64).sum(axis=0)
    negative = _NUMPY_RANDOM.integers(low=0, high=2, size=(parameter, degree), dtype=np.int64).sum(axis=0)
    coefficients = np.mod(positive - negative, modulus)
    return Polynomial.from_numpy(coefficients, degree, modulus)


def sample_random_permutation(length: int) -> List[int]:
    indices = list(range(length))
    for index_outer in range(length - 1, 0, -1):
        index_inner = secrets.randbelow(index_outer + 1)
        indices[index_outer], indices[index_inner] = indices[index_inner], indices[index_outer]
    return indices
