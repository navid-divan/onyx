from __future__ import annotations

import hashlib
from typing import Iterable, List, Sequence

from oper.polynomial import Polynomial


def sha256_bytes(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def sha256_int(data: bytes) -> int:
    return int.from_bytes(sha256_bytes(data), "big")


def hash_to_field(data: bytes, modulus: int) -> int:
    output_length = max(((modulus.bit_length() + 7) // 8) + 16, 32)
    counter = 0
    accumulator = b""
    while len(accumulator) < output_length:
        accumulator += hashlib.sha256(data + counter.to_bytes(4, "big")).digest()
        counter += 1
    integer_value = int.from_bytes(accumulator[:output_length], "big")
    return integer_value % modulus


def hash_to_polynomial(data: bytes, degree: int, modulus: int) -> Polynomial:
    coefficients: List[int] = []
    counter = 0
    byte_length = max((modulus.bit_length() + 7) // 8, 1) + 8
    while len(coefficients) < degree:
        block = hashlib.sha256(data + counter.to_bytes(8, "big")).digest()
        while len(block) >= byte_length and len(coefficients) < degree:
            chunk = block[:byte_length]
            block = block[byte_length:]
            coefficients.append(int.from_bytes(chunk, "big") % modulus)
        counter += 1
    return Polynomial(coefficients, degree, modulus)


def hash_to_ternary_polynomial(data: bytes, degree: int, modulus: int) -> Polynomial:
    coefficients: List[int] = []
    counter = 0
    while len(coefficients) < degree:
        block = hashlib.sha256(data + counter.to_bytes(8, "big")).digest()
        for byte_value in block:
            if len(coefficients) >= degree:
                break
            selector = byte_value & 3
            if selector == 0 or selector == 3:
                coefficients.append(0)
            elif selector == 1:
                coefficients.append(1)
            else:
                coefficients.append(modulus - 1)
        counter += 1
    return Polynomial(coefficients, degree, modulus)


def concatenate(*items: bytes) -> bytes:
    return b"".join(items)


def serialize_int(value: int, length: int = 32) -> bytes:
    return (value % (1 << (8 * length))).to_bytes(length, "big", signed=False)


def serialize_list_of_ints(values: Sequence[int]) -> bytes:
    parts = [len(values).to_bytes(4, "big")]
    for entry in values:
        parts.append(serialize_int(int(entry), 32))
    return b"".join(parts)


def serialize_polynomial(polynomial: Polynomial) -> bytes:
    header = polynomial.degree.to_bytes(4, "big") + polynomial.modulus.to_bytes(64, "big")
    return header + polynomial.to_bytes()


def serialize_polynomials(polynomials: Iterable[Polynomial]) -> bytes:
    pieces = []
    sequence = list(polynomials)
    pieces.append(len(sequence).to_bytes(4, "big"))
    for polynomial in sequence:
        pieces.append(serialize_polynomial(polynomial))
    return b"".join(pieces)
