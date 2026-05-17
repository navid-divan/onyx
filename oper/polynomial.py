from __future__ import annotations

from typing import List, Sequence, Union

import numpy as np


class Polynomial:
    __slots__ = ("coefficients", "degree", "modulus", "_half_modulus")

    def __init__(self, coefficients: Sequence[int], degree: int, modulus: int):
        array = np.asarray(coefficients, dtype=np.int64)
        if array.size != degree:
            padded = np.zeros(degree, dtype=np.int64)
            limit = min(array.size, degree)
            padded[:limit] = array[:limit]
            array = padded
        modulus_int = int(modulus)
        reduced = np.mod(array, modulus_int)
        self.coefficients = reduced.astype(np.int64, copy=False)
        self.degree = degree
        self.modulus = modulus_int
        self._half_modulus = modulus_int // 2

    @classmethod
    def zero(cls, degree: int, modulus: int) -> "Polynomial":
        instance = cls.__new__(cls)
        instance.coefficients = np.zeros(degree, dtype=np.int64)
        instance.degree = degree
        instance.modulus = int(modulus)
        instance._half_modulus = instance.modulus // 2
        return instance

    @classmethod
    def constant(cls, value: int, degree: int, modulus: int) -> "Polynomial":
        instance = cls.zero(degree, modulus)
        instance.coefficients[0] = int(value) % instance.modulus
        return instance

    @classmethod
    def from_list(cls, values: Sequence[int], degree: int, modulus: int) -> "Polynomial":
        return cls(values, degree, modulus)

    @classmethod
    def from_numpy(cls, array: np.ndarray, degree: int, modulus: int) -> "Polynomial":
        instance = cls.__new__(cls)
        modulus_int = int(modulus)
        if array.dtype != np.int64:
            array = array.astype(np.int64)
        reduced = np.mod(array, modulus_int)
        if reduced.size != degree:
            padded = np.zeros(degree, dtype=np.int64)
            limit = min(reduced.size, degree)
            padded[:limit] = reduced[:limit]
            reduced = padded
        instance.coefficients = reduced
        instance.degree = degree
        instance.modulus = modulus_int
        instance._half_modulus = modulus_int // 2
        return instance

    def copy(self) -> "Polynomial":
        return Polynomial.from_numpy(self.coefficients.copy(), self.degree, self.modulus)

    def __add__(self, other: "Polynomial") -> "Polynomial":
        result = np.add(self.coefficients, other.coefficients)
        return Polynomial.from_numpy(np.mod(result, self.modulus), self.degree, self.modulus)

    def __sub__(self, other: "Polynomial") -> "Polynomial":
        result = np.subtract(self.coefficients, other.coefficients)
        return Polynomial.from_numpy(np.mod(result, self.modulus), self.degree, self.modulus)

    def __neg__(self) -> "Polynomial":
        result = np.negative(self.coefficients)
        return Polynomial.from_numpy(np.mod(result, self.modulus), self.degree, self.modulus)

    def __mul__(self, other: Union["Polynomial", int]) -> "Polynomial":
        if isinstance(other, int):
            return self.scale(other)
        return self._negacyclic_multiply(other)

    def _negacyclic_multiply(self, other: "Polynomial") -> "Polynomial":
        degree = self.degree
        modulus = self.modulus
        left_centered = self._centered_array()
        right_centered = other._centered_array()
        full = np.convolve(left_centered, right_centered)
        head = full[:degree].copy()
        if full.size > degree:
            tail_length = full.size - degree
            head[:tail_length] -= full[degree:]
        reduced = np.mod(head, modulus)
        return Polynomial.from_numpy(reduced, degree, modulus)

    def _centered_array(self) -> np.ndarray:
        modulus = self.modulus
        half = self._half_modulus
        adjusted = np.where(self.coefficients > half, self.coefficients - modulus, self.coefficients)
        return adjusted.astype(np.int64, copy=False)

    def scale(self, factor: int) -> "Polynomial":
        factor_centered = int(factor) % self.modulus
        if factor_centered > self._half_modulus:
            factor_centered -= self.modulus
        result = self._centered_array() * factor_centered
        return Polynomial.from_numpy(np.mod(result, self.modulus), self.degree, self.modulus)

    def reduce_modulo(self, new_modulus: int) -> "Polynomial":
        reduced = np.mod(self.coefficients, int(new_modulus))
        return Polynomial.from_numpy(reduced, self.degree, int(new_modulus))

    def centered_lift(self) -> List[int]:
        adjusted = self._centered_array()
        return adjusted.tolist()

    def infinity_norm(self) -> int:
        adjusted = self._centered_array()
        if adjusted.size == 0:
            return 0
        return int(np.max(np.abs(adjusted)))

    def l2_norm_squared(self) -> int:
        adjusted = self._centered_array()
        return int(np.sum(adjusted.astype(np.int64) ** 2))

    def evaluate(self, point: int) -> int:
        modulus = self.modulus
        accumulator = 0
        power = 1
        for coefficient in self.coefficients.tolist():
            accumulator = (accumulator + int(coefficient) * power) % modulus
            power = (power * point) % modulus
        return accumulator

    def to_bytes(self) -> bytes:
        byte_length = max((self.modulus.bit_length() + 7) // 8, 1)
        if byte_length <= 8:
            big_endian = self.coefficients.astype(">u8", copy=False).tobytes()
            if byte_length == 8:
                return big_endian
            byte_view = np.frombuffer(big_endian, dtype=np.uint8).reshape(self.degree, 8)
            trimmed = byte_view[:, 8 - byte_length :]
            return trimmed.tobytes()
        coefficients = self.coefficients.tolist()
        return b"".join(int(value).to_bytes(byte_length, "big") for value in coefficients)

    def to_list(self) -> List[int]:
        return [int(value) for value in self.coefficients.tolist()]

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Polynomial):
            return NotImplemented
        if self.degree != other.degree or self.modulus != other.modulus:
            return False
        return bool(np.array_equal(self.coefficients, other.coefficients))

    def __hash__(self) -> int:
        return hash((self.degree, self.modulus, self.coefficients.tobytes()))

    def __repr__(self) -> str:
        head_values = self.coefficients[: min(6, self.degree)].tolist()
        head = ", ".join(str(int(value)) for value in head_values)
        suffix = "..." if self.degree > 6 else ""
        return f"Poly(deg={self.degree}, q~2^{self.modulus.bit_length()}, [{head}{suffix}])"
