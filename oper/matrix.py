from __future__ import annotations

from typing import List, Sequence

from oper.polynomial import Polynomial


class RingMatrix:
    __slots__ = ("rows", "columns", "degree", "modulus", "entries")

    def __init__(self, entries: Sequence[Sequence[Polynomial]], rows: int, columns: int, degree: int, modulus: int):
        self.rows = rows
        self.columns = columns
        self.degree = degree
        self.modulus = modulus
        self.entries = [list(row) for row in entries]

    @classmethod
    def zero(cls, rows: int, columns: int, degree: int, modulus: int) -> "RingMatrix":
        entries = [[Polynomial.zero(degree, modulus) for _ in range(columns)] for _ in range(rows)]
        return cls(entries, rows, columns, degree, modulus)

    @classmethod
    def identity(cls, size: int, degree: int, modulus: int) -> "RingMatrix":
        matrix = cls.zero(size, size, degree, modulus)
        unit = Polynomial.constant(1, degree, modulus)
        for index in range(size):
            matrix.entries[index][index] = unit
        return matrix

    def multiply_vector(self, vector: Sequence[Polynomial]) -> List[Polynomial]:
        if len(vector) != self.columns:
            raise ValueError("dimension mismatch in matrix-vector product")
        result = []
        for row_index in range(self.rows):
            accumulator = Polynomial.zero(self.degree, self.modulus)
            for column_index in range(self.columns):
                accumulator = accumulator + (self.entries[row_index][column_index] * vector[column_index])
            result.append(accumulator)
        return result

    def transpose(self) -> "RingMatrix":
        transposed = [[self.entries[row_index][column_index] for row_index in range(self.rows)] for column_index in range(self.columns)]
        return RingMatrix(transposed, self.columns, self.rows, self.degree, self.modulus)

    def get(self, row: int, column: int) -> Polynomial:
        return self.entries[row][column]

    def set(self, row: int, column: int, value: Polynomial) -> None:
        self.entries[row][column] = value

    def column(self, index: int) -> List[Polynomial]:
        return [self.entries[row][index] for row in range(self.rows)]

    def row(self, index: int) -> List[Polynomial]:
        return list(self.entries[index])

    def __repr__(self) -> str:
        return f"RingMatrix({self.rows}x{self.columns}, deg={self.degree})"


def vector_inner_product(left: Sequence[Polynomial], right: Sequence[Polynomial], degree: int, modulus: int) -> Polynomial:
    if len(left) != len(right):
        raise ValueError("vectors must share length for inner product")
    accumulator = Polynomial.zero(degree, modulus)
    for left_entry, right_entry in zip(left, right):
        accumulator = accumulator + (left_entry * right_entry)
    return accumulator


def add_vectors(left: Sequence[Polynomial], right: Sequence[Polynomial]) -> List[Polynomial]:
    if len(left) != len(right):
        raise ValueError("vectors must share length")
    return [a + b for a, b in zip(left, right)]


def subtract_vectors(left: Sequence[Polynomial], right: Sequence[Polynomial]) -> List[Polynomial]:
    if len(left) != len(right):
        raise ValueError("vectors must share length")
    return [a - b for a, b in zip(left, right)]


def scale_vector(vector: Sequence[Polynomial], scalar: Polynomial) -> List[Polynomial]:
    return [entry * scalar for entry in vector]
