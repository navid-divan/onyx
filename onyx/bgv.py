from __future__ import annotations

from dataclasses import dataclass
from typing import List, Sequence

from oper.polynomial import Polynomial
from parameters import RingParameters
from primitives.samplers import (
    sample_gaussian_polynomial,
    sample_ternary_polynomial,
    sample_uniform_polynomial,
)


@dataclass
class BGVPublicKey:
    matrix_a: Polynomial
    encryption_b: Polynomial
    ring: RingParameters


@dataclass
class BGVSecretKey:
    secret_polynomial: Polynomial
    ring: RingParameters


@dataclass
class BGVCiphertext:
    component_c0: Polynomial
    component_c1: Polynomial
    ring: RingParameters

    def to_tuple(self):
        return (self.component_c0, self.component_c1)


class BGVScheme:
    def __init__(self, ring_parameters: RingParameters, error_std: float, error_bound: int):
        self.ring = ring_parameters
        self.error_std = error_std
        self.error_bound = error_bound

    def generate_keys(self) -> tuple[BGVPublicKey, BGVSecretKey]:
        secret = sample_ternary_polynomial(self.ring.degree, self.ring.modulus)
        matrix_a = sample_uniform_polynomial(self.ring.degree, self.ring.modulus)
        error = sample_gaussian_polynomial(self.ring.degree, self.ring.modulus, self.error_std, self.error_bound)
        scaled_error = error.scale(self.ring.plaintext_modulus)
        encryption_b = (matrix_a * secret) + scaled_error
        public_key = BGVPublicKey(matrix_a=matrix_a, encryption_b=encryption_b, ring=self.ring)
        secret_key = BGVSecretKey(secret_polynomial=secret, ring=self.ring)
        return public_key, secret_key

    def encrypt(self, public_key: BGVPublicKey, message: int) -> BGVCiphertext:
        return self.encrypt_polynomial(public_key, Polynomial.constant(message % self.ring.plaintext_modulus, self.ring.degree, self.ring.modulus))

    def encrypt_polynomial(self, public_key: BGVPublicKey, message_polynomial: Polynomial) -> BGVCiphertext:
        randomness = sample_ternary_polynomial(self.ring.degree, self.ring.modulus)
        error_one = sample_gaussian_polynomial(self.ring.degree, self.ring.modulus, self.error_std, self.error_bound)
        error_two = sample_gaussian_polynomial(self.ring.degree, self.ring.modulus, self.error_std, self.error_bound)
        scaled_e_one = error_one.scale(self.ring.plaintext_modulus)
        scaled_e_two = error_two.scale(self.ring.plaintext_modulus)
        component_c0 = (public_key.encryption_b * randomness) + scaled_e_two + message_polynomial
        component_c1 = (public_key.matrix_a * randomness) + scaled_e_one
        return BGVCiphertext(component_c0=component_c0, component_c1=component_c1, ring=self.ring)

    def encrypt_with_randomness(
        self,
        public_key: BGVPublicKey,
        message_polynomial: Polynomial,
        randomness: Polynomial,
        error_one: Polynomial,
        error_two: Polynomial,
    ) -> BGVCiphertext:
        scaled_e_one = error_one.scale(self.ring.plaintext_modulus)
        scaled_e_two = error_two.scale(self.ring.plaintext_modulus)
        component_c0 = (public_key.encryption_b * randomness) + scaled_e_two + message_polynomial
        component_c1 = (public_key.matrix_a * randomness) + scaled_e_one
        return BGVCiphertext(component_c0=component_c0, component_c1=component_c1, ring=self.ring)

    def encrypt_zero(self, public_key: BGVPublicKey) -> BGVCiphertext:
        return self.encrypt(public_key, 0)

    def decrypt(self, secret_key: BGVSecretKey, ciphertext: BGVCiphertext) -> int:
        inner_product = ciphertext.component_c0 - (ciphertext.component_c1 * secret_key.secret_polynomial)
        lifted = inner_product.centered_lift()
        constant_term = lifted[0] % self.ring.plaintext_modulus
        return constant_term

    def decrypt_polynomial(self, secret_key: BGVSecretKey, ciphertext: BGVCiphertext) -> Polynomial:
        inner_product = ciphertext.component_c0 - (ciphertext.component_c1 * secret_key.secret_polynomial)
        lifted = inner_product.centered_lift()
        reduced = [value % self.ring.plaintext_modulus for value in lifted]
        return Polynomial(reduced, self.ring.degree, self.ring.plaintext_modulus)

    def add(self, ciphertext_a: BGVCiphertext, ciphertext_b: BGVCiphertext) -> BGVCiphertext:
        return BGVCiphertext(
            component_c0=ciphertext_a.component_c0 + ciphertext_b.component_c0,
            component_c1=ciphertext_a.component_c1 + ciphertext_b.component_c1,
            ring=self.ring,
        )

    def subtract(self, ciphertext_a: BGVCiphertext, ciphertext_b: BGVCiphertext) -> BGVCiphertext:
        return BGVCiphertext(
            component_c0=ciphertext_a.component_c0 - ciphertext_b.component_c0,
            component_c1=ciphertext_a.component_c1 - ciphertext_b.component_c1,
            ring=self.ring,
        )

    def scalar_multiply(self, ciphertext: BGVCiphertext, factor: int) -> BGVCiphertext:
        return BGVCiphertext(
            component_c0=ciphertext.component_c0.scale(factor),
            component_c1=ciphertext.component_c1.scale(factor),
            ring=self.ring,
        )

    def plaintext_multiply(self, ciphertext: BGVCiphertext, plain_polynomial: Polynomial) -> BGVCiphertext:
        return BGVCiphertext(
            component_c0=ciphertext.component_c0 * plain_polynomial,
            component_c1=ciphertext.component_c1 * plain_polynomial,
            ring=self.ring,
        )

    def rerandomize(self, public_key: BGVPublicKey, ciphertext: BGVCiphertext) -> BGVCiphertext:
        fresh_zero = self.encrypt_zero(public_key)
        return self.add(ciphertext, fresh_zero)

    def homomorphic_xor(self, ciphertext_a: BGVCiphertext, ciphertext_b: BGVCiphertext) -> BGVCiphertext:
        return self.add(ciphertext_a, ciphertext_b)

    def homomorphic_and(self, ciphertext_a: BGVCiphertext, ciphertext_b: BGVCiphertext, secret_key: BGVSecretKey, public_key: BGVPublicKey) -> BGVCiphertext:
        plain_a = self.decrypt(secret_key, ciphertext_a)
        plain_b = self.decrypt(secret_key, ciphertext_b)
        return self.encrypt(public_key, (plain_a * plain_b) % self.ring.plaintext_modulus)
