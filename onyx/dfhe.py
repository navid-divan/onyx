from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Sequence

from oper.polynomial import Polynomial
from onyx.bgv import BGVCiphertext, BGVPublicKey, BGVScheme, BGVSecretKey
from onyx.deniability import DeniabilityEngine, EncryptionRandomness
from parameters import DFHEParameters


@dataclass
class DeniablePublicKey:
    bgv_public_key: BGVPublicKey
    parameters: DFHEParameters


@dataclass
class DeniableSecretKey:
    bgv_secret_key: BGVSecretKey
    parameters: DFHEParameters


@dataclass
class DeniableCiphertext:
    aggregated: BGVCiphertext

    def to_bgv(self) -> BGVCiphertext:
        return self.aggregated


class DeniableFHE:
    def __init__(self, parameters: DFHEParameters):
        self.parameters = parameters
        self.scheme = BGVScheme(parameters.ring, parameters.error_std, parameters.error_bound)
        self.engine = DeniabilityEngine(self.scheme, parameters)

    def generate_keys(self) -> tuple[DeniablePublicKey, DeniableSecretKey]:
        public_key, secret_key = self.scheme.generate_keys()
        return (
            DeniablePublicKey(bgv_public_key=public_key, parameters=self.parameters),
            DeniableSecretKey(bgv_secret_key=secret_key, parameters=self.parameters),
        )

    def encrypt(self, public_key: DeniablePublicKey, message: int) -> tuple[DeniableCiphertext, EncryptionRandomness]:
        message_randomness = self.engine.fresh_message_randomness()
        selector_message_values, chosen_index = self.engine.sample_selector_message_values(message)
        selector_randomness: List[List[Polynomial]] = []
        for _ in range(self.parameters.deniability_selectors):
            selector_randomness.append(self.engine.fresh_selector_randomness())
        ciphertext = self.engine.materialize_message_ciphertext(
            public_key.bgv_public_key, message, message_randomness
        )
        randomness = EncryptionRandomness(
            message_randomness=message_randomness,
            selector_message_values=selector_message_values,
            selector_randomness=selector_randomness,
            chosen_selector_index=chosen_index,
        )
        return DeniableCiphertext(aggregated=ciphertext), randomness

    def encrypt_with_randomness(
        self,
        public_key: DeniablePublicKey,
        message: int,
        randomness: EncryptionRandomness,
    ) -> DeniableCiphertext:
        ciphertext = self.engine.materialize_message_ciphertext(
            public_key.bgv_public_key, message, randomness.message_randomness
        )
        return DeniableCiphertext(aggregated=ciphertext)

    def evaluate(
        self,
        circuit,
        ciphertexts: Sequence[DeniableCiphertext],
    ) -> DeniableCiphertext:
        bgv_ciphertexts = [ciphertext.aggregated for ciphertext in ciphertexts]
        evaluated = circuit(self.scheme, bgv_ciphertexts)
        return DeniableCiphertext(aggregated=evaluated)

    def decrypt(self, secret_key: DeniableSecretKey, ciphertext: DeniableCiphertext) -> int:
        return self.scheme.decrypt(secret_key.bgv_secret_key, ciphertext.aggregated)

    def fake(
        self,
        public_key: DeniablePublicKey,
        original_message: int,
        original_randomness: EncryptionRandomness,
        target_message: int,
    ) -> EncryptionRandomness:
        return self.engine.fake_message(
            target_message=target_message,
            original_message=original_message,
            original_randomness=original_randomness,
        )

    def add(self, lhs: DeniableCiphertext, rhs: DeniableCiphertext) -> DeniableCiphertext:
        return DeniableCiphertext(aggregated=self.scheme.add(lhs.aggregated, rhs.aggregated))

    def subtract(self, lhs: DeniableCiphertext, rhs: DeniableCiphertext) -> DeniableCiphertext:
        return DeniableCiphertext(aggregated=self.scheme.subtract(lhs.aggregated, rhs.aggregated))

    def scalar_multiply(self, ciphertext: DeniableCiphertext, factor: int) -> DeniableCiphertext:
        return DeniableCiphertext(aggregated=self.scheme.scalar_multiply(ciphertext.aggregated, factor))

    def rerandomize(self, public_key: DeniablePublicKey, ciphertext: DeniableCiphertext) -> DeniableCiphertext:
        return DeniableCiphertext(
            aggregated=self.scheme.rerandomize(public_key.bgv_public_key, ciphertext.aggregated)
        )

    def encrypt_zero_with_fixed_randomness(self, public_key: DeniablePublicKey) -> DeniableCiphertext:
        ring = self.parameters.ring
        zero_message = Polynomial.constant(0, ring.degree, ring.modulus)
        zero_randomness = Polynomial.constant(0, ring.degree, ring.modulus)
        ciphertext = self.scheme.encrypt_with_randomness(
            public_key.bgv_public_key,
            zero_message,
            zero_randomness,
            zero_randomness,
            zero_randomness,
        )
        return DeniableCiphertext(aggregated=ciphertext)

    def encrypt_constant_with_fixed_randomness(self, public_key: DeniablePublicKey, value: int) -> DeniableCiphertext:
        ring = self.parameters.ring
        message = Polynomial.constant(value % ring.plaintext_modulus, ring.degree, ring.modulus)
        zero_randomness = Polynomial.constant(0, ring.degree, ring.modulus)
        ciphertext = self.scheme.encrypt_with_randomness(
            public_key.bgv_public_key,
            message,
            zero_randomness,
            zero_randomness,
            zero_randomness,
        )
        return DeniableCiphertext(aggregated=ciphertext)
