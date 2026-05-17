from __future__ import annotations

import secrets
from dataclasses import dataclass, field
from typing import List, Sequence

from oper.polynomial import Polynomial
from onyx.bgv import BGVCiphertext, BGVPublicKey, BGVScheme
from parameters import DFHEParameters
from primitives.samplers import (
    sample_gaussian_polynomial,
    sample_ternary_polynomial,
    sample_uniform_polynomial,
)


@dataclass
class EncryptionRandomness:
    message_randomness: List[Polynomial]
    selector_message_values: List[int]
    selector_randomness: List[List[Polynomial]]
    chosen_selector_index: int


class DeniabilityEngine:
    def __init__(self, scheme: BGVScheme, parameters: DFHEParameters):
        self.scheme = scheme
        self.parameters = parameters
        self.ring = parameters.ring

    def fresh_message_randomness(self) -> List[Polynomial]:
        return [
            sample_ternary_polynomial(self.ring.degree, self.ring.modulus),
            sample_gaussian_polynomial(self.ring.degree, self.ring.modulus, self.parameters.error_std, self.parameters.error_bound),
            sample_gaussian_polynomial(self.ring.degree, self.ring.modulus, self.parameters.error_std, self.parameters.error_bound),
        ]

    def fresh_selector_randomness(self) -> List[Polynomial]:
        return [
            sample_ternary_polynomial(self.ring.degree, self.ring.modulus),
            sample_gaussian_polynomial(self.ring.degree, self.ring.modulus, self.parameters.error_std, self.parameters.error_bound),
            sample_gaussian_polynomial(self.ring.degree, self.ring.modulus, self.parameters.error_std, self.parameters.error_bound),
        ]

    def sample_selector_message_values(self, target_message: int) -> tuple[List[int], int]:
        deniability_selectors = self.parameters.deniability_selectors
        chosen_index = secrets.randbelow(deniability_selectors)
        plaintext_modulus = self.ring.plaintext_modulus
        values: List[int] = []
        for index in range(deniability_selectors):
            if index == chosen_index:
                values.append(target_message % plaintext_modulus)
            else:
                values.append(secrets.randbelow(plaintext_modulus))
        return values, chosen_index

    def materialize_message_ciphertext(
        self,
        public_key: BGVPublicKey,
        message: int,
        randomness_triple: Sequence[Polynomial],
    ) -> BGVCiphertext:
        message_polynomial = Polynomial.constant(message % self.ring.plaintext_modulus, self.ring.degree, self.ring.modulus)
        return self.scheme.encrypt_with_randomness(
            public_key, message_polynomial, randomness_triple[0], randomness_triple[1], randomness_triple[2]
        )

    def fake_message(
        self,
        target_message: int,
        original_message: int,
        original_randomness: EncryptionRandomness,
    ) -> EncryptionRandomness:
        if target_message == original_message:
            return EncryptionRandomness(
                message_randomness=list(original_randomness.message_randomness),
                selector_message_values=list(original_randomness.selector_message_values),
                selector_randomness=[list(component) for component in original_randomness.selector_randomness],
                chosen_selector_index=original_randomness.chosen_selector_index,
            )
        new_selector_values = list(original_randomness.selector_message_values)
        new_selector_randomness = [list(component) for component in original_randomness.selector_randomness]
        new_chosen_index = original_randomness.chosen_selector_index
        fake_target_index = -1
        for index, value in enumerate(new_selector_values):
            if index != original_randomness.chosen_selector_index and value == target_message % self.ring.plaintext_modulus:
                fake_target_index = index
                break
        if fake_target_index == -1:
            fake_target_index = (original_randomness.chosen_selector_index + 1) % self.parameters.deniability_selectors
            new_selector_values[fake_target_index] = target_message % self.ring.plaintext_modulus
            new_selector_randomness[fake_target_index] = self.fresh_selector_randomness()
        new_chosen_index = fake_target_index
        new_message_randomness = self.fresh_message_randomness()
        return EncryptionRandomness(
            message_randomness=new_message_randomness,
            selector_message_values=new_selector_values,
            selector_randomness=new_selector_randomness,
            chosen_selector_index=new_chosen_index,
        )
