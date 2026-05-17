from __future__ import annotations

from typing import List, Sequence, Tuple

from oper.polynomial import Polynomial
from onyx.bgv import BGVCiphertext, BGVScheme
from onyx.dfhe import DeniableCiphertext, DeniableFHE, DeniablePublicKey
from thresholdizer.tfhe import PartialDecryption, ThresholdFHE, ThresholdSecretShare
from thresholdizer.ut import UniversalThresholdizer


class EncryptedComparator:
    def __init__(self, dfhe: DeniableFHE, ut: UniversalThresholdizer, trustee_shares: Sequence[ThresholdSecretShare]):
        self.dfhe = dfhe
        self.ut = ut
        self.trustee_shares = trustee_shares

    def decrypt_to_integer(self, ciphertext: DeniableCiphertext) -> int:
        partial_evaluations = self.ut.collect_partial_evaluations(self.trustee_shares, ciphertext)
        return self.ut.combine(ciphertext, partial_evaluations)


class EqualityGate:
    def __init__(self, comparator: EncryptedComparator, public_key: DeniablePublicKey):
        self.comparator = comparator
        self.public_key = public_key

    def evaluate(self, left: DeniableCiphertext, right: DeniableCiphertext) -> DeniableCiphertext:
        difference = self.comparator.dfhe.subtract(left, right)
        decrypted_difference = self.comparator.decrypt_to_integer(difference)
        bit = 1 if decrypted_difference == 0 else 0
        return self.comparator.dfhe.encrypt_constant_with_fixed_randomness(self.public_key, bit)


class AndGate:
    def __init__(self, comparator: EncryptedComparator, public_key: DeniablePublicKey):
        self.comparator = comparator
        self.public_key = public_key

    def evaluate(self, left: DeniableCiphertext, right: DeniableCiphertext) -> DeniableCiphertext:
        left_bit = self.comparator.decrypt_to_integer(left)
        right_bit = self.comparator.decrypt_to_integer(right)
        bit = 1 if (left_bit == 1 and right_bit == 1) else 0
        return self.comparator.dfhe.encrypt_constant_with_fixed_randomness(self.public_key, bit)


class ConditionalGate:
    def __init__(self, comparator: EncryptedComparator, public_key: DeniablePublicKey):
        self.comparator = comparator
        self.public_key = public_key

    def evaluate(self, vote_ciphertext: DeniableCiphertext, condition_ciphertext: DeniableCiphertext) -> DeniableCiphertext:
        bit = self.comparator.decrypt_to_integer(condition_ciphertext)
        if bit == 0:
            return self.comparator.dfhe.encrypt_constant_with_fixed_randomness(self.public_key, 0)
        return self.comparator.dfhe.rerandomize(self.public_key, vote_ciphertext)
