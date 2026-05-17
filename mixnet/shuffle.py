from __future__ import annotations

from dataclasses import dataclass
from typing import List, Sequence

from oper.polynomial import Polynomial
from mixnet.bdlop import BDLOPScheme
from onyx.bgv import BGVCiphertext, BGVPublicKey, BGVScheme
from primitives.hash import serialize_polynomial, sha256_bytes
from primitives.samplers import sample_random_permutation


@dataclass
class ShuffleProof:
    re_randomization_commitments: List[bytes]
    permutation_commitment: bytes
    shuffle_check_value: bytes
    server_index: int


class VerifiableShuffle:
    def __init__(
        self,
        scheme: BGVScheme,
        bdlop_scheme: BDLOPScheme,
        public_key: BGVPublicKey,
        server_index: int,
    ):
        self.scheme = scheme
        self.bdlop_scheme = bdlop_scheme
        self.public_key = public_key
        self.server_index = server_index

    def re_randomize(self, ciphertexts: Sequence[BGVCiphertext]) -> List[BGVCiphertext]:
        return [self.scheme.rerandomize(self.public_key, ciphertext) for ciphertext in ciphertexts]

    def shuffle(self, ciphertexts: Sequence[BGVCiphertext]) -> tuple[List[BGVCiphertext], List[int], ShuffleProof]:
        re_randomized = self.re_randomize(ciphertexts)
        permutation = sample_random_permutation(len(re_randomized))
        shuffled = [re_randomized[index] for index in permutation]
        re_randomization_commitments = [
            sha256_bytes(
                serialize_polynomial(ciphertext.component_c0)
                + serialize_polynomial(ciphertext.component_c1)
            )
            for ciphertext in re_randomized
        ]
        permutation_commitment_input = b"".join(
            entry.to_bytes(4, "big") for entry in permutation
        )
        permutation_commitment = sha256_bytes(permutation_commitment_input)
        check_input = b"".join(re_randomization_commitments) + permutation_commitment + self.server_index.to_bytes(4, "big")
        shuffle_check_value = sha256_bytes(check_input)
        proof = ShuffleProof(
            re_randomization_commitments=re_randomization_commitments,
            permutation_commitment=permutation_commitment,
            shuffle_check_value=shuffle_check_value,
            server_index=self.server_index,
        )
        return shuffled, permutation, proof

    def verify(
        self,
        original_ciphertexts: Sequence[BGVCiphertext],
        shuffled_ciphertexts: Sequence[BGVCiphertext],
        proof: ShuffleProof,
    ) -> bool:
        if len(original_ciphertexts) != len(shuffled_ciphertexts):
            return False
        if len(proof.re_randomization_commitments) != len(original_ciphertexts):
            return False
        check_input = (
            b"".join(proof.re_randomization_commitments)
            + proof.permutation_commitment
            + proof.server_index.to_bytes(4, "big")
        )
        expected = sha256_bytes(check_input)
        return expected == proof.shuffle_check_value


def perform_mixnet_chain(
    scheme: BGVScheme,
    bdlop_scheme: BDLOPScheme,
    public_key: BGVPublicKey,
    ciphertexts: Sequence[BGVCiphertext],
    number_of_servers: int,
) -> tuple[List[BGVCiphertext], List[ShuffleProof]]:
    current_ciphertexts = list(ciphertexts)
    proofs: List[ShuffleProof] = []
    for server_index in range(1, number_of_servers + 1):
        shuffle_operator = VerifiableShuffle(
            scheme=scheme,
            bdlop_scheme=bdlop_scheme,
            public_key=public_key,
            server_index=server_index,
        )
        current_ciphertexts, _, proof = shuffle_operator.shuffle(current_ciphertexts)
        proofs.append(proof)
    return current_ciphertexts, proofs


def verify_mixnet_chain(
    scheme: BGVScheme,
    bdlop_scheme: BDLOPScheme,
    public_key: BGVPublicKey,
    input_ciphertexts: Sequence[BGVCiphertext],
    output_ciphertexts: Sequence[BGVCiphertext],
    proofs: Sequence[ShuffleProof],
) -> bool:
    if len(input_ciphertexts) != len(output_ciphertexts):
        return False
    for proof in proofs:
        if len(proof.re_randomization_commitments) != len(input_ciphertexts):
            return False
        check_input = (
            b"".join(proof.re_randomization_commitments)
            + proof.permutation_commitment
            + proof.server_index.to_bytes(4, "big")
        )
        if sha256_bytes(check_input) != proof.shuffle_check_value:
            return False
    return True
