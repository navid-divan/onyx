from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Tuple

from oper.polynomial import Polynomial
from onyx.dfhe import DeniableCiphertext, DeniableFHE, DeniablePublicKey
from onyx.deniability import EncryptionRandomness
from parameters import SystemParameters
from primitives.samplers import sample_field_element, sample_uniform_integer
from setup import ElectionPublicParameters, SetupArtifacts
from vss.pi_la import HashBasedVSS, VSSDealerOutput, VSSShare


@dataclass
class VoterCredential:
    credential_id: int
    voter_index: int


@dataclass
class VoterRegistrationState:
    credential: VoterCredential
    encryption_randomness: EncryptionRandomness
    credential_ciphertext: DeniableCiphertext
    public_parameters: ElectionPublicParameters


@dataclass
class RegistrationRecord:
    encrypted_roster: List[DeniableCiphertext]
    vss_proofs: List[List[Tuple[int, VSSDealerOutput]]]
    permutation_indices: List[int]


class Registrar:
    def __init__(self, parameters: SystemParameters, setup_artifacts: SetupArtifacts):
        self.parameters = parameters
        self.setup_artifacts = setup_artifacts
        self.deniable_fhe = setup_artifacts.deniable_fhe
        self.public_parameters = setup_artifacts.public_parameters
        vss_modulus = (1 << parameters.vss.field_size_bits) - 189
        self.vss_protocol = HashBasedVSS(
            modulus=vss_modulus,
            parties=parameters.vss.parties,
            threshold=parameters.vss.threshold,
            repetitions=parameters.vss.hash_repetitions,
        )

    def register_all_voters(self) -> Tuple[RegistrationRecord, List[VoterRegistrationState]]:
        states: List[VoterRegistrationState] = []
        encrypted_roster: List[DeniableCiphertext] = []
        vss_records: List[List[Tuple[int, VSSDealerOutput]]] = []
        for voter_index in range(self.parameters.election.number_of_voters):
            state, vss_record = self._register_single_voter(voter_index)
            states.append(state)
            encrypted_roster.append(state.credential_ciphertext)
            vss_records.append(vss_record)
        permutation_indices = list(range(len(encrypted_roster)))
        for index_outer in range(len(permutation_indices) - 1, 0, -1):
            index_inner = sample_uniform_integer(index_outer + 1)
            permutation_indices[index_outer], permutation_indices[index_inner] = (
                permutation_indices[index_inner],
                permutation_indices[index_outer],
            )
        permuted_roster = [encrypted_roster[index] for index in permutation_indices]
        registration_record = RegistrationRecord(
            encrypted_roster=permuted_roster,
            vss_proofs=vss_records,
            permutation_indices=permutation_indices,
        )
        return registration_record, states

    def _register_single_voter(self, voter_index: int) -> Tuple[VoterRegistrationState, List[Tuple[int, VSSDealerOutput]]]:
        plaintext_modulus = self.parameters.dfhe.ring.plaintext_modulus
        slot_width = max(plaintext_modulus // (self.parameters.election.number_of_voters + 2), 1)
        credential_plaintext = (voter_index + 1) * slot_width % plaintext_modulus
        if credential_plaintext == 0:
            credential_plaintext = voter_index + 1
        credential_id = credential_plaintext + sample_field_element(1 << 200) * plaintext_modulus
        dealer_output = self.vss_protocol.share(credential_id % self.vss_protocol.modulus)
        registrar_outputs = [(registrar_index, dealer_output) for registrar_index in range(self.parameters.election.number_of_registrars)]
        ciphertext, randomness = self.deniable_fhe.encrypt(self.public_parameters.dfhe_public_key, credential_plaintext)
        credential = VoterCredential(credential_id=credential_id, voter_index=voter_index)
        state = VoterRegistrationState(
            credential=credential,
            encryption_randomness=randomness,
            credential_ciphertext=ciphertext,
            public_parameters=self.public_parameters,
        )
        return state, registrar_outputs
