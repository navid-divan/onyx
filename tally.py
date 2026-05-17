from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Sequence

from cleansing.gates import AndGate, ConditionalGate, EncryptedComparator, EqualityGate
from cleansing.sort import CleansingPipeline, OddEvenMergeSort, SortedEntry, SortTranscript
from mixnet.ddec import DistributedDecryption, PartialDecryptionShare
from mixnet.shuffle import ShuffleProof, perform_mixnet_chain, verify_mixnet_chain
from onyx.dfhe import DeniableCiphertext, DeniableFHE, DeniablePublicKey
from parameters import SystemParameters
from primitives.hash import sha256_bytes, serialize_polynomial
from register import RegistrationRecord
from setup import ElectionPublicParameters, SetupArtifacts
from thresholdizer.tfhe import ThresholdSecretShare
from thresholdizer.ut import UniversalThresholdizer
from vote import Ballot


@dataclass
class TallyProofBundle:
    sort_transcript: SortTranscript
    shuffle_proofs: List[ShuffleProof]
    decryption_proofs: List[List[PartialDecryptionShare]]
    cleansed_count: int


@dataclass
class TallyResult:
    candidate_totals: Dict[int, int]
    proof_bundle: TallyProofBundle


class TallyAuthority:
    def __init__(self, parameters: SystemParameters, setup_artifacts: SetupArtifacts):
        self.parameters = parameters
        self.setup_artifacts = setup_artifacts
        self.dfhe = setup_artifacts.deniable_fhe
        self.ut = setup_artifacts.universal_thresholdizer
        self.shares = setup_artifacts.trustee_shares
        comparator = EncryptedComparator(self.dfhe, self.ut, self.shares)
        self.comparator = comparator
        public_parameters = setup_artifacts.public_parameters
        self.equality_gate = EqualityGate(comparator, public_parameters.dfhe_public_key)
        self.and_gate = AndGate(comparator, public_parameters.dfhe_public_key)
        self.conditional_gate = ConditionalGate(comparator, public_parameters.dfhe_public_key)

    def execute(
        self,
        ballots: Sequence[Ballot],
        registration_record: RegistrationRecord,
    ) -> TallyResult:
        ballot_count = len(ballots)
        roster_count = len(registration_record.encrypted_roster)
        public_parameters = self.setup_artifacts.public_parameters
        position_marker_plaintext = ballot_count
        sorted_entries = self._build_sorted_entries(ballots, registration_record, ballot_count, public_parameters)
        sorter = OddEvenMergeSort(self.comparator)
        sorted_entries, sort_transcript = sorter.sort(sorted_entries)
        position_marker_ciphertext = self.dfhe.encrypt_constant_with_fixed_randomness(
            public_parameters.dfhe_public_key, position_marker_plaintext
        )
        cleansing_pipeline = CleansingPipeline(
            self.dfhe,
            public_parameters.dfhe_public_key,
            self.equality_gate,
            self.and_gate,
            self.conditional_gate,
        )
        cleaned_ciphertexts = cleansing_pipeline.run(sorted_entries, position_marker_ciphertext)
        bgv_ciphertexts = [ciphertext.aggregated for ciphertext in cleaned_ciphertexts]
        bdlop_scheme = public_parameters.bdlop_scheme
        scheme = self.dfhe.scheme
        public_key = public_parameters.dfhe_public_key.bgv_public_key
        shuffled_ciphertexts, shuffle_proofs = perform_mixnet_chain(
            scheme=scheme,
            bdlop_scheme=bdlop_scheme,
            public_key=public_key,
            ciphertexts=bgv_ciphertexts,
            number_of_servers=self.parameters.mixnet.shuffle_servers,
        )
        verify_mixnet_chain(
            scheme=scheme,
            bdlop_scheme=bdlop_scheme,
            public_key=public_key,
            input_ciphertexts=bgv_ciphertexts,
            output_ciphertexts=shuffled_ciphertexts,
            proofs=shuffle_proofs,
        )
        distributed_decryption = DistributedDecryption(scheme, self.ut.threshold_fhe)
        decryption_proofs: List[List[PartialDecryptionShare]] = []
        candidate_totals: Dict[int, int] = {}
        for index in range(1, self.parameters.election.number_of_candidates + 1):
            candidate_totals[index] = 0
        for ciphertext in shuffled_ciphertexts:
            partial_shares = []
            for share in self.shares[: self.parameters.ut.threshold]:
                partial_shares.append(distributed_decryption.partial_decrypt(share, ciphertext))
            decryption_proofs.append(partial_shares)
            plaintext = distributed_decryption.combine(ciphertext, partial_shares)
            normalized = plaintext % self.parameters.dfhe.ring.plaintext_modulus
            if normalized in candidate_totals:
                candidate_totals[normalized] += 1
        proof_bundle = TallyProofBundle(
            sort_transcript=sort_transcript,
            shuffle_proofs=shuffle_proofs,
            decryption_proofs=decryption_proofs,
            cleansed_count=len(cleaned_ciphertexts),
        )
        return TallyResult(candidate_totals=candidate_totals, proof_bundle=proof_bundle)

    def _build_sorted_entries(
        self,
        ballots: Sequence[Ballot],
        registration_record: RegistrationRecord,
        ballot_count: int,
        public_parameters: ElectionPublicParameters,
    ) -> List[SortedEntry]:
        entries: List[SortedEntry] = []
        for ballot_index, ballot in enumerate(ballots):
            position_ciphertext = self.dfhe.encrypt_constant_with_fixed_randomness(
                public_parameters.dfhe_public_key, ballot_index
            )
            sort_key = self.comparator.decrypt_to_integer(ballot.credential_ciphertext)
            entries.append(
                SortedEntry(
                    vote_ciphertext=ballot.vote_ciphertext,
                    position_ciphertext=position_ciphertext,
                    credential_ciphertext=ballot.credential_ciphertext,
                    sort_key=sort_key,
                    secondary_sort_key=ballot_index,
                )
            )
        for roster_credential in registration_record.encrypted_roster:
            position_ciphertext = self.dfhe.encrypt_constant_with_fixed_randomness(
                public_parameters.dfhe_public_key, ballot_count
            )
            vote_ciphertext = self.dfhe.encrypt_constant_with_fixed_randomness(
                public_parameters.dfhe_public_key, 0
            )
            sort_key = self.comparator.decrypt_to_integer(roster_credential)
            entries.append(
                SortedEntry(
                    vote_ciphertext=vote_ciphertext,
                    position_ciphertext=position_ciphertext,
                    credential_ciphertext=roster_credential,
                    sort_key=sort_key,
                    secondary_sort_key=ballot_count,
                )
            )
        return entries
