from dataclasses import dataclass, field
from typing import Dict, List, Tuple


@dataclass(frozen=True)
class RingParameters:
    degree: int
    modulus: int
    plaintext_modulus: int

    @property
    def log_q(self) -> int:
        return self.modulus.bit_length()


@dataclass(frozen=True)
class DFHEParameters:
    ring: RingParameters
    error_std: float
    error_bound: int
    deniability_selectors: int
    secret_distribution: str
    decryption_bias_bound: int


@dataclass(frozen=True)
class UTParameters:
    trustees: int
    threshold: int
    circuit_depth_bound: int
    share_bound: int
    noise_drowning_param: int


@dataclass(frozen=True)
class VSSParameters:
    parties: int
    threshold: int
    field_size_bits: int
    hash_repetitions: int


@dataclass(frozen=True)
class NIZKParameters:
    ring_degree: int
    log_modulus: int
    msis_rank: int
    mlwe_rank: int
    rejection_factor: int
    challenge_set_size: int
    masking_std: float
    response_bound: int
    witness_bound: int


@dataclass(frozen=True)
class MixNetParameters:
    ring_degree: int
    log_modulus: int
    plaintext_modulus: int
    shuffle_servers: int
    decryption_servers: int
    commitment_rank: int
    commitment_width: int
    statistical_security: int
    commitment_bound: int
    error_bound: int


@dataclass(frozen=True)
class ElectionParameters:
    number_of_voters: int
    number_of_candidates: int
    number_of_trustees: int
    threshold: int
    number_of_registrars: int


@dataclass(frozen=True)
class PQHardnessClaims:
    rlwe_security_bits: int
    mlwe_security_bits: int
    msis_security_bits: int
    dks_infty_security_bits: int
    sks_squared_security_bits: int
    sha256_quantum_preimage_bits: int
    pcr_deniability_advantage_log: int


@dataclass(frozen=True)
class SystemParameters:
    security_level: int
    dfhe: DFHEParameters
    ut: UTParameters
    vss: VSSParameters
    nizk: NIZKParameters
    mixnet: MixNetParameters
    election: ElectionParameters
    pq_claims: PQHardnessClaims
    regime_name: str


def production_parameters() -> SystemParameters:
    dfhe_ring = RingParameters(degree=1024, modulus=(1 << 26) - 5, plaintext_modulus=257)
    return SystemParameters(
        security_level=128,
        dfhe=DFHEParameters(
            ring=dfhe_ring,
            error_std=3.19,
            error_bound=20,
            deniability_selectors=4,
            secret_distribution="ternary",
            decryption_bias_bound=(1 << 22),
        ),
        ut=UTParameters(
            trustees=5,
            threshold=3,
            circuit_depth_bound=64,
            share_bound=(1 << 25),
            noise_drowning_param=40,
        ),
        vss=VSSParameters(
            parties=5,
            threshold=2,
            field_size_bits=256,
            hash_repetitions=3,
        ),
        nizk=NIZKParameters(
            ring_degree=128,
            log_modulus=28,
            msis_rank=14,
            mlwe_rank=21,
            rejection_factor=13,
            challenge_set_size=2,
            masking_std=20000.0,
            response_bound=(1 << 24),
            witness_bound=(1 << 14),
        ),
        mixnet=MixNetParameters(
            ring_degree=512,
            log_modulus=26,
            plaintext_modulus=2,
            shuffle_servers=3,
            decryption_servers=3,
            commitment_rank=6,
            commitment_width=8,
            statistical_security=30,
            commitment_bound=1,
            error_bound=1,
        ),
        election=ElectionParameters(
            number_of_voters=6,
            number_of_candidates=3,
            number_of_trustees=5,
            threshold=3,
            number_of_registrars=3,
        ),
        pq_claims=PQHardnessClaims(
            rlwe_security_bits=128,
            mlwe_security_bits=128,
            msis_security_bits=128,
            dks_infty_security_bits=168,
            sks_squared_security_bits=262,
            sha256_quantum_preimage_bits=128,
            pcr_deniability_advantage_log=-13,
        ),
        regime_name="medium-PQ",
    )


def quick_parameters() -> SystemParameters:
    dfhe_ring = RingParameters(degree=1024, modulus=(1 << 26) - 5, plaintext_modulus=257)
    return SystemParameters(
        security_level=128,
        dfhe=DFHEParameters(
            ring=dfhe_ring,
            error_std=3.19,
            error_bound=20,
            deniability_selectors=3,
            secret_distribution="ternary",
            decryption_bias_bound=(1 << 22),
        ),
        ut=UTParameters(
            trustees=4,
            threshold=2,
            circuit_depth_bound=32,
            share_bound=(1 << 25),
            noise_drowning_param=32,
        ),
        vss=VSSParameters(
            parties=4,
            threshold=1,
            field_size_bits=256,
            hash_repetitions=2,
        ),
        nizk=NIZKParameters(
            ring_degree=128,
            log_modulus=26,
            msis_rank=10,
            mlwe_rank=14,
            rejection_factor=8,
            challenge_set_size=2,
            masking_std=10000.0,
            response_bound=(1 << 22),
            witness_bound=(1 << 14),
        ),
        mixnet=MixNetParameters(
            ring_degree=512,
            log_modulus=26,
            plaintext_modulus=2,
            shuffle_servers=2,
            decryption_servers=2,
            commitment_rank=4,
            commitment_width=6,
            statistical_security=30,
            commitment_bound=1,
            error_bound=1,
        ),
        election=ElectionParameters(
            number_of_voters=4,
            number_of_candidates=3,
            number_of_trustees=4,
            threshold=2,
            number_of_registrars=2,
        ),
        pq_claims=PQHardnessClaims(
            rlwe_security_bits=128,
            mlwe_security_bits=128,
            msis_security_bits=128,
            dks_infty_security_bits=140,
            sks_squared_security_bits=210,
            sha256_quantum_preimage_bits=128,
            pcr_deniability_advantage_log=-10,
        ),
        regime_name="medium-PQ-compact",
    )


def describe_post_quantum_parameters(parameters: SystemParameters) -> str:
    dfhe = parameters.dfhe
    nizk = parameters.nizk
    mixnet = parameters.mixnet
    ut = parameters.ut
    vss = parameters.vss
    election = parameters.election
    claims = parameters.pq_claims
    border = "=" * 70
    lines = []
    lines.append(f"Security parameters              : {parameters.regime_name}")
    lines.append(f"post-quantum setting : lambda = {parameters.security_level} bits")
    lines.append("")
    lines.append("[ dFHE - Modified BGV over R_q with biased decryption ]")
    lines.append(f"  ring degree   N_D          : {dfhe.ring.degree}")
    lines.append(f"  ciphertext modulus log q   : {dfhe.ring.log_q} bits  (q ~ 2^{dfhe.ring.log_q})")
    lines.append(f"  plaintext modulus p        : {dfhe.ring.plaintext_modulus}")
    lines.append(f"  error std (sigma)          : {dfhe.error_std}")
    lines.append(f"  error bound B              : {dfhe.error_bound}")
    lines.append(f"  secret distribution        : {dfhe.secret_distribution}")
    lines.append(f"  deniability selectors n_d  : {dfhe.deniability_selectors}")
    lines.append(f"  decryption bias bound      : 2^{dfhe.decryption_bias_bound.bit_length() - 1}")
    lines.append(f"  RLWE_{{N_D, q, sigma}} hardness : ~{claims.rlwe_security_bits}-bit PQ")
    lines.append("")
    lines.append("[ Universal Thresholdizer ]")
    lines.append(f"  trustees n_T               : {ut.trustees}")
    lines.append(f"  reconstruction threshold t : {ut.threshold}")
    lines.append(f"  circuit depth bound d      : {ut.circuit_depth_bound}")
    lines.append(f"  share bound                : 2^{ut.share_bound.bit_length() - 1}")
    lines.append(f"  noise drowning param 2^sec : 2^{ut.noise_drowning_param}")
    lines.append("")
    lines.append("[ VSS Pi_LA - hash-based ]")
    lines.append(f"  registrars (parties) n_R   : {vss.parties}")
    lines.append(f"  threshold t_R              : {vss.threshold}")
    lines.append(f"  field size |Z_N|           : {vss.field_size_bits} bits  (SHA-256 committed)")
    lines.append(f"  soundness repetitions l    : {vss.hash_repetitions}")
    lines.append(f"  SHA-256 PQ preimage        : ~{claims.sha256_quantum_preimage_bits}-bit PQ")
    lines.append("")
    lines.append("[ Lattice-based deniable NIZK ]")
    lines.append(f"  ring degree d'             : {nizk.ring_degree}")
    lines.append(f"  modulus log q'             : {nizk.log_modulus} bits")
    lines.append(f"  MSIS rank n_SIS            : {nizk.msis_rank}")
    lines.append(f"  MLWE rank m_LWE            : {nizk.mlwe_rank}")
    lines.append(f"  rejection factor M         : {nizk.rejection_factor}")
    lines.append(f"  masking sigma_mask         : {nizk.masking_std}")
    lines.append(f"  MSIS_{{n,m,q,beta}} hardness : ~{claims.msis_security_bits}-bit PQ")
    lines.append(f"  MLWE_{{n,m,q,chi}} hardness : ~{claims.mlwe_security_bits}-bit PQ")
    lines.append("")
    lines.append("[ Verifiable MixNet over BGV ]")
    lines.append(f"  ring degree N_M            : {mixnet.ring_degree}")
    lines.append(f"  modulus log q              : {mixnet.log_modulus} bits")
    lines.append(f"  plaintext modulus p        : {mixnet.plaintext_modulus}")
    lines.append(f"  shuffle servers xi_1       : {mixnet.shuffle_servers}")
    lines.append(f"  decryption servers xi_2    : {mixnet.decryption_servers}")
    lines.append(f"  BDLOP rank / width         : {mixnet.commitment_rank} / {mixnet.commitment_width}")
    lines.append(f"  statistical security sec   : {mixnet.statistical_security} bits")
    lines.append(f"  DKS^infty hardness         : ~{claims.dks_infty_security_bits}-bit PQ")
    lines.append(f"  SKS^2 hardness             : ~{claims.sks_squared_security_bits}-bit PQ")
    lines.append("")
    lines.append("[ Election parameters ]")
    lines.append(f"  voters n_V                 : {election.number_of_voters}")
    lines.append(f"  candidates n_C             : {election.number_of_candidates}")
    lines.append(f"  trustees n_T (threshold t) : {election.number_of_trustees} ({ut.threshold})")
    lines.append(f"  registrars n_R             : {election.number_of_registrars}")
    lines.append("")
    lines.append("[ Persistent Coercion Resistance (PCR) gap ]")
    lines.append(f"  Adv^Onyx_PCR <= 2^{claims.pcr_deniability_advantage_log} + negl(lambda)")
    lines.append(border)
    return "\n".join(lines)
