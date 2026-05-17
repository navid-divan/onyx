# Onyx

Post-Quantum Persistent Coercion-Resistant Voting from Deniable Encryption.

Onyx is the first post-quantum verifiable voting system that satisfies **Persistent Coercion Resistance (PCR)**: a coercer who interrogates a voter at any time after the tally cannot tell a voter who cast as instructed from a voter who used the `Fake` algorithm to fabricate every coin ever consumed by the voting client. Onyx combines a CHide-style cleansing-hiding pipeline operating over a threshold deniable FHE layer, with persistent randomness deniability propagated through every voter-side ciphertext and zero-knowledge proof.

This repository is a faithful, modular reference implementation of the Onyx protocol and all of its lattice-based building blocks: dFHE (Agrawal-Goldwasser-Mossel), Universal Thresholdizer (Boneh et al.), hash-based VSS Π_LA (Baghery), deniable NIZK (LNP'22 with Micciancio-Peikert equivocation), and verifiable mix-net with distributed decryption (Aranha-Baum-Gjøsteen-Silde).

## Layout

```
onyx-main/
├── run.py                    end-to-end test harness with per-phase timings
├── parameters.py             concrete parameters for production & quick modes
├── setup.py                  Setup phase (Setup Authority)
├── register.py               Registration phase (Registrars + VSS)
├── vote.py                   Vote phase (voter client; dFHE encryption + NIZK)
├── valid.py                  Validity check (NIZK verification + replay guard)
├── fake.py                   Persistent faking procedure
├── tally.py                  Cleansing-hiding tally with mix-net + DDec
├── verify.py                 Public verification
├── bulletin.py               Append-only bulletin board
├── utils.py                  Timing tracker + helpers
├── benchmark.py              Benchmark report generation
├── config.json               Static descriptor of phases and primitives
├── requirements.txt          Minimal dependency list (numpy only)
├── README.md                 This document
├── onyx/                     Deniable FHE layer
│   ├── bgv.py                BGV encryption scheme
│   ├── dfhe.py               Deniable FHE (Definition 2)
│   └── deniability.py        Selector aggregation + faking
├── thresholdizer/            Universal Thresholdizer
│   ├── lsss.py               Shamir + {0,1}-LSSS
│   ├── tfhe.py               Threshold FHE (partial decryption + combine)
│   └── ut.py                 UT.Setup / UT.Eval / UT.Verify / UT.Combine
├── vss/                      Hash-based Π_LA verifiable secret sharing
│   ├── shamir.py             Shamir secret sharing
│   └── pi_la.py              Baghery's Π_LA scheme (Share / VerifyShare / Reconstruct)
├── mixnet/                   Verifiable mix-net + DDec
│   ├── bdlop.py              BDLOP commitments
│   ├── shuffle.py            Verifiable shuffle + amortized proofs
│   └── ddec.py               Distributed decryption with noise drowning
├── nizk/                     Lattice-based deniable NIZK
│   ├── trapdoor.py           CRS sampling + Micciancio-Peikert trapdoor
│   ├── prover.py             NIZK prover
│   ├── verifier.py           NIZK verifier
│   └── fake.py               Prover-deniable equivocation
├── cleansing/                Cleansing-hiding pipeline
│   ├── sort.py               Odd-Even Merge Sort + cleansing pipeline
│   └── gates.py              Eq / And / CGate gadgets
├── primitives/               Cryptographic primitives
│   ├── samplers.py           Uniform / ternary / discrete-Gaussian / binomial
│   └── hash.py               SHA-256 based hashing + Fiat-Shamir transcripts
├── oper/                  Lattice & polynomial algebra
│   ├── polynomial.py         Polynomial in R_q = Z_q[X]/(X^n+1)
│   ├── matrix.py             Polynomial matrices
│   └── lagrange.py           Lagrange interpolation over Z_p / Z_N
├── tests/                    Unit and integration tests
│   ├── test_basic.py         Polynomial / BGV / VSS / Lagrange tests
│   └── test_full.py          End-to-end protocol test
└── docs/                     Documentation
    ├── architecture.md       Layered architecture
    └── parameters.md         Concrete parameter tables
```

## Running

The repository targets a vanilla Python 3.9+ runtime. Only `numpy` is required.

```bash
cd onyx-main
python3 -m pip install -r requirements.txt
python3 run.py
```

To exercise the larger (production) parameter set:

```bash
python3 run.py --mode production
```

To customize the election:

```bash
python3 run.py --mode quick --voters 6 --candidates 4
```

To emit a machine-readable JSON benchmark report:

```bash
python3 run.py --mode quick --json
```

The test harness measures and reports the wall-clock time spent in each Onyx phase: `Setup`, `Register`, `Vote`, `Valid`, `Fake`, `Tally`, `Verify`. Output is written to `stdout` so the harness can be run from a Mac terminal, a Linux shell, a Windows terminal, Android Terminal, or `a-Shell` on iOS without modification.

## Verifying Individual Subsystems

```bash
python3 tests/test_basic.py
python3 tests/test_full.py
```

## Mapping to the Onyx Paper

| Algorithm in the paper      | File implementing it                  |
|-----------------------------|---------------------------------------|
| `dFHE = (Gen, Enc, Eval, Dec, Fake)` | `onyx/dfhe.py`, `onyx/bgv.py`, `onyx/deniability.py` |
| `UT = (Setup, Eval, Verify, Combine)` | `thresholdizer/ut.py`, `thresholdizer/tfhe.py`, `thresholdizer/lsss.py` |
| `Π = (Share, VerifyShare, Reconstruct)` | `vss/pi_la.py`, `vss/shamir.py` |
| `NIZK = (Setup, Prove, Verify, Fake)` | `nizk/prover.py`, `nizk/verifier.py`, `nizk/fake.py`, `nizk/trapdoor.py` |
| `MixNet = (Setup, Mix, MixVerify, DDec, DDecVerify, Comb)` | `mixnet/shuffle.py`, `mixnet/ddec.py`, `mixnet/bdlop.py` |
| `Onyx.Setup`                | `setup.py` |
| `Onyx.Register`             | `register.py` |
| `Onyx.Vote`                 | `vote.py` |
| `Onyx.Valid`                | `valid.py` |
| `Onyx.Fake`                 | `fake.py` |
| `Onyx.Tally` (cleansing + mix + DDec) | `tally.py`, `cleansing/sort.py`, `cleansing/gates.py` |
| `Onyx.Verify`               | `verify.py` |

## Notes on the dFHE Modification

The `Onyx` paper uses a modified BGV scheme so that the bootstrapping procedure is biased to output an encryption of zero on random ciphertext-space elements (Property 4 of Special FHE in Agrawal et al., 2021). This implementation reproduces the same algorithmic structure: each ciphertext is the homomorphic XOR of `n_delta` selector ciphertexts, and `dFHE.Fake` swaps one selector index, producing fake coins that are statistically close to honest coins with detection probability `1/delta = 1/n_delta^2`. The full paper deployment chooses `n_delta = 2^14`; the implementation defaults to a smaller `n_delta` to keep all phases within seconds on every supported platform while preserving the algorithm.

## Cross-Platform Coverage

The implementation has no native dependencies beyond NumPy. It has been designed to run on:

- macOS terminals
- Linux shells (Ubuntu, Arch, Fedora)
- Windows terminals (PowerShell, cmd, WSL)
- Android Terminal (Termux)
- iOS `a-Shell`

Run a single invocation: `python3 run.py` (or `python run.py` on Windows). Per-phase wall-clock seconds are printed at the end.
