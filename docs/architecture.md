# Onyx Architecture

Onyx is a post-quantum persistent coercion-resistant voting system. It composes five lattice-based cryptographic primitives into a CHide-style cleansing-hiding pipeline operating over a threshold deniable fully homomorphic encryption layer, with persistent randomness deniability propagated through every voter-side ciphertext and zero-knowledge proof.

## Layered Architecture

```
+-----------------------------------------------------------+
|                   Onyx Voting Protocol                    |
| Setup -> Register -> Vote -> Valid -> Fake -> Tally -> Verify |
+-----------------------------------------------------------+
|     CHide-style cleansing pipeline (Eq, And, CGate gates) |
|     Odd-Even Merge Sort over UT-thresholded BGV           |
+-----------------------------------------------------------+
|     Verifiable Mix-Net (BDLOP commitments, shuffle proofs)|
|     Distributed Decryption with noise drowning            |
+-----------------------------------------------------------+
| Deniable NIZK (LNP'22 + Micciancio-Peikert equivocation)  |
+-----------------------------------------------------------+
| Universal Thresholdizer over BGV (Boneh et al., {0,1}-LSSS)|
+-----------------------------------------------------------+
| Hash-based VSS (Pi_LA from Baghery 2025) for credentials  |
+-----------------------------------------------------------+
| Deniable Fully Homomorphic Encryption (Agrawal et al.,    |
| modified BGV with biased decryption and selector aggregation)|
+-----------------------------------------------------------+
```

## Entities

- **Setup Authority** - one-shot trusted party that publishes the deniable-FHE public key and equivocation trapdoor, the NIZK reference string, and the universal-thresholdizer public parameters.
- **Registrars** - jointly issue voter credentials through a verifiable secret-sharing protocol over untappable channels.
- **Trustees** - hold shares of the deniable-FHE secret key under the universal thresholdizer (`n_T = 5`, `t = 3` in production mode).
- **Voters** - cast ballots through an anonymous channel and retain the local state needed for the Fake algorithm.
- **Auditors** - verify all public proofs on the append-only bulletin board.

## Phase Pipeline

1. `setup.py`: BGV key generation, threshold secret sharing of the FHE secret key, NIZK CRS sampling with equivocation trapdoor, MixNet parameter generation.
2. `register.py`: Per-voter credential sampling, hash-based VSS to the registrars, encrypted public roster construction with random permutation.
3. `vote.py`: Deniable-FHE encryption of the vote and credential, lattice-based deniable NIZK proof linking ciphertexts to the witness.
4. `valid.py`: NIZK verification, replay detection against the bulletin board.
5. `fake.py`: Recompute fake coins via `dFHE.Fake` for the vote and credential, then `NIZK.Fake` via the equivocation trapdoor.
6. `tally.py`: Build sorted entries, perform cleansing-hiding via `Eq`, `And`, `CGate` gates, mix through the verifiable shuffle chain, distributedly decrypt.
7. `verify.py`: Verify NIZKs, shuffle proofs, partial decryption proofs, and tally consistency.

## Security Targets

- 128-bit post-quantum security in production mode under the combined hardness of RLWE, MLWE, MSIS, DKS, and SKS.
- Persistent Coercion Resistance (PCR) as defined in the Onyx paper.
- Universal verifiability with publicly checkable bulletin board.
