# Onyx Concrete Parameters

The implementation supports two parameter regimes: `quick` and `production`. Both are tracked in `parameters.py`.

## Production Mode

| Component | Parameter | Value | Source |
|-----------|-----------|-------|--------|
| dFHE      | Ring degree N_D                      | 1024            | BGV over Z_q[X]/(X^N+1) (paper uses 32768 for full deployment) |
| dFHE      | Plaintext modulus p                  | 257             | accommodates `n_C` candidates with margin |
| dFHE      | Error standard deviation             | 3.19            | HE security standard |
| dFHE      | Deniability selectors `n_delta`      | 4               | δ-deniability with online/offline decomposition |
| UT        | Trustees `n_T`                       | 5               | strict-minority corruption tolerance |
| UT        | Threshold `t`                        | 3               | t-out-of-`n_T` reconstruction |
| UT        | Circuit depth bound `d`              | 64              | covers cleansing-hiding pipeline depth |
| VSS       | Parties `n_R`                        | 5               | hash-based Π_LA verifiable secret sharing |
| VSS       | Threshold `t_R`                      | 2               | honest-majority registrar setting |
| VSS       | Field size                           | 256-bit modulus | SHA-256 hashing target |
| NIZK      | Ring degree `d'`                     | 128             | distinct from dFHE cyclotomic |
| NIZK      | log q'                               | 50              | aligns with LNP'22 |
| NIZK      | MSIS rank `n_SIS`                    | 14              | bound short responses |
| NIZK      | MLWE rank `m_LWE`                    | 21              | LNP'22 128-bit configuration |
| NIZK      | Rejection-sampling factor `M`        | 13              | controls completeness error |
| MixNet    | Ring degree `N_M`                    | 512             | BGV mix-net (paper uses 4096 in full deployment) |
| MixNet    | Shuffle servers `xi_1`               | 3               | provides 168-bit DKS hardness |
| MixNet    | Decryption servers `xi_2`            | 3               | matches `xi_1` for cleansing-hiding |

## Quick Mode

A reduced-dimension regime tuned for fast end-to-end validation on resource-constrained devices (`a-Shell`, Android Terminal, low-power VMs). Quick mode preserves the *algorithmic correctness* of every primitive while shrinking ring degrees, modulus sizes, party counts, and rejection-sampling slack to keep the entire pipeline within seconds.

## Faking Detection Probability

In the deniable FHE construction, the per-ciphertext detection probability is `1/delta = 1/(n_delta^2)`. Production mode sets `n_delta = 4` (so `delta = 16`) inside the test pipeline; the paper's full deployment uses `n_delta = 2^14`.

## Compatibility Notes

- The implementation deliberately avoids native C extensions beyond NumPy so it runs without modification on Mac, Linux, Windows, Android Terminal, and `a-Shell` (iOS).
- The Universal Thresholdizer leverages `{0,1}`-LSSS reconstruction via Shamir secret sharing with integer Lagrange coefficients scaled by `(n_T!)^2` to keep ciphertext noise growth controlled.
