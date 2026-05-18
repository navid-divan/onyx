# Onyx Voting System

This is the core implementation of Onyx, which is a post-quantum verifiable voting system that satisfies **Persistent Coercion Resistance (PCR)**: a coercer who interrogates a voter at any time after the tally cannot tell a voter who cast as instructed from a voter who used the `Fake` algorithm to fabricate every coin ever consumed by the voting client. Onyx combines a [CHide-style](https://ieeexplore.ieee.org/document/10664323) cleansing-hiding pipeline with [MixNets](https://dl.acm.org/doi/10.1145/3576915.3616683) operating over a threshold [deniable FHE](https://link.springer.com/chapter/10.1007/978-3-030-84245-1_22) layer, via [Universal Thresholdizer](https://link.springer.com/chapter/10.1007/978-3-319-96884-1_19), [NIZK](https://link.springer.com/chapter/10.1007/978-3-031-15979-4_3), and [Π_LA](https://link.springer.com/chapter/10.1007/978-3-031-91829-2_4) Verifiable Secret Sharing scheme.

## Running

The repository reqires Python 3.9+ runtime and `numpy` only.

```bash
cd onyx-main
python3 -m pip install -r requirements.txt
python3 run.py
```

To test the larger (production) parameter set:

```bash
python3 run.py --mode production
```

To customize the election:

```bash
python3 run.py --mode quick --voters 6 --candidates 4
```

To get a machine-readable JSON benchmark report:

```bash
python3 run.py --mode quick --json
```

The test reports the wall-clock time spent in each Onyx phase: `Setup`, `Register`, `Vote`, `Valid`, `Fake`, `Tally`, `Verify`. Output is written to `stdout` so the harness can be run from any terminal.

## Verifying Individual Subsystems

```bash
python3 tests/test_basic.py
python3 tests/test_full.py
```
