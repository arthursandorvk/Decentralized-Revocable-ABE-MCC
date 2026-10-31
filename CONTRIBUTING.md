# Contributing to DL-SAR-ABE

Thank you for your interest. This repository is the reference implementation of a
peer-reviewed paper; contributions that preserve reproducibility of the published
results are especially welcome.

## What to contribute

- Bug reports (open an issue with: OS, Python/Charm versions, minimal reproducer).
- Correctness fixes and test coverage.
- Performance improvements that do not change the protocol's semantics.
- Documentation corrections.

## Ground rules

1. **Reproducibility first.** Changes must not silently alter the benchmark
   results reported in the paper. If a change affects timings or sizes, note it
   explicitly in the PR description.
2. **Security changes need discussion.** Open an issue before modifying any
   cryptographic logic (curve choice, serialization, randomness, revocation
   state handling).
3. **License.** By submitting a pull request you agree your contribution is
   licensed under GPL-3.0 and the NOTICE attribution terms.
4. Run `pytest tests/` before submitting.

## Style

- Python 3.9+, type hints on public APIs, docstrings referencing the paper's
  algorithm numbers where applicable (e.g., "implements Alg. 4: Transform").
