# Decentralized-Revocable-ABE-MCC: Decentralized and Lightweight Server-Aided Revocable Attribute-Based Encryption
[![DOI](https://img.shields.io/badge/DOI-10.1109%2FTDSC.2026.3696736-blue)](https://doi.org/10.1109/TDSC.2026.3696736)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-%E2%89%A53.6-blue)](https://www.python.org/)

Official reference implementation accompanying the paper:
> Arthur Sandor Voundi Koe, Jianghong Wei and Xiaofeng Chen, "Decentralized and Lightweight Server-Aided Revocable Attribute-Based Encryption for Mobile Cloud Computing," *IEEE Transactions on Dependable and Secure Computing*, vol. 23, no. 5, pp. 9918-9933, Sept.-Oct. 2026, doi: [10.1109/TDSC.2026.3696736](https://doi.org/10.1109/TDSC.2026.3696736)

## Overview

Decentralized-Revocable-ABE-MCC is a **decentralized**, **lightweight**, and **server-aided revocable** ciphertext-policy attribute-based encryption (CP-ABE) scheme designed for **mobile cloud computing**. It targets resource-constrained mobile devices by offloading heavy cryptographic operations to a semi-trusted cloud server, while supporting:

- **Decentralized attribute authorities** — no single central authority; multiple independent authorities issue attributes (multi-authority ABE).
- **Server-aided computation** — expensive pairing/exponentiation work in decryption (and partially in key generation/encryption) is outsourced to a cloud server without revealing plaintext or keys.
- **Efficient user/attribute revocation** — immediate revocation via server-held update material, without re-encrypting existing ciphertexts or re-issuing keys to non-revoked users.
- **Key-exposure resistance** — protection of long-term secrets under the scheme's threat model (see the paper, Security Analysis section).
- **Lightweight mobile-side cost** — constant or near-constant client-side computation, verified by the benchmarks in this repository.

## Repository Structure

```
Decentralized-Revocable-ABE-MCC/
├── README.md               # This file
├── LICENSE                 # GNU GPL v3.0 (see "License & Usage Tracking")
├── NOTICE                  # Attribution notice that must accompany copies
├── CITATION.cff            # Machine-readable citation (GitHub "Cite this repository")
├── CONTRIBUTING.md         # How to contribute / report issues
├── .gitignore
├── src/                    
│   ├── main.py             # End-to-end demo: Core scheme implementation - all fourteen operations
│   ├── measurements.py     # Benchmarks reproducing the paper's performance evaluation (paper Table/Figures)
│   ├── sr_macp_abe.py      #  Core scheme implementation - all fourteen operations
└── docs/                   # Protocol description, API reference, security notes
```

> **Note:** fill in `src/` with your implementation. The layout above follows the scheme's entities (authorities, cloud server, mobile client) one-to-one so reviewers can map code to the paper's algorithms.

## Quick Start

Run the end-to-end demonstration, which exercises all three execution paths: normal decryption, decryption after user revocation, and decryption after attribute revocation.
```bash
python src/main.py
```
The demo registers three attribute authorities, enrolls a user, runs the four-stage decentralized key generation, encrypts a message under an access policy, and verifies decryption across the revocation scenarios. Set *revoke_user* / *revoke_attribute* in *main.py* to toggle the paths; passing ```UL=[alice['gid']]``` to *revoke1* demonstrates that a revoked user can no
longer decrypt.

## Reproducing the Paper's Results

Run the end-to-end demonstration, which exercises all three execution paths: normal decryption, decryption after user revocation, and decryption after attribute revocation.
```bash
python src/measurements_cp.py
```
This reproduces the running-time measurements reported in the *Performance Evaluation* (Section 5) of the paper.

## Requirements

- Python ≥ 3.6
- [Charm-Crypto](https://github.com/JHUISI/charm) (pairing-based cryptography, PBC backend) — the scheme is pairing-based; we recommend a 128-bit security curve (e.g., `SS512` or BN/BLS12 families per your parameter choice).

```bash
pip install -r requirements.txt   # or: conda install -c jhuisi charm-crypto
```

## Reproducing the Paper's Results

```bash
python src/measurements_cp.py
```

The scripts reproduce the timing measurements reported in Section *Performance Evaluation* of the paper.

## Security Notice

This is a **research prototype** published for reproducibility and peer review. See [docs/SECURITY.md] for the trust assumptions (trusted DO; semi-trusted, non-colluding TEE-CS;
semi-trusted AAs; malicious DUs), the security properties, and the known limitations. It has **not** been audited for production use. Side-channel hardening, constant-time operations, and production parameter validation are out of scope. **Report vulnerabilities privately** to the corresponding author - not via public issues. Do not use it to protect real data.

## Citation

If you use this code in academic work, please cite the paper (GitHub also shows a *Cite this repository* widget generated from `CITATION.cff`):

```bibtex
@ARTICLE{koeweichen2026dlsarabe,
  author={Voundi Koe, Arthur Sandor and Wei, Jianghong and Chen, Xiaofeng.},
  journal={IEEE Transactions on Dependable and Secure Computing},
  title={Decentralized and Lightweight Server-Aided Revocable Attribute-Based Encryption for Mobile Cloud Computing},
  year={2026},
  volume={23},
  number={5},
  pages={9918-9933},
  doi={10.1109/TDSC.2026.3696736}
}
```

## License & Usage Tracking

This project is released under the **GNU General Public License v3.0** (see [LICENSE](LICENSE)), with the additional attribution requirement in [NOTICE](NOTICE). In short:

- You may use, study, modify, and redistribute the code — **but any distributed copy or derivative work must remain GPL-3.0, keep the copyright and NOTICE files, and disclose its source code.**
- Commercial closed-source use is **not permitted** without a separate agreement with the authors (contact below).
- Please cite the paper when using the code in research.

The authors actively track reuse of this code (see NOTICE for the tracking policy: forks, code search, and academic citation monitoring). If you find this code used without attribution, please open an issue or contact the authors.

## Contact

- Corresponding author: *2517482859@qq.com*
- Issues and bugs: please use the GitHub issue tracker.

