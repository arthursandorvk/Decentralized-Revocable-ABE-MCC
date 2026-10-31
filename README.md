# Decentralized-Revocable-ABE-MCC: Decentralized and Lightweight Server-Aided Revocable Attribute-Based Encryption
[![DOI](https://img.shields.io/badge/DOI-10.1109%2FTDSC.2026.3696736-blue)](https://doi.org/10.1109/TDSC.2026.3696736)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-%E2%89%A53.6-blue)](https://www.python.org/)

Official reference implementation accompanying the paper:
> Arthur Sandor Voundi Koe, Jianghong Wei and Xiaofeng. Chen, "Decentralized and Lightweight Server-Aided Revocable Attribute-Based Encryption for Mobile Cloud Computing," *IEEE Transactions on Dependable and Secure Computing*, vol. 23, no. 5, pp. 9918-9933, Sept.-Oct. 2026, doi: [10.1109/TDSC.2026.3696736](https://doi.org/10.1109/TDSC.2026.3696736)

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
├── src/                    # Core scheme implementation
│   ├──
│   ├── main.py             # Setup / KeyGen / Encrypt / Transform / Decrypt / Revoke
│   ├── measurements.py     # Timing & communication-cost evaluation (paper Table/Figures)
│   ├── sr_macp_abe.py      # System parameters & global setup
└── docs/                   # Protocol description, API reference, security notes
```

> **Note:** fill in `src/sr_macp_abe/` with your implementation. The layout above follows the scheme's entities (authorities, cloud server, mobile client) one-to-one so reviewers can map code to the paper's algorithms.

## Requirements

- Python ≥ 3.6
- [Charm-Crypto](https://github.com/JHUISI/charm) (pairing-based cryptography, PBC backend) — the scheme is pairing-based; we recommend a 128-bit security curve (e.g., `SS512` or BN/BLS12 families per your parameter choice).

```bash
pip install -r requirements.txt   # or: conda install -c jhuisi charm-crypto
```

## Quick Start

```python
 groupObj = PairingGroup('SS512')

    sr_macpabe = SR_MACP_ABE(groupObj)

    attrs = ['ONE', 'TWO', 'FOUR']
    # access_policy = '((four and three) and (three and one))'
    access_policy = '((four or two) and (three or one))'

    if debug:
        print("Attributes =>", attrs)
        print("Policy =>", access_policy)

    (prv_DO, pub_DO, pk, msk) = sr_macpabe.setup()

    # WE consider three AAs
    # ----------------------------------------------------------------
    # we register the first AA
    authority_id = 1
    authority_name = "AA1"
    attrs_1 = ['ONE']
    sr_macpabe.setupAA(authority_id, authority_name, attrs_1)

    # we register the second AA
    authority_id = 2
    authority_name = "AA2"
    attrs_2 = ['TWO']
    sr_macpabe.setupAA(authority_id, authority_name, attrs_2)

    # we register the third AA
    authority_id = 3
    authority_name = "AA3"
    attrs_3 = ['THREE']
    sr_macpabe.setupAA(authority_id, authority_name, attrs_3)
    # ----------------------------------------------------------------

    # we register a user
    alice = sr_macpabe.regUser('alice', ['ONE', 'TWO', 'THREE', 'FOUR'])

    # Keygen1
    DO_key = sr_macpabe.keygen1(msk, alice['gid'])

    # Keygen2
    hash_gid = sr_macpabe.crs['group'].hash(str(alice['gid']), ZR)
    aa_key_1 = sr_macpabe.keygen2(AA_ID=1, hash_gid=hash_gid, S_DU=alice['attributes'])
    aa_key_2 = sr_macpabe.keygen2(AA_ID=2, hash_gid=hash_gid, S_DU=alice['attributes'])
    aa_key_3 = sr_macpabe.keygen2(AA_ID=3, hash_gid=hash_gid, S_DU=alice['attributes'])

    print(f"Alice attributes: {alice['attributes'][0], alice['attributes'][1], alice['attributes'][2]}\n\n\n")

    # Keygen3
    #
    input_aa_key = list()
    input_aa_key.append(aa_key_1)
    input_aa_key.append(aa_key_2)
    input_aa_key.append(aa_key_3)

    # Keygen3
    TK_DU = sr_macpabe.keygen3(input_aa_key)

    # Keygen4
    DU_key, DU_hkey = sr_macpabe.keygen4(DO_key, TK_DU)

    # rand_msg = groupObj.random(GT)
    rand_msg = sr_macpabe.crs['group'].random(GT)

    # if debug: print("msg =>", rand_msg)
    ct = sr_macpabe.encrypt_(pk, rand_msg, access_policy, prv_DO)
    if debug: print("\n\nCiphertext... => ", ct, "\n\n")

    ct_user_revoke = ct
    ct_attr_revoke = ct

    # groupObj.debug(ct)
    # ehrabe.crs['group'].debug(ct)

    # global variales
    global state_DO

    #########################################################################################

    revoke_user = True
    # Remember a revoked user cannot recover the original plaintext

    # User REvocation settings
    if revoke_user:
        print("***************************************************")
        print("*****************User Revocation**************")
        print("***************************************************")

        # Uncomment to revoke the suer
        # gid_bytes = bytes('gid', 'utf-8')
        # hash_gid = hashlib.sha256(gid_bytes).hexdigest()
        # ehrabe.MHT_UL.add_leaf(hash_gid)
        # self.MHT_UL.make_tree()

        state_DO, rk_Urev_DO, umrk = sr_macpabe.revoke1(prv_DO, msk, UL=[])#[alice['gid']])

        # revocation updates by the cloud
        # gid_bytes = bytes(alice['gid'], 'utf-8')
        # hash_gid = hashlib.sha256(gid_bytes).hexdigest()
        RC1, DU_hkey = sr_macpabe.revoke3(rk_Urev_DO, umrk, alice['gid'], DU_hkey, ct_user_revoke, pub_DO)
        if debug: print("\n\nCiphertext after user revocation... => ", ct_user_revoke, "\n\n")
        print("\n\nCiphertext after user revocation... => ", ct_user_revoke, "\n\n")

        # ciphertext transformation (after user revocation)
        TC_urev, I = sr_macpabe.Transform(RC1, DU_hkey)

        # Local decryption by DU
        M1 = sr_macpabe.Decrypt(RC1, TC_urev, I, DO_key, DU_hkey, pub_DO)

        if debug: print("M (after revocation) :=>", M1, "\n")
        if debug: print("Original Message => ", rand_msg, "\n\n")
        assert rand_msg == M1, "FAILED Decryption: message is incorrect"
        if debug: print("Successful Decryption after user revocation !!!")

    ###########################################################################################
    # Attribute Revocation settings
    revoke_attribute = False # True # False

    # revocation list of attributes with current active version number
    # AL = [{'attr': 'FOUR', 'vers': 0}, {'attr': 'TW', 'vers': 0}, {'attr': 'RW', 'vers': 1}]
    AL = ['FOUR', 'TWO', 'RW']

    if revoke_attribute:
        print("***************************************************")
        print("*****************Attribute Revocation**************")
        print("***************************************************")

        state_AA, awmrk = sr_macpabe.revoke2(AL, AA_ID=2)

        # revocation updates by the cloud
        gid_bytes = bytes(alice['gid'], 'utf-8')
        hash_gid = hashlib.sha256(gid_bytes).hexdigest()
        RC2, DU_hkey = sr_macpabe.revoke4(awmrk, hash_gid, DU_hkey, ct_attr_revoke, pub_DO,
                                          AA_ID=2)

        # ciphertext transformation (after user revocation)
        TC_arev, I = sr_macpabe.Transform(RC2, DU_hkey)

        # Local decryption by DU
        M2 = sr_macpabe.Decrypt(RC2, TC_arev, I, DO_key, DU_hkey, pub_DO)

        if debug: print("M (After Attribute Revocation) :=>", M2, "\n")
        if debug: print("Original Message => ", rand_msg, "\n\n")
        assert rand_msg == M2, "FAILED Decryption: message is incorrect"
        if debug: print("Successful Decryption after Attribute revocation !!!")

    if revoke_user is False and revoke_attribute is False:
        # ciphertext transformation (after user revocation)
        TC, I = sr_macpabe.Transform(ct, DU_hkey)

        sr_macpabe.crs['group'].hash(str(alice['gid']), ZR)

        # Local decryption by DU
        M3 = sr_macpabe.Decrypt(ct, TC, I, DO_key, DU_hkey, pub_DO)
        # additional tests

        if debug: print("Original Message => ", rand_msg, "\n")
        if debug: print("Recovered Message => ", M3, "\n\n")
        assert rand_msg == M3, "FAILED Decryption: message is incorrect"
        if debug: print("Successful Normal Decryption (No Revocation) !!!")
```

## Reproducing the Paper's Results

```bash
python scripts/measurements_cp.py
```

The scripts reproduce the timing measurements reported in Section *Performance Evaluation* of the paper.

## Security Notice

This is a **research prototype** published for reproducibility and peer review. It has **not** been audited for production use. Side-channel hardening, constant-time operations, and production parameter validation are out of scope. Do not use it to protect real data.

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

