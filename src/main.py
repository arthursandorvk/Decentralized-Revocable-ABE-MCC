"""
End-to-end demonstration of the proposed decentralized SR-ABE scheme.

| Paper:      "Decentralized and Lightweight Server-Aided Revocable
|              Attribute-Based Encryption for Mobile Cloud Computing"
| Authors:    Arthur Sandor Voundi Koe, Jianghong Wei, Xiaofeng Chen
| Journal:    IEEE Transactions on Dependable and Secure Computing,
|             vol. 23, no. 5, pp. 9918-9933, Sept.-Oct. 2026
| DOI:        10.1109/TDSC.2026.3696736
|
| Type:       multi-authority ciphertext-policy attribute-based encryption
|             (server-aided, revocable; public key)
| Setting:    symmetric pairing groups (SS512, Type-A, 128-bit security)
| Security:   adaptive IND-CPA under the DBDH assumption
|             (random oracle model)

This script operates the full workflow of the scheme's fourteen operations:

    1.  System setup ......... Setup, SetupAA (per attribute authority)
    2.  User enrollment ...... RegUser
    3.  Key generation ....... Keygen1 (DO), Keygen2 (per AA),
                               Keygen3 / Keygen4 (DU)
    4.  Encryption ........... Encrypt (DO, with signed witness W)
    5.  User revocation ...... Revoke1 (DO) + Revoke3 (TEE-CS)
    6.  Attribute revocation . Revoke2 (AA) + Revoke4 (TEE-CS)
    7.  Decryption ........... Transform (TEE-CS) + Decrypt (DU,
                               with witness verification)

Three execution paths are controlled by the `revoke_user`
and `revoke_attribute` flags below:

    - normal decryption (no revocation),
    - decryption after user revocation of a *non-revoked* user
      (recomputed ciphertext RC1, updated helper key),
    - decryption after attribute revocation
      (recomputed ciphertext RC2, updated helper key).

Note: when revoking Alice (i.e., passing `UL=[alice['gid']]` to `revoke1`), decryption must then fail.
"""

import hashlib

from charm.toolbox.pairinggroup import PairingGroup, ZR, GT

from SR_MACP_ABE import SR_MACP_ABE


def main():
    # Pairing group: SS512 (Type-A supersingular curve, ~128-bit security)
    groupObj = PairingGroup('SS512')

    sr_macpabe = SR_MACP_ABE(groupObj)
    
    # User attribute set and ciphertext access policy for this demo.
    attrs = ['ONE', 'TWO', 'FOUR']
    access_policy = '((four or two) and (three or one))'

    if debug:
        print("Attributes =>", attrs)
        print("Policy =>", access_policy)

    # ----------------------------------------------------------------------
    # Setup: DO generates (prv_DO, pub_DO) on the public-key layer and
    # (pk, msk) = (PP, MSK) on the ABE layer. [Setup operation]
    # ----------------------------------------------------------------------
    (prv_DO, pub_DO, pk, msk) = sr_macpabe.setup()

    # ----------------------------------------------------------------------
    # SetupAA: register three independent attribute authorities, each
    # managing a disjoint attribute subset. [SetupAA operation]
    # ----------------------------------------------------------------------
    # ----------------------------------------------------------------
    # First attribute authority
    authority_id = 1
    authority_name = "AA1"
    attrs_1 = ['ONE']
    sr_macpabe.setupAA(authority_id, authority_name, attrs_1)

    # Second attribute authority
    authority_id = 2
    authority_name = "AA2"
    attrs_2 = ['TWO']
    sr_macpabe.setupAA(authority_id, authority_name, attrs_2)

    # Third attribute authority
    authority_id = 3
    authority_name = "AA3"
    attrs_3 = ['THREE']
    sr_macpabe.setupAA(authority_id, authority_name, attrs_3)
    # ----------------------------------------------------------------

    # ----------------------------------------------------------------------
    # RegUser: enroll user "alice" with her gid and requested attributes.
    # [RegUser operation]
    # ----------------------------------------------------------------------
    alice = sr_macpabe.regUser('alice', ['ONE', 'TWO', 'THREE', 'FOUR'])

    # ----------------------------------------------------------------------
    # Key generation, split across DO, AAs, and DU so that no single party
    # can reconstruct the user's complete secret key. [Keygen1 to Keygen4]
    # ----------------------------------------------------------------------
    
    # Keygen1: DO computes the partial user key DOkey for alice's gid
    DO_key = sr_macpabe.keygen1(msk, alice['gid'])

    # Keygen2: each AA contributes its key component. The gid is first
    # passed through H0 (DY-PRF pseudonym) to ensure unlinkability of the
    # user's identity across different AAs
    hash_gid = sr_macpabe.crs['group'].hash(str(alice['gid']), ZR)
    aa_key_1 = sr_macpabe.keygen2(AA_ID=1, hash_gid=hash_gid, S_DU=alice['attributes'])
    aa_key_2 = sr_macpabe.keygen2(AA_ID=2, hash_gid=hash_gid, S_DU=alice['attributes'])
    aa_key_3 = sr_macpabe.keygen2(AA_ID=3, hash_gid=hash_gid, S_DU=alice['attributes'])


    # Collect the per-authority key components.
    input_aa_key = list()
    input_aa_key.append(aa_key_1)
    input_aa_key.append(aa_key_2)
    input_aa_key.append(aa_key_3)

    # Keygen3: DU aggregates the AA components into the transformation key.
    TK_DU = sr_macpabe.keygen3(input_aa_key)

    # Keygen4: DU merges DO_key with the transformation key, yielding the
    # complete user key DU_key (kept local) and the helper key DU_hkey
    # (outsourced to TEE-CS for server-aided transformation)
    DU_key, DU_hkey = sr_macpabe.keygen4(DO_key, TK_DU)

    # ----------------------------------------------------------------------
    # Encrypt: DO encrypts a random group-element message under the access
    # policy, embedding the signed witness W. [Encrypt operation]
    # ----------------------------------------------------------------------
    rand_msg = sr_macpabe.crs['group'].random(GT)
    
    ct = sr_macpabe.encrypt_(pk, rand_msg, access_policy, prv_DO)
    if debug: print("\n\nCiphertext... => ", ct, "\n\n")

    # Separate references for the two revocation paths below
    ct_user_revoke = ct
    ct_attr_revoke = ct

    
    # Global state maintained by the DO across revocation epochs
    global state_DO

    # ======================================================================
    # PATH 1 — User revocation (state-triggered, indirect, lazy).
    #
    # Revoke1 (DO) produces the signed public state and the update material
    # (rk_Urev_DO, umrk); Revoke3 (TEE-CS) recomputes the ciphertext into
    # RC1 and updates the helper keys of non-revoked users only.
    # A *revoked* user receives no update and can no longer decrypt.
    # ======================================================================
    revoke_user = True
    
    if revoke_user:
        print("***************************************************")
        print("*****************User Revocation**************")
        print("***************************************************")

        # To actually revoke Alice, pass UL=[alice['gid']] here; the UL is
        # disseminated as a signed Merkle hash tree in the public state.
        state_DO, rk_Urev_DO, umrk = sr_macpabe.revoke1(prv_DO, msk, UL=[])


        # Cloud-side updates: ciphertext recomputation (CT -> RC1) and
        # helper-key refresh for non-revoked users: if alice is revoked, her helper-key will not be refreshed.
        RC1, DU_hkey = sr_macpabe.revoke3(rk_Urev_DO, umrk, alice['gid'], DU_hkey, ct_user_revoke, pub_DO)
        
        if debug: print("\n\nCiphertext after user revocation... => ", ct_user_revoke, "\n\n")
        print("\n\nCiphertext after user revocation... => ", ct_user_revoke, "\n\n")

        # Server-aided transformation of the recomputed ciphertext.
        TC_urev, I = sr_macpabe.Transform(RC1, DU_hkey)

        # Final lightweight decryption at the DU, including witness
        # verification (detects any tampering by the server).
        M1 = sr_macpabe.Decrypt(RC1, TC_urev, I, DO_key, DU_hkey, pub_DO)
        

        if debug: print("M (after revocation) :=>", M1, "\n")
        if debug: print("Original Message => ", rand_msg, "\n\n")
        assert rand_msg == M1, "FAILED Decryption: message is incorrect"
        if debug: print("Successful Decryption after user revocation !!!")

    # ======================================================================
    # PATH 2 — Attribute revocation (attribute version control).
    #
    # Revoke2 (AA) cancels the current version of the listed attributes and
    # emits update material (awmrk) in a signed public state; Revoke4
    # (TEE-CS) recomputes the affected ciphertext components into RC2 and
    # refreshes non-revoked users' helper keys.
    # ======================================================================
    revoke_attribute = False # True # False

     # Attribute revocation list: attributes whose versions are incremented.
    AL = ['FOUR', 'TWO', 'RW']

    if revoke_attribute:
        print("***************************************************")
        print("*****************Attribute Revocation**************")
        print("***************************************************")

        state_AA, awmrk = sr_macpabe.revoke2(AL, AA_ID=2)

        # Cloud-side updates: ciphertext recomputation (CT -> RC2) and
        # helper-key refresh for the non-revoked user
        gid_bytes = bytes(alice['gid'], 'utf-8')
        hash_gid = hashlib.sha256(gid_bytes).hexdigest()
        RC2, DU_hkey = sr_macpabe.revoke4(awmrk, hash_gid, DU_hkey, ct_attr_revoke, pub_DO, AA_ID=2)

        # Server-aided transformation of the recomputed ciphertext
        TC_arev, I = sr_macpabe.Transform(RC2, DU_hkey)

        # Final lightweight decryption at the DU (with witness verification)
        M2 = sr_macpabe.Decrypt(RC2, TC_arev, I, DO_key, DU_hkey, pub_DO)

        if debug: print("M (After Attribute Revocation) :=>", M2, "\n")
        if debug: print("Original Message => ", rand_msg, "\n\n")
        assert rand_msg == M2, "FAILED Decryption: message is incorrect"
        if debug: print("Successful Decryption after Attribute revocation !!!")


    # ======================================================================
    # PATH 3 — Normal decryption (no revocation in effect).
    # ======================================================================
    if revoke_user is False and revoke_attribute is False:
        # Server-aided transformation of the original ciphertext
        TC, I = sr_macpabe.Transform(ct, DU_hkey)

        # Final lightweight decryption at the DU (with witness verification)
        M3 = sr_macpabe.Decrypt(ct, TC, I, DO_key, DU_hkey, pub_DO)
        
        # additional tests
        if debug: print("Original Message => ", rand_msg, "\n")
        if debug: print("Recovered Message => ", M3, "\n\n")
        assert rand_msg == M3, "FAILED Decryption: message is incorrect"
        if debug: print("Successful Normal Decryption (No Revocation) !!!")


if __name__ == "__main__":
    debug = True
    main()
