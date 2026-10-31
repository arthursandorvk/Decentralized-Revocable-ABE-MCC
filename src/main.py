'''
Arthur Sandor Voundi Koe, Wei Jian Hong, Jin Li, Chen Xiao Feng

| From: "E-HR-ABE Enhanced Hardware Revocable Attribute-Based Encryption".
| Published in: 2025
| Available from:
| Notes:
| Security Assumption:
|
| type:           multi-authority ciphertext-policy attribute-based encryption (public key)
| setting:        Pairing

:Authors:    Arthur SAndor Voundi Koe
:Date:            11/2024
'''
import hashlib

from charm.toolbox.pairinggroup import PairingGroup, ZR, GT

from SR_MACP_ABE import SR_MACP_ABE


def main():
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


if __name__ == "__main__":
    debug = True
    main()
