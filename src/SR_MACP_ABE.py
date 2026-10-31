'''
Arthur Sandor Voundi Koe, JiangHong Wei, Xiaofeng Chen

| From: "Decentralized and Lightweight Server-Aided Revocable Attribute-Based Encryption for Mobile Cloud Computing"
| Published in: 2026
| Available from:
| Notes:
| Security Assumption:
|
| type:           multi-authority ciphertext-policy attribute-based encryption (public key)
| setting:        Pairing

:Corresponding Authors: Arthur Sandor Voundi Koe
:Date:            10/2026
'''
import hashlib
import pickle
from collections import defaultdict

import merkletools
from charm.toolbox.ABEnc import ABEnc
from charm.toolbox.pairinggroup import ZR, G1, GT, pair
from charm.toolbox.secretutil import SecretUtil

debug = True

# type annotations
crs_t = {'g': G1, 'e_gg': GT}
pp_t = {'h': G1, 'f': G1, 'e_gg_alpha': GT}
msk_t = {'beta': ZR, 'g2_alpha': G1}


class SR_MACP_ABE(ABEnc):

    def __init__(self, group_obj):
        ABEnc.__init__(self)
        self.name = "SR-MACP-ABE"
        #self.crs = {}
        util = SecretUtil(group_obj, verbose=True)
        group = group_obj

        # we pick random generator
        g = group.random(G1)

        # initialize pre-processing for generators
        g.initPP()

        # set the generator for target group
        e_gg = pair(g, g)

        self.crs = {'g': g, 'e_gg': e_gg, 'group': group, 'util': util}

        # Traditional public/private key pairs for asymmetric cryptography
        # for Data Owner
        # a0 = self.crs['group'].random(ZR)
        # b0 = self.crs['group'].random(ZR)
        # self.prv_DO = a0 * b0
        # self.pub_DO = self.crs['g'] ** self.prv_DO

        # # for Attribute Authority
        # # self.pub_AA
        # a1 = self.crs['group'].random(ZR)
        # b1 = self.crs['group'].random(ZR)
        # self.prv_AA = a1 * b1
        # self.pub_AA = self.crs['g'] ** self.prv_AA
        #
        # # for Data User
        # # self.pub_DU
        # a2 = self.crs['group'].random(ZR)
        # b2 = self.crs['group'].random(ZR)
        # self.prv_DU = a2 * b2
        # self.pub_DU = self.crs['g'] ** self.prv_DU
        #
        #  initialize internal states for revocation
        # for Data Owner
        self.counter_DO = -1
        self.sigma_DO = {}

        # initial publicly observable states
        # publicly observable state for DO
        self.state_DO = []

        # # publicly observable state for AA
        # self.state_AA = []
        #
        # # for Attribute Authority
        self.authorities = {}

        # for Users
        self.users = {}

        # Merkle tree for DO
        self.MHT_UL = merkletools.MerkleTools(hash_type="SHA256")
        # new_leaf = self.MHT_UL.get_leaf(0).__sizeof__()

        # secret exponent for encryption (shared secret)
        self.shared_secret = None

        # random exponent r for the user
        self.random_user_exponent = None

        # number of user revocation occurrences
        self.user_revocation_counter = 0

    def regUser(self, gid: str, attributes: list):
        '''Generate user keys (executed by the user).'''
        # for Data User
        # self.pub_DU
        a2 = self.crs['group'].random(ZR)
        b2 = self.crs['group'].random(ZR)
        prv_DU = a2 * b2
        pub_DU = self.crs['g'] ** prv_DU
        DU_key = {}
        DU_hkey = []
        # only DO has knowledge of the real user gid while AA will access the digest value of DU's gid
        self.users[gid] = {
            'pub_DU': pub_DU, 'prv_DU': prv_DU, 'gid': gid, 'attributes': attributes, 'DU_key': DU_key,
            'DU_hkey': DU_hkey
        }
        return {
            'pub_DU': pub_DU, 'prv_DU': prv_DU, 'gid': gid, 'attributes': attributes, 'DU_key': DU_key,
            'DU_hkey': DU_hkey
        }

    def setupAA(self, authorityid, authority_name, attributes: list):
        '''Generate attribute authority keys (executed by attribute authority)'''
        if authorityid not in self.authorities.keys():
            ''' new AA to register '''
            a1 = self.crs['group'].random(ZR)
            b1 = self.crs['group'].random(ZR)
            prv_AA = a1 * b1
            pub_AA = self.crs['g'] ** prv_AA
            state_AA = []
            counter_AA = -1
            sigma_AA = {}
            AL = defaultdict(list)  # int, {'attr':'', 'vers':0})

            attr_set = defaultdict(list)
            for attr in attributes:
                # initialize each attribute with the version 0
                attr_set[attr] = [attr, 0]

            self.authorities[authorityid] = {
                'name': authority_name, 'pub_AA': pub_AA, 'prv_AA': prv_AA,
                'state_AA': state_AA, 'counter_AA': counter_AA, 'sigma_AA': sigma_AA,
                'attributes': list(attr_set.keys())
            }
            # for attrib in self.authorities[authorityid]['attributes']:
            #     AL[attrib] = {'attr': attrib, 'version': 0}
            #
            self.authorities[authorityid]['AL'] = AL
            self.authorities[authorityid]['attr_set'] = attr_set

        return self.authorities[authorityid]

    #@Output(pp_t, msk_t)
    def setup(self):
        a0 = self.crs['group'].random(ZR)
        b0 = self.crs['group'].random(ZR)
        prv_DO = a0 * b0
        pub_DO = self.crs['g'] ** prv_DO

        beta = self.crs['group'].random(ZR)
        h = self.crs['g'] ** beta
        f = self.crs['g'] ** (1 / beta)

        alpha = self.crs['group'].random(ZR)
        g_alpha = self.crs['g'] ** alpha
        e_gg_alpha = self.crs['e_gg'] ** alpha

        pp = {'h': h, 'f': f, 'e_gg_alpha': e_gg_alpha}
        msk = {'beta': beta, 'g_alpha': g_alpha}
        return prv_DO, pub_DO, pp, msk

    def keygen(self, pp, msk, gid):
        pass

    def keygen1(self, msk, gid):
        # process the user GID
        epsilon = self.crs['group'].hash(str(gid), ZR)
        1 / (1 + epsilon)

        # random exponent
        r = self.crs['group'].random(ZR)

        sk_DO = (msk['g_alpha'] ** (1 / msk['beta'])) * self.users[gid]['pub_DU'] ** (r * (1/ (msk['beta']) * (1/(1+epsilon)))) #k_DO = (msk['g_alpha'] ** (1 / msk['beta'])) * (self.users[gid]['pub_DU'] ** (r * exponent) * (1/ msk['beta']))


        hk_DO_1 =((self.crs['g'] ** epsilon) ** (1/(1+epsilon))) * ((self.users[gid]['pub_DU'] ** r)) ** (1/(1+epsilon))
        #
        hk_DO_2 = self.crs['g'] ** (epsilon * (1/(msk['beta']*(1+epsilon))))
        # hk_DO_2 = hk_DO_2 ** (1/(1+epsilon))
        #
        # initialize to 0 - only used in case of user revocation for non-revoked users
        hk_DO_3 = self.crs['group'].init(ZR, 0)

        # Debugging value of F
        msk['g_alpha'] ** (1 / msk['beta']) * self.users[gid]['pub_DU'] ** (r * (1 / msk['beta']) * 1 / (1 + epsilon))


        DO_key = {'sk': sk_DO, 'hk_1': hk_DO_1, 'hk_2': hk_DO_2, 'hk_3': hk_DO_3}
        return DO_key

    def keygen2(self, AA_ID, hash_gid, S_DU):
        # AA has no access to gid but hash(gid))
        epsilon = hash_gid  # self.crs['group'].hash(str(gid), ZR)
        AA_key = {}

        #
        if AA_ID in self.authorities.keys():
            AA = self.authorities[AA_ID]
            prv_AA = AA['prv_AA']
            pub_AA = AA['pub_AA']
        else:
            raise Exception("AA_ID does not exist !")

        for j in S_DU:
            if j not in AA['attributes']:
                continue
            #
            r_j = self.crs['group'].random(ZR)

            D_j = (self.crs['g'] ** (self.crs['group'].hash(j, ZR) * r_j / (prv_AA + epsilon)) *
                   pub_AA ** (self.crs['group'].hash(j, ZR)) *
                   self.crs['g'] ** (self.crs['group'].hash(j, ZR) * r_j))

            T_j = pub_AA * self.crs['g'] ** (r_j / (prv_AA + epsilon)) * self.crs['g'] ** r_j

            AA_key[j] = {'D_j': D_j, 'T_j': T_j, 'attr': j}
        return AA_key

    def keygen3(self, aa_key_list: list):
        TK_DU = {}

        # complete set of attributes for Data user
        S_attr = list()
        for aa_key in aa_key_list:
            for j in list(aa_key.keys()):
                TK_DU[j] = aa_key[j]
                S_attr.append(j)
        TK_DU['S_attr'] = S_attr
        return TK_DU

    def keygen4(self, DO_key, TK_DU):
        DU_key = {'sk': DO_key, 'hk': TK_DU}
        DU_hkey = {'hk_1': DO_key['hk_1'], 'hk_2': DO_key['hk_2'], 'hk_3': DO_key['hk_3'], 'TK_DU': TK_DU, 'S_attr': TK_DU['S_attr']}
        return DU_key, DU_hkey

    def encrypt_(self, pp, M, policy_str, prv_DO):
        policy = self.crs['util'].createPolicy(policy_str)
        a_list = self.crs['util'].getAttributeList(policy)
        s = self.crs['group'].random(ZR)

        # Stored by DO
        self.shared_secret = s

        shares = self.crs['util'].calculateSharesDict(s, policy)

        C_tilde = (pp['e_gg_alpha'] ** s) * M
        C = pp['h'] ** s
        C_y, C_y_pr, C_attr = {}, {}, {}

        # witness W
        W = self.crs['group'].hash(str(M), G1)

        # DO signature on Witness
        sig_W = (self.crs['group'].hash(str(W), G1)) ** prv_DO  # (H(m))^s

        for i in shares.keys():
            j = self.crs['util'].strip_index(i)
            print('the value of j is ', j)
            C_y[i] = self.crs['g'] ** shares[i]
            # Modified Line
            C_y_pr[i] = (self.crs['g'] ** (self.crs['group'].hash(j, ZR))) ** shares[i]

            C_attr[j] = i  # store the position of attributes
            # C_y_pr[i] = self.crs['group'].hash(j, G1) ** shares[i]

        CT = {
            'C_tilde': C_tilde,
            'C': C, 'C_y': C_y, 'T_y': C_y_pr, 'C_attr': C_attr, 'policy': policy_str, 'attributes': a_list, 'W': W,
            'sig_W': sig_W
        }
        return CT

    def revoke1(self, prv_DO, msk, UL: list):

        if len(self.sigma_DO.keys()) == 0:
            # first time user revocation
            lambda_value = self.crs['group'].init(ZR, 0)
            z = self.crs['group'].random(ZR)
            self.counter_DO = self.counter_DO + 1
            self.sigma_DO = {self.counter_DO: {'z': z, 'lambda': lambda_value}}

        else:

            lambda_value = self.sigma_DO.get(self.counter_DO)['z']  # former value of z
            z = self.crs['group'].random(ZR)
            self.counter_DO = self.counter_DO + 1
            self.sigma_DO = {self.counter_DO: {'z': z, 'lambda': lambda_value}}

        # we build the MHT tree
        for gid in UL:
            gid_bytes = bytes(gid, 'utf-8')
            hash_gid = hashlib.sha256(gid_bytes).hexdigest()
            self.MHT_UL.add_leaf(hash_gid)
        self.MHT_UL.make_tree()

        # we get the root of MHT
        root = self.MHT_UL.get_merkle_root()

        # we sign the root
        sig = (self.crs['group'].hash(str(root), G1)) ** prv_DO  # (H(m))^s

        # public state
        self.state_DO.insert(self.counter_DO, {'MHT': self.MHT_UL, 'sig': sig})

        rk_Urev_DO_1 = self.crs['g'] ** (self.sigma_DO[self.counter_DO].get('z') * prv_DO * self.shared_secret)
        rk_Urev_DO_2 = self.crs['g'] ** (self.sigma_DO[self.counter_DO].get('lambda') * prv_DO * self.shared_secret)
        rk_Urev_DO = rk_Urev_DO_1 / rk_Urev_DO_2

        # user-aware master recomputation key uwmrk
        umrk_1 = self.crs['g'] ** (self.sigma_DO[self.counter_DO].get('z') * prv_DO * (1 / msk['beta']))  # ab*z/beta
        umrk_2 = self.crs['g'] ** (
                self.sigma_DO[self.counter_DO].get('lambda') * prv_DO * (1 / msk['beta']))  # ab*lambda/beta

        umrk = umrk_1 / umrk_2

        # increase the global variable that oversees the number of user revocations
        self.user_revocation_counter = self.user_revocation_counter + 1

        return self.state_DO, rk_Urev_DO, umrk


    def revoke2(self, attr_list: list, AA_ID):
        if AA_ID not in self.authorities.keys():
            raise Exception(f"{AA_ID} not in set of authorities \n")



        if len(self.authorities[AA_ID]['sigma_AA'].keys()) == 0:
            # first time attribute revocation
            k = self.crs['group'].random(ZR)
            eta = self.crs['group'].init(ZR, 1)
            'increment the revocation counter'
            self.authorities[AA_ID]['counter_AA'] = self.authorities[AA_ID]['counter_AA'] + 1
            self.authorities[AA_ID]['sigma_AA'] = {self.authorities[AA_ID]['counter_AA']: {'k': k, 'eta': eta}}

        else:
            eta_value = self.authorities[AA_ID]['sigma_AA'].get(self.authorities[AA_ID]['counter_AA'])['k']  # safegard old value of k
            k = self.crs['group'].random(ZR)
            self.authorities[AA_ID]['counter_AA'] = self.authorities[AA_ID]['counter_AA'] + 1
            self.authorities[AA_ID]['sigma_AA'] = {self.authorities[AA_ID]['counter_AA']: {'k': k, 'eta': eta_value}}

        # increase the version if attributes in AL list
        # for index in range(len(AL)):
        #     AL.get(index)['vers'] = AL.get(index)['vers'] + 1
        for index in range(len(attr_list)):
            # content['vers'] = content['vers'] + 1
            if attr_list[index] in self.authorities[AA_ID]['attributes']:
                'increment the attribute version by 1'
                self.authorities[AA_ID]['attr_set'][attr_list[index]] = [ attr_list[index], self.authorities[AA_ID]['attr_set'][attr_list[index]][1] + 1 ]

                'update the attribute revocation list AL'
                self.authorities[AA_ID]['AL'][attr_list[index]] = (attr_list[index],  self.authorities[AA_ID]['attr_set'][attr_list[index]][1])

        # we sign the list
        bytes_list = pickle.dumps(self.authorities[AA_ID]['AL'])
        sig = ((self.crs['group'].hash(str(bytes_list), G1)) ** self.authorities[AA_ID]['prv_AA'])  # (H(m))^key

        # public state
        self.authorities[AA_ID]['state_AA'].insert(self.authorities[AA_ID]['counter_AA'],
                                                   {'AL': self.authorities[AA_ID]['AL'], 'sig': sig})

        # attribute-aware master recomputation key awmrk
        amrk = self.authorities[AA_ID]['sigma_AA'][self.authorities[AA_ID]['counter_AA']].get('k') * \
                self.authorities[AA_ID]['sigma_AA'][self.authorities[AA_ID]['counter_AA']].get('eta')

        return self.authorities[AA_ID]['state_AA'], amrk


    def revoke3(self, crk_Urev_DO, umrk, gid, DU_hkey, CT, pub_DO):

        epsilon = self.crs['group'].hash(str(gid), ZR)

        # We check the signature in State_DO
        current_MHT = self.state_DO[self.counter_DO].get('MHT')
        # we get the root of MHT
        root = current_MHT.get_merkle_root()
        # check signature on root
        if pair(self.state_DO[self.counter_DO].get('sig'), self.crs['g']) == pair(self.crs['group'].hash(str(root), G1),
                                                                                  pub_DO):
            # Ciphertext update
            update_param = pair(self.crs['g'], crk_Urev_DO)
            CT['C_tilde'] = update_param * CT['C_tilde']

            # encode the user gid
            gid_bytes = bytes(gid, 'utf-8')
            gid_encoded = hashlib.sha256(gid_bytes).hexdigest()

            # # check whether current user is revoked
            for count in range(current_MHT.get_leaf_count()):
                if gid_encoded != current_MHT.get_leaf(count):
                    continue
                else:
                    # found it
                    # generate proof
                    current_MHT.get_proof(count)

                    # validate the proof
                    result_check = current_MHT.validate_proof(current_MHT.get_proof(count), current_MHT.get_leaf(count),
                                                              current_MHT.get_merkle_root())
                    if result_check is True:  # proof is valid so user is revoked
                        # do nothing
                        # return {'RC1': RC1, 'DU_GIDhkey': DU_GIDhkey}
                        # return DU_GIDhkey
                        # print(f"***user {gid} is revoked*** \n")
                        return CT, DU_hkey

            # user has not been revoked (so we can update the user secret key)
            DU_hkey['hk_2'] = DU_hkey['hk_2'] * umrk * (umrk ** (1 / (1 + epsilon)))
            DU_hkey['hk_3'] = umrk ** (1 / (1 + epsilon))
        return CT, DU_hkey


    def revoke4(self, amrk, hash_gid, DU_hkey, CT, pub_DO, AA_ID):
        #  AL = self.state_AA[self.counter_AA].get('AL')
        AL = self.authorities[AA_ID]['state_AA'][-1]['AL']
        sig = self.authorities[AA_ID]['state_AA'][-1].get('sig')

        # checking signature on AL
        bytes_list = pickle.dumps(AL)
        if pair(sig, self.crs['g']) == pair(
                self.crs['group'].hash(str(bytes_list), G1), self.authorities[AA_ID]['pub_AA']):
            #     # cannot verify signature on AL
            #     return None
            # else:
            # we update the corresponding ciphertext terms
            for attr in CT['attributes']:
                # for index in range(len(AL)):
                if attr in AL.keys():
                    # we update the required attribute
                    index = CT['C_attr'][attr]
                    CT['C_y'][index] = CT['C_y'][index] ** amrk
                    CT['T_y'][index] = CT['T_y'][index] ** amrk

            # checking signature on MHT_UL before checking whether the current user is revoked or not
            if self.counter_DO != 0:
                # whether there has already been a user revocation occurence
                current_MHT = self.state_DO[self.counter_DO].get('MHT')
                root = current_MHT.get_merkle_root()
                if pair(self.state_DO[self.counter_DO].get('sig'), self.crs['g']) != pair(
                        self.crs['group'].hash(str(root), G1), pub_DO):
                    # If signature fails on MHT_UL, simply return the updated ciphertext and do not check for DU-hkey update
                    return CT, DU_hkey
                else:
                    # signature valid on the MHT_UL
                    # process the user GID

                    # prior user revocation so need to check about the current user gid
                    current_MHT = self.state_DO[self.counter_DO].get('MHT')

                    for count in range(current_MHT.get_leaf_count()):
                        if hash_gid != current_MHT.get_leaf(count):
                            continue
                        else:
                            # found the user gid within the Merkle hash tree's leaves
                            # validate the proof
                            result_check = current_MHT.validate_proof(current_MHT.get_proof(count),
                                                                      current_MHT.get_leaf(count),
                                                                      current_MHT.get_merkle_root())
                            if result_check is True:  # proof is valid so user is revoked
                                # do nothing (do not update attributes of revoked user)
                                # return {'RC2': RC2, 'DU_GIDhkey': DU_GIDhkey}
                                return CT, DU_hkey

            # user has not been revoked
            # local_AA_GIDkey = DU_GIDhkey.get('AA_GIDkey')
            # for content in self.state_AA[self.counter_AA].get('AL'):  # get the latest attribute revocation list
            for content in AL.keys():
                if content in DU_hkey.get('TK_DU').keys():
                    # the version of the attribute is to be enforced
                    DU_hkey.get('TK_DU')[content]['D_j'] = DU_hkey.get('TK_DU')[
                                                               content].get('D_j') * \
                                                           DU_hkey['hk_1'] ** (1 / amrk)

                    # need to update the value of DU_GIDhkey.get('TK_DU')[content.get('attr')].get('T_j')
                    DU_hkey_up = DU_hkey.get('hk_1') ** (
                            1 / self.crs['group'].hash(content, ZR))

                    DU_hkey.get('TK_DU')[content]['T_j'] = DU_hkey.get('TK_DU')[content].get('T_j') * DU_hkey_up
        return CT, DU_hkey

    def Transform(self, CT, DU_hkey):

        policy = self.crs['util'].createPolicy(CT['policy'])
        pruned_list = self.crs['util'].prune(policy, DU_hkey['S_attr'])

        if not pruned_list:
            TC = None
            return TC

        # else
        q = self.crs['util'].getCoefficients(policy)

        TC = 1

        for i in pruned_list:
            j = i.getAttributeAndIndex()
            k = i.getAttribute()
            TC *= (pair((CT['C_y'][j]), (DU_hkey['hk_1'] * DU_hkey['TK_DU'][k]['D_j'])) / pair(
                (CT['T_y'][j]), DU_hkey.get('TK_DU')[k]['T_j'])) ** q[j]

        # the cloud server performs some online computation to alleviate pairing operations on the user side
        if DU_hkey['hk_3'] is None:
            I = pair(CT['C'], DU_hkey['hk_2'])

        else:
            I = pair(CT['C'], DU_hkey['hk_2']) / pair(CT['C'], DU_hkey['hk_3'])
        return TC,I


    def Decrypt(self, CT, TC, I, DO_key, DU_hkey, pub_DO):
        F = pair(CT['C'], DO_key['sk'])
        I = I #pair(CT['C'], DU_hkey['hk_2'])
        B = ((F * I) / TC)
        M_prime = CT['C_tilde'] / B

        # two cases  1) no user revocation occured and 2) user revocation occured

        #1) No User Revocation
        # verify the witness and the signature on witness
        # function H2
        W_prime = self.crs['group'].hash(str(M_prime), G1)

        if pair(CT['sig_W'], self.crs['g']) == pair(self.crs['group'].hash(str(W_prime), G1), pub_DO):
            return M_prime
        else:
            return None
           #  #2) Revocation Occured
           # # assert self.crs['group'].init(ZR, 1) == 1
           #  print("you checked this ? \n")
           #  F = pair(CT['C'], DO_key['sk'])
           #  I = pair(CT['C'], DU_hkey['hk_2'])
           #
           #  B = ((F * (I / pair(CT['C'], DU_hkey['hk_3'])) ) / TC )
           #  M_prime = CT['C_tilde'] / B
           #
           #  # verify the witness and the signature on witness
           #  # function H2
           #  W_prime = self.crs['group'].hash(str(M_prime), G1)
           #  if pair(CT['sig_W'], self.crs['g']) == pair(self.crs['group'].hash(str(W_prime), G1), pub_DO):
           #      return M_prime
           #  else:
           #      print("second version of M prime is ", M_prime, "\n")
           #      #3) Illegitimate User
           #      return None
