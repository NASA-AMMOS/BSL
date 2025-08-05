#
# Copyright (c) 2025 The Johns Hopkins University Applied Physics
# Laboratory LLC.
#
# This file is part of the Bundle Protocol Security Library (BSL).
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#     http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# This work was performed for the Jet Propulsion Laboratory, California
# Institute of Technology, sponsored by the United States Government under
# the prime contract 80NM0018D0004 between the Caltech and NASA under
# subcontract 1700763.
#
import cbor2
import hmac
import hashlib
import io

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# HMAC signs, encrypts, or decrypts payload string
# This is a really messy function for now 
def sign_and_encrypt(   payload_s:str, 
                        sign:bool=True, sign_key_s:str='1a2b1a2b1a2b1a2b1a2b1a2b1a2b1a2b', 
                        enc:bool=True, enc_key_s:str='71776572747975696f70617364666768', 
                        denc:bool=False, denc_key_s:str='71776572747975696f70617364666768', denc_tag_s:str='5d37d992dbc6fc795ea597ed7e8a6078'):
    
    #print(f'{payload_s} | {sign} | {sign_key_s} | {enc} | {enc_key_s} | {denc} | {denc_key_s} | {denc_tag_s}\n')

    # TODO only convert what's needed in if statements below
    payload = bytes.fromhex(payload_s)
    enc_key = bytes.fromhex(enc_key_s)
    denc_key = bytes.fromhex(denc_key_s)
    sign_key = bytes.fromhex(sign_key_s)
    denc_tag = bytes.fromhex(denc_tag_s)
    iv = bytes.fromhex('5477656c7665313231323132')
    aad = bytes.fromhex('00')
    ippt_scope_flag = 0

    results = [None, None, None]

    if sign:
        payload_ippt = cbor2.dumps(ippt_scope_flag)
        payload_ippt += cbor2.dumps(payload)

        print(f'ippt: {payload_ippt.hex()}')

        signature = hmac.new(sign_key, payload_ippt, hashlib.sha512).digest()

        print(f'sign: {signature.hex()}')

        results[0] = signature.hex()

    if enc:
        cipher = AES.new(enc_key, AES.MODE_GCM, nonce=iv)
        cipher.update(aad)
        ciphertext, tag = cipher.encrypt_and_digest(payload)
        results[1] = (ciphertext.hex(), tag.hex(), '69c411276fecddc4780df42c8a2af89296fabf34d7fae700', iv.hex())

    if denc:
        cipher = AES.new(denc_key, AES.MODE_GCM, nonce=iv)
        plaintext = cipher.decrypt_and_verify(payload, denc_tag)
        results[2] = plaintext.hex()

    return results


def add_bib_to_bundle_over_x(bundle, x):
    # find max blk num, we will make new BCB max+1. This guarantees the block num is free
    mx_blk_num = max(bundle, key=lambda blk: blk[1])[1]

    if x == 0:
        sign = sign_and_encrypt(cbor2.dumps(bundle[0]).hex(), sign=True, enc=False, denc=False)[0]
        asb = [
                [x], 1, 1, [2, [2, 1]],
                [[1, 7], [3, 0]],
                [[[1, bytes.fromhex(sign)]]]
            ]
        buf = io.BytesIO()
        for b in asb:
            cbor2.dump(b, buf)

        # add block to bundle
        bundle.append([11, mx_blk_num+1, 0, 0, buf.getvalue().hex()])

        return bundle

    for i, blk in enumerate(bundle):
        if i == 0:
            continue

        # find the target block
        if blk[1] == x:

            # get the HMAC signature 
            sign = sign_and_encrypt(blk[4], sign=True, enc=False, denc=False)[0]

            # create ASB and cbor dump as BIB btsd
            asb = [
                [x], 1, 1, [2, [2, 1]],
                [[1, 7], [3, 0]],
                [[[1, bytes.fromhex(sign)]]]
            ]
            buf = io.BytesIO()
            for b in asb:
                cbor2.dump(b, buf)

            # add block to bundle
            bundle.append([11, mx_blk_num+1, 0, 0, buf.getvalue().hex()])

    return bundle

def add_bcb_to_bundle_over_x(bundle, x):
    # find max blk num, we will make new BCB max+1. This guarantees the block num is free
    mx_blk_num = max(bundle, key=lambda blk: blk[1])[1]

    for blk in bundle:
        # find the target block
        if blk[1] == x:

            # encrypt: 4-tuple (ciphertext, tag, wrapped key, iv)
            ciphertext = sign_and_encrypt(blk[4], sign=False, enc=True, denc=False)[1]

            # create ASB and cbor dump as BCB btsd
            asb = [
                [x], 2, 1, [2, [2, 1]],
                     # IV                                       # wrapped key
                [[1, bytes.fromhex(ciphertext[3])], [2, 1], [3, bytes.fromhex(ciphertext[2])], [4, 0]],
                      # ciphertext
                [[[1, bytes.fromhex(ciphertext[1])]]]
            ]
            buf = io.BytesIO()
            for b in asb:
                cbor2.dump(b, buf)

            # add block to bundle
            bundle.append([12, mx_blk_num+1, 1, 0, buf.getvalue().hex()])

            # modify target btsd
            blk[4] = ciphertext[0]

    return bundle

b = [
    [7, 0, 0, [2, [1, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000],
                 # 2 byte uint - 300
    [7, 2, 0, 0, '19012C'],
    [1, 1, 0, 0, '526561647920746f2067656e657261746520612033322d62797465207061796c6f6164']
]


print (f"ORIGINAL BUNDLE: {b}")
b = add_bib_to_bundle_over_x(b, 2)
print(f'BUNDLE AFTER BIB: {b}')
#b = add_bcb_to_bundle_over_x(b, 1)
print(f'FINAL BUNDLE: {b}')
