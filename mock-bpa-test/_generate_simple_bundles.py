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

    results = [None, None, None]

    if sign:
        # IPPT is a CBOR sequence of [scope flag : payload]
        # TODO this will break if bytestring < 0x17 bytes: 0x4 - 0x57
        ippt = '0058' + hex(len(payload_s)//2)[2:]
        payload = bytes.fromhex(ippt+payload_s)

        signature = hmac.new(sign_key, payload, hashlib.sha512).digest()
        results[0] = signature.hex()

    if enc:
        cipher = AES.new(enc_key, AES.MODE_GCM, nonce=iv)
        cipher.update(aad)
        ciphertext, tag = cipher.encrypt_and_digest(payload)
        #print(f"Ciphertext: {ciphertext.hex()} | Authtag: {tag.hex()}")
        results[1] = (ciphertext.hex(), tag.hex(), '69c411276fecddc4780df42c8a2af89296fabf34d7fae700', iv.hex())

    if denc:
        cipher = AES.new(denc_key, AES.MODE_GCM, nonce=iv)
        plaintext = cipher.decrypt_and_verify(payload, denc_tag)
        #print(f"plaintext: {plaintext.hex()}")
        results[2] = plaintext.hex()

    #print(f'RESULTS: {results}')
    return results


def add_bib_to_bundle_over_x(bundle, x):
    # find max blk num, we will make new BCB max+1. This guarantees the block num is free
    mx_blk_num = max(bundle, key=lambda blk: blk[1])[1]

    if x == 0:
        sign = sign_and_encrypt(cbor2.dumps(bundle[0]).hex(), sign=True, enc=False, denc=False)[0]
        asb = [
                [x], 1, 1, [2, [2, 1]],
                [[1, 7], [3, bytes.fromhex('0000')]],
                [[[1, bytes.fromhex(sign)]]]
            ]
        buf = io.BytesIO()
        for b in asb:
            cbor2.dump(b, buf)

        # add block to bundle
        bundle.append([11, mx_blk_num+1, 0, 0, buf.getvalue().hex()])

        return bundle

    for blk in bundle:
        # find the target block
        if blk[0] == x:

            # get the HMAC signature 
            sign = sign_and_encrypt(blk[4], sign=True, enc=False, denc=False)[0]

            # create ASB and cbor dump as BIB btsd
            asb = [
                [x], 1, 1, [2, [2, 1]],
                [[1, 7], [3, bytes.fromhex('0000')]],
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

# b = [
#         [7, 0, 0, [2, [1, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000],
#         [1, 1, 0, 0, '526561647920746F2067656E657261746520612033322D62797465207061796C6F6164']
#     ]

# 9173 - A.3.1
b = [
    [7, 0, 0, [2, [1, 2]], [2, [2, 1]], [2, [2, 1]], [0, 40], 1000000],
                 # 2 byte uint - 300
    [7, 2, 0, 0, '19012C'],
    [1, 1, 0, 0, '526561647920746F2067656E657261746520612033322D62797465207061796C6F6164']
]

print (f"ORIGINAL BUNDLE: {b}")
# b = add_bib_to_bundle_over_x(b, 0)
# print(f'BUNDLE AFTER BIB: {b}')
b = add_bcb_to_bundle_over_x(b, 2)
print(f'FINAL BUNDLE: {b}')
