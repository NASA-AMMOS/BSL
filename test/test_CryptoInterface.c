/*
 * Copyright (c) 2025 The Johns Hopkins University Applied Physics
 * Laboratory LLC.
 *
 * This file is part of the Bundle Protocol Security Library (BSL).
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *     http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * This work was performed for the Jet Propulsion Laboratory, California
 * Institute of Technology, sponsored by the United States Government under
 * the prime contract 80NM0018D0004 between the Caltech and NASA under
 * subcontract 1700763.
 */
#include <inttypes.h>

#include <openssl/err.h>
#include <openssl/rand.h>
#include <unity.h>

#include <BPSecLib_Private.h>
#include <CryptoInterface.h>

#include <backend/UtilDefs_SeqReadWrite.h>
#include <backend/PublicInterfaceImpl.h>

#include "bsl_test_utils.h"

#define TEST_CASE(...)
#define TEST_RANGE(...)
#define TEST_MATRIX(...)

static BSL_LibCtx_t bsl;

/**
 * copied from openssl examples, used for testing for now
 * https://wiki.openssl.org/index.php/EVP_Authenticated_Encryption_and_Decryption
 */
int gcm_encrypt(const EVP_CIPHER *cipher, unsigned char *plaintext, int plaintext_len, unsigned char *aad, int aad_len,
                unsigned char *key, unsigned char *iv, int iv_len, unsigned char *ciphertext, int *ciphertext_len,
                unsigned char *tag)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    /* Create and initialise the context */
    if (!(ctx = EVP_CIPHER_CTX_new()))
    {
        return 1;
    }
    /* Initialise the encryption operation. */
    if (1 != EVP_EncryptInit_ex(ctx, cipher, NULL, NULL, NULL))
    {
        return 1;
    }
    /*
     * Set IV length if default 12 bytes (96 bits) is not appropriate
     */
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL))
    {
        return 1;
    }
    /* Initialise key and IV */
    if (1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv))
    {
        return 1;
    }
    /*
     * Provide any AAD data. This can be called zero or more times as
     * required
     */
    if (1 != EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len))
    {
        return 1;
    }
    /*
     * Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
    {
        return 1;
    }
    *ciphertext_len = len;

    /*
     * Finalise the encryption. Normally ciphertext bytes may be written at
     * this stage, but this does not occur in GCM mode
     */
    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
    {
        return 1;
    }
    *ciphertext_len += len;

    /* Get the tag */
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag))
    {
        return 1;
    }
    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return 0;
}

/**
 * copied from openssl examples, used for testing for now
 * https://wiki.openssl.org/index.php/EVP_Authenticated_Encryption_and_Decryption
 */
int gcm_decrypt(const EVP_CIPHER *cipher, unsigned char *ciphertext, int ciphertext_len, unsigned char *aad,
                int aad_len, unsigned char *tag, unsigned char *key, unsigned char *iv, int iv_len,
                unsigned char *plaintext, int *plaintext_len)
{
    EVP_CIPHER_CTX *ctx;
    int             len;
    int             res;

    /* Create and initialise the context */
    if (!(ctx = EVP_CIPHER_CTX_new()))
    {
        return 1;
    }

    /* Initialise the decryption operation. */
    if (!EVP_DecryptInit_ex(ctx, cipher, NULL, NULL, NULL))
    {
        return 1;
    }

    /* Set IV length. Not necessary if this is 12 bytes (96 bits) */
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL))
    {
        return 1;
    }

    /* Initialise key and IV */
    if (!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv))
    {
        return 1;
    }

    /*
     * Provide any AAD data. This can be called zero or more times as
     * required
     */
    if (!EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len))
    {
        return 1;
    }

    /*
     * Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary
     */

    if (!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
    {
        return 1;
    }
    *plaintext_len = len;

    /* Set expected tag value. Works in OpenSSL 1.0.1d and later */
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag))
    {
        return 1;
    }

    /*
     * Finalise the decryption. A positive return value indicates success,
     * anything else is a failure - the plaintext is not trustworthy.
     */
    res = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    if (res <= 0)
    {
        return -1;
    }

    *plaintext_len += len;
    return 0;
}

static uint8_t test_128[16] = { 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
                                0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b };

static uint8_t test_256[32] = { 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
                                0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
                                0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b };

void suiteSetUp(void)
{
    BSL_openlog();
    BSL_CryptoInit();

    // static keys
    uint8_t test1[20]  = { 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
                           0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b };
    uint8_t test2[4]   = { 0x4a, 0x65, 0x66, 0x65 };
    uint8_t test7[131] = { 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
                           0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
                           0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
                           0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
                           0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
                           0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
                           0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
                           0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
                           0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa };
    BSL_Crypto_AddRegistryKey("Key1", test1, 20);
    BSL_Crypto_AddRegistryKey("Key2", test2, 4);
    BSL_Crypto_AddRegistryKey("Key7", test7, 131);

    BSL_Crypto_AddRegistryKey("Key8", test_256, 32);
    BSL_Crypto_AddRegistryKey("Key9", test_128, 16);
}

int suiteTearDown(int failures)
{
    BSL_CryptoDeinit();
    BSL_closelog();
    return failures;
}

void setUp(void)
{
    TEST_ASSERT_EQUAL(0, BSL_API_InitLib(&bsl));
}

void tearDown(void)
{
    TEST_ASSERT_EQUAL(0, BSL_API_DeinitLib(&bsl));
}

// test vectors from RFC 4231
// Test vector 1
TEST_MATRIX([ 0, 1 ], ["Key1"], [BSL_CRYPTO_SHA_256], ["4869205468657265"],
            ["b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"])
TEST_MATRIX([ 0, 1 ], ["Key1"], [BSL_CRYPTO_SHA_384], ["4869205468657265"],
            ["afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6"])
TEST_MATRIX([ 0, 1 ], ["Key1"], [BSL_CRYPTO_SHA_512], ["4869205468657265"],
            ["87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914ee"
             "b61f1702e696c203a126854"])

// Test vector 2
TEST_MATRIX([ 0, 1 ], ["Key2"], [BSL_CRYPTO_SHA_256], ["7768617420646f2079612077616e7420666f72206e6f7468696e673f"],
            ["5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"])
TEST_MATRIX([ 0, 1 ], ["Key2"], [BSL_CRYPTO_SHA_384], ["7768617420646f2079612077616e7420666f72206e6f7468696e673f"],
            ["af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e8e2240ca5e69e2c78b3239ecfab21649"])
TEST_MATRIX([ 0, 1 ], ["Key2"], [BSL_CRYPTO_SHA_512], ["7768617420646f2079612077616e7420666f72206e6f7468696e673f"],
            ["164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34"
             "d4a6b4b636e070a38bce737"])

// Test vector 7
TEST_MATRIX([ 0, 1 ], ["Key7"], [BSL_CRYPTO_SHA_256],
            ["5468697320697320612074657374207573696e672061206c6172676572207468616e20626c6f636b2d73697a65206b657920616e6"
             "42061206c6172676572207468616e20626c6f636b2d73697a6520646174612e20546865206b6579206e6565647320746f20626520"
             "686173686564206265666f7265206265696e6720757365642062792074686520484d414320616c676f726974686d2e"],
            ["9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2"])
TEST_MATRIX([ 0, 1 ], ["Key7"], [BSL_CRYPTO_SHA_384],
            ["5468697320697320612074657374207573696e672061206c6172676572207468616e20626c6f636b2d73697a65206b657920616e6"
             "42061206c6172676572207468616e20626c6f636b2d73697a6520646174612e20546865206b6579206e6565647320746f20626520"
             "686173686564206265666f7265206265696e6720757365642062792074686520484d414320616c676f726974686d2e"],
            ["6617178e941f020d351e2f254e8fd32c602420feb0b8fb9adccebb82461e99c5a678cc31e799176d3860e6110c46523e"])
TEST_MATRIX([ 0, 1 ], ["Key7"], [BSL_CRYPTO_SHA_512],
            ["5468697320697320612074657374207573696e672061206c6172676572207468616e20626c6f636b2d73697a65206b657920616e6"
             "42061206c6172676572207468616e20626c6f636b2d73697a6520646174612e20546865206b6579206e6565647320746f20626520"
             "686173686564206265666f7265206265696e6720757365642062792074686520484d414320616c676f726974686d2e"],
            ["e37b6a775dc87dbaa4dfa9f96e5e3ffddebd71f8867289865df5a32d20cdc944b6022cac3c4982b10d5eeb55c3e4de15134676fb6"
             "de0446065c97440fa8c6a58"])
void test_hmac_in(int input_case, const char *keyid, BSL_CryptoCipherSHAVariant_e sha_var, const char *plaintext_in,
                  char *expected)
{
    string_t exp_txt;
    string_init_set_str(exp_txt, expected);
    BSL_Data_t expected_data;
    BSL_Data_Init(&expected_data);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, BSL_TestUtils_DecodeBase16(&expected_data, exp_txt),
                                  "BSL_TestUtils_DecodeBase16() failed");

    string_t pt_txt;
    string_init_set_str(pt_txt, plaintext_in);
    BSL_Data_t pt_in_data;
    BSL_Data_Init(&pt_in_data);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, BSL_TestUtils_DecodeBase16(&pt_in_data, pt_txt),
                                  "BSL_TestUtils_DecodeBase16() failed");

    void *keyhandle;
    TEST_ASSERT_EQUAL(0, BSLB_Crypto_GetRegistryKey(keyid, &keyhandle));

    BSL_AuthCtx_t hmac;
    TEST_ASSERT_EQUAL(0, BSL_AuthCtx_Init(&hmac, keyhandle, sha_var));

    BSL_SeqReader_t reader;
    switch (input_case)
    {
        case 0:
            BSL_SeqReader_InitFlat(&reader, pt_in_data.ptr, pt_in_data.len);
            TEST_ASSERT_NOT_NULL(&reader);

            TEST_ASSERT_EQUAL(0, BSL_AuthCtx_DigestSeq(&hmac, &reader));
            break;
        case 1:
            TEST_ASSERT_EQUAL(0, BSL_AuthCtx_DigestBuffer(&hmac, (void *)pt_in_data.ptr, pt_in_data.len));
            break;
        default:
            TEST_ABORT();
    }
    int hmac_sz = 0;
    switch (hmac.SHA_variant)
    {
        case BSL_CRYPTO_SHA_256:
            hmac_sz = 32;
            break;
        case BSL_CRYPTO_SHA_384:
            hmac_sz = 48;
            break;
        case BSL_CRYPTO_SHA_512:
            hmac_sz = 64;
            break;
        default:
            TEST_ABORT();
    }
    uint8_t hmac_buf[hmac_sz];
    void   *hmac_buf_ptr = hmac_buf;
    size_t  hmac_len;
    TEST_ASSERT_EQUAL(0, BSL_AuthCtx_Finalize(&hmac, &hmac_buf_ptr, &hmac_len));
    TEST_ASSERT_EQUAL(hmac_sz, hmac_len);

    TEST_ASSERT_EQUAL_INT(hmac_len, expected_data.len);
    TEST_ASSERT_EQUAL_MEMORY(hmac_buf_ptr, expected_data.ptr, expected_data.len);

    TEST_ASSERT_EQUAL(0, BSL_AuthCtx_Deinit(&hmac));

    BSL_Data_Deinit(&expected_data);
    BSL_Data_Deinit(&pt_in_data);
    string_clear(exp_txt);
    string_clear(pt_txt);
}

/**
 * Test library encrypt using OpenSSL example decrypt
 */
TEST_MATRIX([ "plaintext", "0123456789", "" ], [ "Key8", "Key9" ])
void test_encrypt(const char *plaintext_in, const char *keyid)
{
    int res;

    int     iv_len = 16;
    uint8_t iv[iv_len];
    res = BSL_Crypto_GenIV(&iv, iv_len);
    TEST_ASSERT_EQUAL(0, res);

    BSL_SeqReader_t reader;
    BSL_SeqWriter_t writer;

    uint8_t *ciphertext;
    size_t   ct_size;

    res = BSL_SeqReader_InitFlat(&reader, (unsigned char *)plaintext_in, strlen(plaintext_in));
    TEST_ASSERT_EQUAL(0, res);

    res = BSL_SeqWriter_InitFlat(&writer, &ciphertext, &ct_size);
    TEST_ASSERT_EQUAL(0, res);

    int aes_var = (0 == strcmp(keyid, "Key8")) ? BSL_CRYPTO_AES_256 : BSL_CRYPTO_AES_128;

    BSL_Cipher_t ctx;
    void  *ekey;
    TEST_ASSERT_EQUAL(0, BSLB_Crypto_GetRegistryKey(keyid, &ekey));
    res = BSL_Cipher_Init(&ctx, BSL_CRYPTO_ENCRYPT, aes_var, iv, iv_len, ekey);
    TEST_ASSERT_EQUAL(0, res);

    uint8_t aad[2] = { 0x00, 0x01 };
    res            = BSL_Cipher_AddAAD(&ctx, aad, 2);
    TEST_ASSERT_EQUAL(0, res);

    res = BSL_Cipher_AddSeq(&ctx, &reader, &writer);
    TEST_ASSERT_EQUAL(0, res);

    uint8_t tag[16];
    void   *tag_ptr = tag;

    res = BSL_Cipher_FinalizeSeq(&ctx, &writer);
    TEST_ASSERT_EQUAL(0, res);

    res = BSL_SeqWriter_Deinit(&writer);
    TEST_ASSERT_EQUAL(0, res);

    res = BSL_Cipher_GetTag(&ctx, &tag_ptr);
    TEST_ASSERT_EQUAL(0, res);

    uint8_t plaintext[ct_size];
    int     plaintext_len;

    void *key;
    TEST_ASSERT_EQUAL_INT(0, BSLB_Crypto_GetRegistryKey(keyid, &key));
    TEST_ASSERT_NOT_NULL(key);

    bool              is_key8 = (0 == strcmp(keyid, "Key8"));
    const EVP_CIPHER *cipher  = (is_key8) ? EVP_aes_256_gcm() : EVP_aes_128_gcm();
    res                       = gcm_decrypt(cipher, ciphertext, ct_size, aad, 2, (unsigned char *)tag,
                                            (unsigned char *)((is_key8) ? test_256 : test_128), iv, iv_len, plaintext, &plaintext_len);
    TEST_ASSERT_EQUAL(0, res);

    plaintext[plaintext_len] = '\0';
    TEST_ASSERT_EQUAL(0, strcmp((char *)plaintext, plaintext_in));

    res = BSL_Cipher_Deinit(&ctx);
    TEST_ASSERT_EQUAL(0, res);

    BSL_FREE(ciphertext);
}

/**
 * Test library decrypt using OpenSSL example encrypt
 */
TEST_MATRIX([ "plaintext", "0123456789", "" ], [ "Key8", "Key9" ])
void test_decrypt(const char *plaintext_in, const char *keyid)
{
    int res;

    int     iv_len = 16;
    uint8_t iv[iv_len];
    res = BSL_Crypto_GenIV(&iv, iv_len);
    TEST_ASSERT_EQUAL(0, res);

    uint8_t aad[2] = { 0x00, 0x01 };

    uint8_t ciphertext[1000];
    uint8_t tag[16];
    int     ciphertext_len;

    void *key;
    TEST_ASSERT_EQUAL_INT(0, BSLB_Crypto_GetRegistryKey(keyid, &key));
    TEST_ASSERT_NOT_NULL(key);

    bool              is_key8 = (0 == strcmp(keyid, "Key8"));
    const EVP_CIPHER *cipher  = (is_key8) ? EVP_aes_256_gcm() : EVP_aes_128_gcm();
    res                       = gcm_encrypt(cipher, (unsigned char *)plaintext_in, strlen(plaintext_in), aad, 2,
                                            (unsigned char *)((is_key8) ? test_256 : test_128), iv, iv_len, ciphertext, &ciphertext_len, tag);
    TEST_ASSERT_EQUAL(0, res);

    BSL_SeqReader_t reader;
    BSL_SeqWriter_t writer;

    uint8_t *plaintext;
    size_t   pt_size;

    res = BSL_SeqReader_InitFlat(&reader, ciphertext, ciphertext_len);
    TEST_ASSERT_EQUAL(0, res);

    res = BSL_SeqWriter_InitFlat(&writer, &plaintext, &pt_size);
    TEST_ASSERT_EQUAL(0, res);

    int aes_var = (0 == strcmp(keyid, "Key8")) ? BSL_CRYPTO_AES_256 : BSL_CRYPTO_AES_128;

    void *ckey;
    TEST_ASSERT_EQUAL(0, BSLB_Crypto_GetRegistryKey(keyid, &ckey));
    BSL_Cipher_t ctx;
    res = BSL_Cipher_Init(&ctx, BSL_CRYPTO_DECRYPT, aes_var, iv, iv_len, ckey);
    TEST_ASSERT_EQUAL(0, res);

    res = BSL_Cipher_AddAAD(&ctx, aad, 2);
    TEST_ASSERT_EQUAL(0, res);

    res = BSL_Cipher_AddSeq(&ctx, &reader, &writer);
    TEST_ASSERT_EQUAL(0, res);

    res = BSL_Cipher_SetTag(&ctx, tag);
    TEST_ASSERT_EQUAL(0, res);

    res = BSL_Cipher_FinalizeSeq(&ctx, &writer);
    TEST_ASSERT_EQUAL(0, res);

    res = BSL_SeqWriter_Deinit(&writer);
    TEST_ASSERT_EQUAL(0, res);

    // compare output plaintext and expected plaintext
    char plaintext_c[pt_size + 1];
    memcpy(plaintext_c, plaintext, pt_size);
    plaintext_c[pt_size] = '\0';
    TEST_ASSERT_EQUAL(0, strcmp(plaintext_c, plaintext_in));

    res = BSL_Cipher_Deinit(&ctx);
    TEST_ASSERT_EQUAL(0, res);

    BSL_FREE(plaintext);
}

TEST_RANGE(<6, 18, 1>)
void test_crypto_generate_iv(int iv_len)
{
    uint8_t iv[iv_len];

    int res = BSL_Crypto_GenIV(&iv, iv_len);

    if (iv_len >= 8 && iv_len <= 16)
    {
        TEST_ASSERT_EQUAL(0, res);
    }
    else
    {
        TEST_ASSERT_LESS_THAN(0, res);
    }
}

// rfc3394 test vectors
TEST_CASE("000102030405060708090A0B0C0D0E0F", "00112233445566778899AABBCCDDEEFF", "1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5")
TEST_CASE("000102030405060708090A0B0C0D0E0F1011121314151617", "00112233445566778899AABBCCDDEEFF", "96778B25AE6CA435F92B5B97C050AED2468AB8A17AD84E5D")
TEST_CASE("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F", "00112233445566778899AABBCCDDEEFF", "64E8C3F9CE0F5BA263E9777905818A2A93C8191E7D6E8AE7")
TEST_CASE("000102030405060708090A0B0C0D0E0F1011121314151617", "00112233445566778899AABBCCDDEEFF0001020304050607", "031D33264E15D33268F24EC260743EDCE1C6C7DDEE725A936BA814915C6762D2")
TEST_CASE("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F", "00112233445566778899AABBCCDDEEFF0001020304050607", "A8F9BC1612C68B3FF6E6F4FBE30E71E4769C8B80A32CB8958CD5D17D6B254DA1")
TEST_CASE("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F", "00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F", "28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43BFB988B9B7A02DD21")
void test_key_wrap(const char *kek, const char *cek, const char *expected)
{
    // convert strings to bytedata
    string_t in_text;
    string_init_set_str(in_text, kek);
    BSL_Data_t kek_data;
    BSL_Data_Init(&kek_data);
    TEST_ASSERT_EQUAL(BSL_TestUtils_DecodeBase16(&kek_data, in_text), 0);
    string_clear(in_text);
    string_init_set_str(in_text, cek);
    BSL_Data_t cek_data;
    BSL_Data_Init(&cek_data);
    TEST_ASSERT_EQUAL(BSL_TestUtils_DecodeBase16(&cek_data, in_text), 0);
    string_clear(in_text);
    string_init_set_str(in_text, expected);
    BSL_Data_t expected_data;
    BSL_Data_Init(&expected_data);
    TEST_ASSERT_EQUAL(BSL_TestUtils_DecodeBase16(&expected_data, in_text), 0);
    string_clear(in_text);

    // convert bytedata to keyhandles
    BSL_Crypto_AddRegistryKey("kek", kek_data.ptr, kek_data.len);
    void *kek_handle;
    BSLB_Crypto_GetRegistryKey("kek", &kek_handle);

    BSL_Crypto_AddRegistryKey("cek", cek_data.ptr, cek_data.len);
    void *cek_handle;
    BSLB_Crypto_GetRegistryKey("cek", &cek_handle);

    void *wrapped_key_handle;
    BSL_Data_t wrapped_key;
    BSL_Data_InitBuffer(&wrapped_key, cek_data.len + 8);
    BSL_Crypto_WrapKey(kek_handle, cek_handle, &wrapped_key, &wrapped_key_handle);

    TEST_ASSERT_EQUAL_MEMORY(wrapped_key.ptr, expected_data.ptr, wrapped_key.len);

    BSL_Data_Deinit(&kek_data);
    BSL_Data_Deinit(&cek_data);
    BSL_Data_Deinit(&expected_data);
    BSL_Data_Deinit(&wrapped_key);
    BSL_Crypto_ClearKeyHandle((void *) wrapped_key_handle);
    BSLB_Crypto_RemoveRegistryKey("kek");
    BSLB_Crypto_RemoveRegistryKey("cek");
}

// rfc3394 test vectors
TEST_CASE("000102030405060708090A0B0C0D0E0F", "00112233445566778899AABBCCDDEEFF", "1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5")
TEST_CASE("000102030405060708090A0B0C0D0E0F1011121314151617", "00112233445566778899AABBCCDDEEFF", "96778B25AE6CA435F92B5B97C050AED2468AB8A17AD84E5D")
TEST_CASE("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F", "00112233445566778899AABBCCDDEEFF", "64E8C3F9CE0F5BA263E9777905818A2A93C8191E7D6E8AE7")
TEST_CASE("000102030405060708090A0B0C0D0E0F1011121314151617", "00112233445566778899AABBCCDDEEFF0001020304050607", "031D33264E15D33268F24EC260743EDCE1C6C7DDEE725A936BA814915C6762D2")
TEST_CASE("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F", "00112233445566778899AABBCCDDEEFF0001020304050607", "A8F9BC1612C68B3FF6E6F4FBE30E71E4769C8B80A32CB8958CD5D17D6B254DA1")
TEST_CASE("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F", "00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F", "28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43BFB988B9B7A02DD21")
void test_key_unwrap(const char *kek, const char *expected_cek, const char *wrapped_key)
{
    // convert strings to bytedata
    string_t in_text;
    string_init_set_str(in_text, kek);
    BSL_Data_t kek_data;
    BSL_Data_Init(&kek_data);
    TEST_ASSERT_EQUAL(BSL_TestUtils_DecodeBase16(&kek_data, in_text), 0);
    string_clear(in_text);
    string_init_set_str(in_text, expected_cek);
    BSL_Data_t cek_data;
    BSL_Data_Init(&cek_data);
    TEST_ASSERT_EQUAL(BSL_TestUtils_DecodeBase16(&cek_data, in_text), 0);
    string_clear(in_text);
    string_init_set_str(in_text, wrapped_key);
    BSL_Data_t wrapped_key_data;
    BSL_Data_Init(&wrapped_key_data);
    TEST_ASSERT_EQUAL(BSL_TestUtils_DecodeBase16(&wrapped_key_data, in_text), 0);
    string_clear(in_text);

    // convert bytedata to keyhandles
    BSL_Crypto_AddRegistryKey("kek", kek_data.ptr, kek_data.len);
    void *kek_handle;
    BSLB_Crypto_GetRegistryKey("kek", &kek_handle);

    BSL_Crypto_AddRegistryKey("cek", cek_data.ptr, cek_data.len);
    void *expected_cek_handle;
    BSLB_Crypto_GetRegistryKey("cek", &expected_cek_handle);

    void *cek_handle;
    BSL_Crypto_UnwrapKey(kek_handle, &wrapped_key_data, &cek_handle);

    // test our unwrapped key
    void *wrapped_key_handle1;
    BSL_Data_t wrapped_key1;
    BSL_Data_InitBuffer(&wrapped_key1, cek_data.len + 8);
    BSL_Crypto_WrapKey(kek_handle, cek_handle, &wrapped_key1, &wrapped_key_handle1);

    void *wrapped_key_handle2;
    BSL_Data_t wrapped_key2;
    BSL_Data_InitBuffer(&wrapped_key2, cek_data.len + 8);
    BSL_Crypto_WrapKey(kek_handle, expected_cek_handle, &wrapped_key2, &wrapped_key_handle2);
    
    TEST_ASSERT_EQUAL_MEMORY(wrapped_key1.ptr, wrapped_key_data.ptr, wrapped_key_data.len);
    TEST_ASSERT_EQUAL_MEMORY(wrapped_key1.ptr, wrapped_key2.ptr, wrapped_key2.len);

    BSL_Data_Deinit(&kek_data);
    BSL_Data_Deinit(&cek_data);
    BSL_Data_Deinit(&wrapped_key_data);
    BSL_Data_Deinit(&wrapped_key1);
    BSL_Data_Deinit(&wrapped_key2);
    BSL_Crypto_ClearKeyHandle((void *) cek_handle);
    BSL_Crypto_ClearKeyHandle((void *) wrapped_key_handle1);
    BSL_Crypto_ClearKeyHandle((void *) wrapped_key_handle2);
    BSLB_Crypto_RemoveRegistryKey("kek");
    BSLB_Crypto_RemoveRegistryKey("cek");
}