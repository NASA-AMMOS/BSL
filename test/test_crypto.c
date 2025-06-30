/*
 * Copyright (c) 2024 The Johns Hopkins University Applied Physics
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
#include <backend/DeprecatedLibContext.h>
#include <backend/DynBundleContext.h>
#include <backend/DynCrypto.h>
#include "Logging.h"
#include <TypeDefintions.h>
#include <UtilHelpers.h>
#include <inttypes.h>
#include <unity.h>

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

void suiteSetUp(void)
{
    BSL_openlog();
    BSL_CryptoInit();

    // static keys
    uint8_t test1[20] = { 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
                          0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b };
    uint8_t test2[4]  = { 0x4a, 0x65, 0x66, 0x65 };
    BSL_CryptoTools_AddKeyToRegistry(1, test1, 20);
    BSL_CryptoTools_AddKeyToRegistry(2, test2, 4);

    uint8_t test_128[16] = { 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
                             0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b };
    uint8_t test_256[32] = { 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
                             0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
                             0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b };
    BSL_CryptoTools_AddKeyToRegistry(8, test_256, 32);
    BSL_CryptoTools_AddKeyToRegistry(9, test_128, 16);
}

int suiteTearDown(int failures)
{
    BSL_CryptoDeinit();
    BSL_closelog();
    return failures;
}

void setUp(void)
{
    TEST_ASSERT_EQUAL(0, BSL_LibCtx_Init(&bsl));
}

void tearDown(void)
{
    TEST_ASSERT_EQUAL(0, BSL_LibCtx_Deinit(&bsl));
}

// test vectors from RFC 4231
// Test vector 1
TEST_MATRIX([ 0, 1 ], [1], [BSL_CRYPTO_SHA_256], ["4869205468657265"],
            ["b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"])
TEST_MATRIX([ 0, 1 ], [1], [BSL_CRYPTO_SHA_384], ["4869205468657265"],
            ["afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6"])
TEST_MATRIX([ 0, 1 ], [1], [BSL_CRYPTO_SHA_512], ["4869205468657265"],
            ["87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914ee"
             "b61f1702e696c203a126854"])

// Test vector 2
TEST_MATRIX([ 0, 1 ], [2], [BSL_CRYPTO_SHA_256], ["7768617420646f2079612077616e7420666f72206e6f7468696e673f"],
            ["5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"])
TEST_MATRIX([ 0, 1 ], [2], [BSL_CRYPTO_SHA_384], ["7768617420646f2079612077616e7420666f72206e6f7468696e673f"],
            ["af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e8e2240ca5e69e2c78b3239ecfab21649"])
TEST_MATRIX([ 0, 1 ], [2], [BSL_CRYPTO_SHA_512], ["7768617420646f2079612077616e7420666f72206e6f7468696e673f"],
            ["164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34"
             "d4a6b4b636e070a38bce737"])
void test_hmac_in(int input_case, uint64_t keyid, BSL_CryptoCipherSHAVariant_e sha_var, const char *plaintext_in,
                  char *expected)
{
    string_t exp_txt;
    string_init_set_str(exp_txt, expected);
    BSL_Data_t expected_data;
    BSL_Data_Init(&expected_data);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, base16_decode(&expected_data, exp_txt), "base16_decode() failed");

    string_t pt_txt;
    string_init_set_str(pt_txt, plaintext_in);
    BSL_Data_t pt_in_data;
    BSL_Data_Init(&pt_in_data);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, base16_decode(&pt_in_data, pt_txt), "base16_decode() failed");

    BSL_CryptoHMACCtx_t hmac;
    TEST_ASSERT_EQUAL(0, BSL_CryptoHMACCtx_Init(&hmac, keyid, sha_var));

    BSL_SeqReader_t reader;
    switch (input_case)
    {
        case 0:
            BSL_SeqReader_InitFlat(&reader, pt_in_data.ptr, pt_in_data.len);
            TEST_ASSERT_NOT_NULL(&reader);

            TEST_ASSERT_EQUAL(0, BSL_CryptoHMACCtx_DigestSeq(&hmac, &reader));
            break;
        case 1:
            TEST_ASSERT_EQUAL(0, BSL_CryptoHMACCtx_DigestBuffer(&hmac, (void *)pt_in_data.ptr, pt_in_data.len));
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
    TEST_ASSERT_EQUAL(0, BSL_CryptoHMACCtx_Finalize(&hmac, &hmac_buf_ptr, &hmac_len));
    TEST_ASSERT_EQUAL(hmac_sz, hmac_len);

    TEST_ASSERT_EQUAL_INT(hmac_len, expected_data.len);
    TEST_ASSERT_EQUAL_MEMORY(hmac_buf_ptr, expected_data.ptr, expected_data.len);

    TEST_ASSERT_EQUAL(0, BSL_CryptoHMACCtx_Deinit(&hmac));

    BSL_Data_Deinit(&expected_data);
    BSL_Data_Deinit(&pt_in_data);
    string_clear(exp_txt);
    string_clear(pt_txt);
}

/**
 * Test library encrypt using OpenSSL example decrypt
 */
TEST_MATRIX([ "plaintext", "0123456789", "" ], [ 8, 9 ])
void test_encrypt(const char *plaintext_in, uint64_t keyid)
{
    int res;

    int     iv_len = 16;
    uint8_t iv[iv_len];
    res = BSL_CryptoTools_GenIV(&iv, iv_len);
    TEST_ASSERT_EQUAL(0, res);

    BSL_SeqReader_t reader;
    BSL_SeqWriter_t writer;

    uint8_t *ciphertext;
    size_t   ct_size;

    res = BSL_SeqReader_InitFlat(&reader, (unsigned char *)plaintext_in, strlen(plaintext_in));
    TEST_ASSERT_EQUAL(0, res);

    res = BSL_SeqWriter_InitFlat(&writer, &ciphertext, &ct_size);
    TEST_ASSERT_EQUAL(0, res);

    int aes_var = (keyid == 8) ? BSL_CRYPTO_AES_256 : BSL_CRYPTO_AES_128;

    BSL_CryptoCipherCtx_t ctx;
    const uint8_t        *ekey;
    size_t                ekeylen = 0;
    TEST_ASSERT_EQUAL(0, BSL_CryptoTools_GetKeyFromRegistry(keyid, &ekey, &ekeylen));
    BSL_Data_t key_data;
    BSL_Data_InitView(&key_data, ekeylen, (uint8_t *)ekey);
    res = BSL_CryptoCipherCtx_Init(&ctx, BSL_CRYPTO_ENCRYPT, aes_var, iv, iv_len, key_data);
    TEST_ASSERT_EQUAL(0, res);

    uint8_t aad[2] = { 0x00, 0x01 };
    res            = BSL_CryptoCipherCtx_AddAAD(&ctx, aad, 2);
    TEST_ASSERT_EQUAL(0, res);

    res = BSL_CryptoCipherCtx_AddSeq(&ctx, &reader, &writer);
    TEST_ASSERT_EQUAL(0, res);

    uint8_t tag[16];
    void   *tag_ptr = tag;

    res = BSL_CryptoCipherContext_FinalizeSeq(&ctx, &writer);
    TEST_ASSERT_EQUAL(0, res);

    res = BSL_SeqWriter_Deinit(&writer);
    TEST_ASSERT_EQUAL(0, res);

    res = BSL_CryptoCipherCtx_GetTag(&ctx, &tag_ptr);
    TEST_ASSERT_EQUAL(0, res);

    uint8_t plaintext[ct_size];
    int     plaintext_len;

    const uint8_t *key;
    TEST_ASSERT_EQUAL_INT(0, BSL_CryptoTools_GetKeyFromRegistry(keyid, &key, NULL));
    TEST_ASSERT_NOT_NULL(key);

    const EVP_CIPHER *cipher = (keyid == 8) ? EVP_aes_256_gcm() : EVP_aes_128_gcm();
    res = gcm_decrypt(cipher, ciphertext, ct_size, aad, 2, (unsigned char *)tag, (unsigned char *)key, iv, iv_len,
                      plaintext, &plaintext_len);
    TEST_ASSERT_EQUAL(0, res);

    plaintext[plaintext_len] = '\0';
    TEST_ASSERT_EQUAL(0, strcmp((char *)plaintext, plaintext_in));

    res = BSL_CryptoCipherCtx_Deinit(&ctx);
    TEST_ASSERT_EQUAL(0, res);

    BSL_FREE(ciphertext);
}

/**
 * Test library decrypt using OpenSSL example encrypt
 */
TEST_MATRIX([ "plaintext", "0123456789", "" ], [ 8, 9 ])
void test_decrypt(const char *plaintext_in, uint64_t keyid)
{
    int res;

    int     iv_len = 16;
    uint8_t iv[iv_len];
    res = BSL_CryptoTools_GenIV(&iv, iv_len);
    TEST_ASSERT_EQUAL(0, res);

    uint8_t aad[2] = { 0x00, 0x01 };

    uint8_t ciphertext[1000];
    uint8_t tag[16];
    int     ciphertext_len;

    const uint8_t *key;
    TEST_ASSERT_EQUAL_INT(0, BSL_CryptoTools_GetKeyFromRegistry(keyid, &key, NULL));
    TEST_ASSERT_NOT_NULL(key);

    const EVP_CIPHER *cipher = (keyid == 8) ? EVP_aes_256_gcm() : EVP_aes_128_gcm();
    res = gcm_encrypt(cipher, (unsigned char *)plaintext_in, strlen(plaintext_in), aad, 2, (unsigned char *)key, iv,
                      iv_len, ciphertext, &ciphertext_len, tag);
    TEST_ASSERT_EQUAL(0, res);

    BSL_SeqReader_t reader;
    BSL_SeqWriter_t writer;

    uint8_t *plaintext;
    size_t   pt_size;

    res = BSL_SeqReader_InitFlat(&reader, ciphertext, ciphertext_len);
    TEST_ASSERT_EQUAL(0, res);

    res = BSL_SeqWriter_InitFlat(&writer, &plaintext, &pt_size);
    TEST_ASSERT_EQUAL(0, res);

    int aes_var = (keyid == 8) ? BSL_CRYPTO_AES_256 : BSL_CRYPTO_AES_128;

    const uint8_t *ckey;
    size_t         ckeylen;
    TEST_ASSERT_EQUAL(0, BSL_CryptoTools_GetKeyFromRegistry(keyid, &ckey, &ckeylen));
    BSL_Data_t key_data;
    BSL_Data_InitView(&key_data, ckeylen, (uint8_t *)ckey);
    BSL_CryptoCipherCtx_t ctx;
    res = BSL_CryptoCipherCtx_Init(&ctx, BSL_CRYPTO_DECRYPT, aes_var, iv, iv_len, key_data);
    TEST_ASSERT_EQUAL(0, res);

    res = BSL_CryptoCipherCtx_AddAAD(&ctx, aad, 2);
    TEST_ASSERT_EQUAL(0, res);

    res = BSL_CryptoCipherCtx_AddSeq(&ctx, &reader, &writer);
    TEST_ASSERT_EQUAL(0, res);

    res = BSL_CryptoCipherCtx_SetTag(&ctx, tag);
    TEST_ASSERT_EQUAL(0, res);

    res = BSL_CryptoCipherContext_FinalizeSeq(&ctx, &writer);
    TEST_ASSERT_EQUAL(0, res);

    res = BSL_SeqWriter_Deinit(&writer);
    TEST_ASSERT_EQUAL(0, res);

    // compare output plaintext and expected plaintext
    char plaintext_c[pt_size + 1];
    memcpy(plaintext_c, plaintext, pt_size);
    plaintext_c[pt_size] = '\0';
    TEST_ASSERT_EQUAL(0, strcmp(plaintext_c, plaintext_in));

    res = BSL_CryptoCipherCtx_Deinit(&ctx);
    TEST_ASSERT_EQUAL(0, res);

    BSL_FREE(plaintext);
}

TEST_RANGE(<6, 18, 1>)
void test_crypto_generate_iv(int iv_len)
{
    uint8_t iv[iv_len];

    int res = BSL_CryptoTools_GenIV(&iv, iv_len);

    if (iv_len >= 8 && iv_len <= 16)
    {
        TEST_ASSERT_EQUAL(0, res);
    }
    else
    {
        TEST_ASSERT_EQUAL(1, res);
    }
}
