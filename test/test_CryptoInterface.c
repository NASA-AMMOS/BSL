/*
 * Copyright (c) 2025-2026 The Johns Hopkins University Applied Physics
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
#include "DefaultScUtils.h"

#include <bsl/BPSecLib_Private.h>
#include <bsl/crypto/CryptoInterface.h>
#include <bsl/dynamic/PublicInterfaceImpl.h>
#include <bsl/mock_bpa/agent.h>
#include <bsl/mock_bpa/log.h>

#include <openssl/err.h>
#include <openssl/rand.h>

#include <inttypes.h>
#include <unity.h>

static BSL_LibCtx_t bsl;

/**
 * copied from openssl examples, used for testing for now
 * https://wiki.openssl.org/index.php/EVP_Authenticated_Encryption_and_Decryption
 */
static int gcm_encrypt(const EVP_CIPHER *cipher, unsigned char *plaintext, int plaintext_len, unsigned char *aad,
                       int aad_len, unsigned char *key, unsigned char *iv, int iv_len, unsigned char *ciphertext,
                       int *ciphertext_len, unsigned char *tag)
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
static int gcm_decrypt(const EVP_CIPHER *cipher, unsigned char *ciphertext, int ciphertext_len, unsigned char *aad,
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
    TEST_ASSERT_EQUAL_INT(0, BSL_HostDescriptors_Set(MockBPA_Agent_Descriptors(NULL)));
    mock_bpa_LogOpen();
    mock_bpa_LogSetLeastSeverity(LOG_ERR);
}

int suiteTearDown(int failures)
{
    mock_bpa_LogClose();
    return failures;
}

void setUp(void)
{
    TEST_ASSERT_EQUAL(0, BSL_API_InitLib(&bsl));

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
    BSL_Crypto_AddRegistryKeyName("Key1", test1, sizeof(test1));
    BSL_Crypto_AddRegistryKeyName("Key2", test2, sizeof(test2));
    BSL_Crypto_AddRegistryKeyName("Key7", test7, sizeof(test7));

    BSL_Crypto_AddRegistryKeyName("Key8", test_256, sizeof(test_256));
    BSL_Crypto_AddRegistryKeyName("Key9", test_128, sizeof(test_128));
}

void tearDown(void)
{
    BSL_CryptoDeinit();
    TEST_ASSERT_EQUAL(0, BSL_API_DeinitLib(&bsl));
}

void test_SeqReader_flat(void)
{
    uint8_t source[] = { 0x01, 0x02, 0x03, 0x04, 0x05 };

    BSL_SeqReader_t *reader = BSL_TestUtils_FlatReader(source, sizeof(source));
    TEST_ASSERT_NOT_NULL(reader);

    uint8_t buf[3];
    size_t  bufsize = sizeof(buf);
    // first 3 bytes
    TEST_ASSERT_EQUAL_INT(0, BSL_SeqReader_Get(reader, buf, &bufsize));
    TEST_ASSERT_EQUAL_INT(3, bufsize);
    TEST_ASSERT_EQUAL_MEMORY(source, buf, 3);
    // next 2 bytes
    bufsize = sizeof(buf);
    TEST_ASSERT_EQUAL_INT(0, BSL_SeqReader_Get(reader, buf, &bufsize));
    TEST_ASSERT_EQUAL_INT(2, bufsize);
    TEST_ASSERT_EQUAL_MEMORY(source + 3, buf, 2);

    BSL_SeqReader_Destroy(reader);
}

void test_SeqWriter_flat(void)
{
    uint8_t *dest      = NULL;
    size_t   dest_size = 0;

    BSL_SeqWriter_t *writer = BSL_TestUtils_FlatWriter((void **)&dest, &dest_size);
    TEST_ASSERT_NOT_NULL(writer);

    uint8_t buf[3]  = { 0x01, 0x02, 0x03 };
    size_t  bufsize = sizeof(buf);
    // first 3 bytes
    TEST_ASSERT_EQUAL_INT(0, BSL_SeqWriter_Put(writer, buf, bufsize));
    // next 2 bytes
    bufsize = sizeof(buf) - 1;
    TEST_ASSERT_EQUAL_INT(0, BSL_SeqWriter_Put(writer, buf, bufsize));

    TEST_ASSERT_NULL(dest);
    TEST_ASSERT_EQUAL_size_t(0, dest_size);
    BSL_SeqWriter_Destroy(writer, true);

    TEST_ASSERT_NOT_NULL(dest);
    TEST_ASSERT_EQUAL_size_t(5, dest_size);
    const uint8_t expect[] = { 0x01, 0x02, 0x03, 0x01, 0x02 };
    TEST_ASSERT_EQUAL_MEMORY(expect, dest, sizeof(expect));

    BSL_free(dest);
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
void test_hmac_in(int input_case, const char *keyid, BSL_Crypto_SHAVariant_e sha_var, const char *plaintext_in,
                  const char *expected)
{
    BSL_Data_t pt_in_data;
    BSL_Data_Init(&pt_in_data);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, BSL_TestUtils_DecodeBase16_cstr(&pt_in_data, plaintext_in),
                                  "BSL_TestUtils_DecodeBase16_cstr() failed");

    BSL_Crypto_KeyHandle_t keyhandle;
    TEST_ASSERT_EQUAL(0, BSL_Crypto_GetRegistryKeyName(keyid, &keyhandle));

    BSL_AuthCtx_t hmac;
    TEST_ASSERT_EQUAL(0, BSL_AuthCtx_Init(&hmac, keyhandle, sha_var));
    BSL_Crypto_ReleaseKeyHandle(keyhandle);

    switch (input_case)
    {
        case 0:
        {
            BSL_SeqReader_t *reader = BSL_TestUtils_FlatReader(pt_in_data.ptr, pt_in_data.len);
            TEST_ASSERT_NOT_NULL(reader);

            TEST_ASSERT_EQUAL(0, BSL_AuthCtx_DigestSeq(&hmac, reader));

            BSL_SeqReader_Destroy(reader);
            break;
        }
        case 1:
            TEST_ASSERT_EQUAL(0, BSL_AuthCtx_DigestBuffer(&hmac, (void *)pt_in_data.ptr, pt_in_data.len));
            break;
        default:
            TEST_ABORT();
    }
    int expect_hmac_sz = 0;
    switch (sha_var)
    {
        case BSL_CRYPTO_SHA_256:
            expect_hmac_sz = 32;
            break;
        case BSL_CRYPTO_SHA_384:
            expect_hmac_sz = 48;
            break;
        case BSL_CRYPTO_SHA_512:
            expect_hmac_sz = 64;
            break;
        default:
            TEST_ABORT();
    }

    BSL_Data_t tag;
    BSL_Data_Init(&tag);
    TEST_ASSERT_EQUAL(0, BSL_AuthCtx_Finalize(&hmac, &tag));
    TEST_ASSERT_EQUAL(expect_hmac_sz, tag.len);

    TEST_ASSERT_TRUE(BSL_TestUtils_IsB16StrEqualTo(expected, tag));

    BSL_Data_Deinit(&tag);
    BSL_AuthCtx_Deinit(&hmac);
    BSL_Data_Deinit(&pt_in_data);
}

/**
 * Test library encrypt using OpenSSL example decrypt
 */
TEST_MATRIX([ "plaintext", "0123456789", "" ], [ "Key8", "Key9" ])
void test_encrypt(const char *plaintext_in, const char *keyid)
{
    int res;

    BSL_Data_t iv;
    BSL_Data_InitBuffer(&iv, 16);
    res = BSL_Crypto_GenIV(&iv);
    TEST_ASSERT_EQUAL(0, res);

    size_t           pt_size = strlen(plaintext_in);
    BSL_SeqReader_t *reader  = BSL_TestUtils_FlatReader((const void *)plaintext_in, pt_size);
    TEST_ASSERT_NOT_NULL(reader);

    uint8_t         *ciphertext;
    size_t           ct_size;
    BSL_SeqWriter_t *writer = BSL_TestUtils_FlatWriter((void *)&ciphertext, &ct_size);
    TEST_ASSERT_NOT_NULL(writer);

    int aes_var = (0 == strcmp(keyid, "Key8")) ? BSL_CRYPTO_AES_256 : BSL_CRYPTO_AES_128;

    BSL_Crypto_KeyHandle_t ekey;
    TEST_ASSERT_EQUAL(0, BSL_Crypto_GetRegistryKeyName(keyid, &ekey));
    BSL_Cipher_t ctx;
    res = BSL_Cipher_Init(&ctx, BSL_CRYPTO_ENCRYPT, aes_var, &iv, ekey);
    TEST_ASSERT_EQUAL(0, res);

    uint8_t aad[2] = { 0x00, 0x01 };
    res            = BSL_Cipher_AddAadBuffer(&ctx, aad, 2);
    TEST_ASSERT_EQUAL(0, res);

    res = BSL_Cipher_AddSeq(&ctx, reader, writer, pt_size);
    TEST_ASSERT_EQUAL(0, res);

    BSL_Data_t tag;
    BSL_Data_Init(&tag);

    res = BSL_Cipher_FinalizeSeq(&ctx, writer);
    TEST_ASSERT_EQUAL(0, res);

    BSL_SeqWriter_Destroy(writer, true);

    res = BSL_Cipher_GetTag(&ctx, &tag);
    TEST_ASSERT_EQUAL(0, res);
    TEST_ASSERT_NOT_NULL(tag.ptr);
    TEST_ASSERT_EQUAL_size_t(16, tag.len);

    uint8_t plaintext[ct_size];
    int     plaintext_len;

    bool              is_key8 = (0 == strcmp(keyid, "Key8"));
    const EVP_CIPHER *cipher  = (is_key8) ? EVP_aes_256_gcm() : EVP_aes_128_gcm();
    res                       = gcm_decrypt(cipher, ciphertext, ct_size, aad, 2, (unsigned char *)tag.ptr,
                                            (unsigned char *)((is_key8) ? test_256 : test_128), iv.ptr, iv.len, plaintext, &plaintext_len);
    TEST_ASSERT_EQUAL(0, res);
    BSL_Data_Deinit(&tag);

    TEST_ASSERT_EQUAL_INT(ct_size, plaintext_len);
    if (plaintext_len > 0)
    {
        TEST_ASSERT_EQUAL_MEMORY(plaintext_in, plaintext, plaintext_len);
    }

    BSL_SeqReader_Destroy(reader);

    res = BSL_Cipher_Deinit(&ctx);
    TEST_ASSERT_EQUAL(0, res);
    BSL_Crypto_ReleaseKeyHandle(ekey);
    BSL_Data_Deinit(&iv);

    BSL_free(ciphertext);
}

/**
 * Test library decrypt using OpenSSL example encrypt
 */
TEST_MATRIX([ "plaintext", "0123456789", "" ], [ "Key8", "Key9" ])
void test_decrypt(const char *plaintext_in, const char *keyid)
{
    int res;

    BSL_Data_t iv;
    BSL_Data_InitBuffer(&iv, 16);

    res = BSL_Crypto_GenIV(&iv);
    TEST_ASSERT_EQUAL(0, res);

    uint8_t aad[2] = { 0x00, 0x01 };

    uint8_t ciphertext[1000];
    int     ciphertext_len = 0;

    BSL_Data_t tag;
    BSL_Data_InitBuffer(&tag, 16);

    bool              is_key8 = (0 == strcmp(keyid, "Key8"));
    const EVP_CIPHER *cipher  = (is_key8) ? EVP_aes_256_gcm() : EVP_aes_128_gcm();
    res                       = gcm_encrypt(cipher, (unsigned char *)plaintext_in, strlen(plaintext_in), aad, 2,
                                            (unsigned char *)((is_key8) ? test_256 : test_128), iv.ptr, iv.len, ciphertext, &ciphertext_len,
                                            tag.ptr);
    TEST_ASSERT_EQUAL(0, res);
    TEST_ASSERT_GREATER_OR_EQUAL_INT(0, ciphertext_len);

    BSL_SeqReader_t *reader = BSL_TestUtils_FlatReader((const void *)ciphertext, ciphertext_len);

    uint8_t         *plaintext;
    size_t           pt_size;
    BSL_SeqWriter_t *writer = BSL_TestUtils_FlatWriter((void *)&plaintext, &pt_size);

    int aes_var = (0 == strcmp(keyid, "Key8")) ? BSL_CRYPTO_AES_256 : BSL_CRYPTO_AES_128;

    BSL_Crypto_KeyHandle_t ckey;
    TEST_ASSERT_EQUAL(0, BSL_Crypto_GetRegistryKeyName(keyid, &ckey));
    BSL_Cipher_t ctx;
    res = BSL_Cipher_Init(&ctx, BSL_CRYPTO_DECRYPT, aes_var, &iv, ckey);
    TEST_ASSERT_EQUAL(0, res);

    res = BSL_Cipher_AddAadBuffer(&ctx, aad, 2);
    TEST_ASSERT_EQUAL(0, res);

    res = BSL_Cipher_AddSeq(&ctx, reader, writer, ciphertext_len);
    TEST_ASSERT_EQUAL(0, res);

    res = BSL_Cipher_SetTag(&ctx, &tag);
    TEST_ASSERT_EQUAL(0, res);
    BSL_Data_Deinit(&tag);

    res = BSL_Cipher_FinalizeSeq(&ctx, writer);
    TEST_ASSERT_EQUAL(0, res);

    BSL_SeqWriter_Destroy(writer, true);

    if (pt_size > 0)
    {
        // compare output plaintext and expected plaintext
        TEST_ASSERT_EQUAL_MEMORY(plaintext_in, plaintext, pt_size);
    }

    TEST_ASSERT_EQUAL(0, BSL_Cipher_Deinit(&ctx));
    BSL_Crypto_ReleaseKeyHandle(ckey);
    BSL_Data_Deinit(&iv);

    BSL_SeqReader_Destroy(reader);
    BSL_free(plaintext);
}

TEST_RANGE(<6, 18, 1>)
void test_crypto_generate_iv(int iv_len)
{
    BSL_Data_t buf;
    BSL_Data_InitBuffer(&buf, iv_len);

    int res = BSL_Crypto_GenIV(&buf);
    TEST_ASSERT_EQUAL(0, res);

    BSL_Data_Deinit(&buf);
}

// rfc3394 test vectors
TEST_CASE("000102030405060708090A0B0C0D0E0F", "00112233445566778899AABBCCDDEEFF",
          "1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5")
TEST_CASE("000102030405060708090A0B0C0D0E0F1011121314151617", "00112233445566778899AABBCCDDEEFF",
          "96778B25AE6CA435F92B5B97C050AED2468AB8A17AD84E5D")
TEST_CASE("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F", "00112233445566778899AABBCCDDEEFF",
          "64E8C3F9CE0F5BA263E9777905818A2A93C8191E7D6E8AE7")
TEST_CASE("000102030405060708090A0B0C0D0E0F1011121314151617", "00112233445566778899AABBCCDDEEFF0001020304050607",
          "031D33264E15D33268F24EC260743EDCE1C6C7DDEE725A936BA814915C6762D2")
TEST_CASE("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
          "00112233445566778899AABBCCDDEEFF0001020304050607",
          "A8F9BC1612C68B3FF6E6F4FBE30E71E4769C8B80A32CB8958CD5D17D6B254DA1")
TEST_CASE("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
          "00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F",
          "28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43BFB988B9B7A02DD21")
void test_key_wrap(const char *kek, const char *cek, const char *expected)
{
    // convert strings to bytedata
    BSL_Data_t kek_data;
    BSL_Data_Init(&kek_data);
    TEST_ASSERT_EQUAL(0, BSL_TestUtils_DecodeBase16_cstr(&kek_data, kek));

    BSL_Data_t cek_data;
    BSL_Data_Init(&cek_data);
    TEST_ASSERT_EQUAL(0, BSL_TestUtils_DecodeBase16_cstr(&cek_data, cek));

    // convert bytedata to keyhandles
    TEST_ASSERT_EQUAL_INT(0, BSL_Crypto_AddRegistryKeyName("kek", kek_data.ptr, kek_data.len));
    BSL_Crypto_KeyHandle_t kek_handle;
    TEST_ASSERT_EQUAL_INT(0, BSL_Crypto_GetRegistryKeyName("kek", &kek_handle));

    TEST_ASSERT_EQUAL_INT(0, BSL_Crypto_AddRegistryKeyName("cek", cek_data.ptr, cek_data.len));
    BSL_Crypto_KeyHandle_t cek_handle;
    TEST_ASSERT_EQUAL_INT(0, BSL_Crypto_GetRegistryKeyName("cek", &cek_handle));

    BSL_Data_t wrapped_key;
    BSL_Data_InitBuffer(&wrapped_key, cek_data.len + 8);
    TEST_ASSERT_EQUAL_INT(0, BSL_Crypto_WrapKey(kek_handle, cek_handle, &wrapped_key));

    TEST_ASSERT_TRUE(BSL_TestUtils_IsB16StrEqualTo(expected, wrapped_key));

    BSL_Crypto_KeyStats_t stats;
    BSL_Crypto_GetKeyStatistics(kek_handle, &stats);
    TEST_ASSERT_EQUAL_size_t(1, stats.stats[BSL_CRYPTO_KEYSTATS_TIMES_USED]);
    TEST_ASSERT_EQUAL_size_t(cek_data.len, stats.stats[BSL_CRYPTO_KEYSTATS_BYTES_PROCESSED]);

    BSL_Crypto_ReleaseKeyHandle(cek_handle);
    BSL_Crypto_ReleaseKeyHandle(kek_handle);
    BSL_Data_Deinit(&kek_data);
    BSL_Data_Deinit(&cek_data);
    BSL_Data_Deinit(&wrapped_key);
    BSL_Crypto_RemoveRegistryKeyName("kek");
    BSL_Crypto_RemoveRegistryKeyName("cek");
}

// rfc3394 test vectors
TEST_CASE("000102030405060708090A0B0C0D0E0F", "00112233445566778899AABBCCDDEEFF",
          "1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5")
TEST_CASE("000102030405060708090A0B0C0D0E0F1011121314151617", "00112233445566778899AABBCCDDEEFF",
          "96778B25AE6CA435F92B5B97C050AED2468AB8A17AD84E5D")
TEST_CASE("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F", "00112233445566778899AABBCCDDEEFF",
          "64E8C3F9CE0F5BA263E9777905818A2A93C8191E7D6E8AE7")
TEST_CASE("000102030405060708090A0B0C0D0E0F1011121314151617", "00112233445566778899AABBCCDDEEFF0001020304050607",
          "031D33264E15D33268F24EC260743EDCE1C6C7DDEE725A936BA814915C6762D2")
TEST_CASE("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
          "00112233445566778899AABBCCDDEEFF0001020304050607",
          "A8F9BC1612C68B3FF6E6F4FBE30E71E4769C8B80A32CB8958CD5D17D6B254DA1")
TEST_CASE("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
          "00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F",
          "28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43BFB988B9B7A02DD21")
void test_key_unwrap(const char *kek, const char *expected_cek, const char *wrapped_key)
{
    // convert strings to bytedata
    BSL_Data_t kek_data;
    BSL_Data_Init(&kek_data);
    TEST_ASSERT_EQUAL(BSL_TestUtils_DecodeBase16_cstr(&kek_data, kek), 0);

    BSL_Data_t cek_data;
    BSL_Data_Init(&cek_data);
    TEST_ASSERT_EQUAL(BSL_TestUtils_DecodeBase16_cstr(&cek_data, expected_cek), 0);

    BSL_Data_t wrapped_key_data;
    BSL_Data_Init(&wrapped_key_data);
    TEST_ASSERT_EQUAL(BSL_TestUtils_DecodeBase16_cstr(&wrapped_key_data, wrapped_key), 0);

    // convert bytedata to keyhandles
    TEST_ASSERT_EQUAL_INT(0, BSL_Crypto_AddRegistryKeyName("kek", kek_data.ptr, kek_data.len));
    BSL_Crypto_KeyHandle_t kek_handle;
    TEST_ASSERT_EQUAL_INT(0, BSL_Crypto_GetRegistryKeyName("kek", &kek_handle));

    TEST_ASSERT_EQUAL_INT(0, BSL_Crypto_AddRegistryKeyName("expect", cek_data.ptr, cek_data.len));
    BSL_Crypto_KeyHandle_t expect_handle;
    TEST_ASSERT_EQUAL_INT(0, BSL_Crypto_GetRegistryKeyName("expect", &expect_handle));

    BSL_Crypto_KeyHandle_t cek_handle;
    TEST_ASSERT_EQUAL_INT(0, BSL_Crypto_UnwrapKey(kek_handle, &wrapped_key_data, &cek_handle));

    TEST_ASSERT_TRUE(BSL_Crypto_CompareKeys(expect_handle, cek_handle));

    BSL_Crypto_KeyStats_t stats;
    BSL_Crypto_GetKeyStatistics(kek_handle, &stats);
    TEST_ASSERT_EQUAL_size_t(1, stats.stats[BSL_CRYPTO_KEYSTATS_TIMES_USED]);
    TEST_ASSERT_EQUAL_size_t(cek_data.len, stats.stats[BSL_CRYPTO_KEYSTATS_BYTES_PROCESSED]);

    BSL_Data_Deinit(&kek_data);
    BSL_Data_Deinit(&cek_data);
    BSL_Data_Deinit(&wrapped_key_data);
    BSL_Crypto_ReleaseKeyHandle(cek_handle);
    BSL_Crypto_ReleaseKeyHandle(expect_handle);
    BSL_Crypto_ReleaseKeyHandle(kek_handle);
    BSL_Crypto_RemoveRegistryKeyName("kek");
    BSL_Crypto_RemoveRegistryKeyName("cek");
}

// RFC 5869 test vectors
TEST_CASE("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", BSL_CRYPTO_KDF_HKDF_SHA_256, "000102030405060708090a0b0c",
          "f0f1f2f3f4f5f6f7f8f9", 42,
          "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865")
TEST_CASE("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", BSL_CRYPTO_KDF_HKDF_SHA_256, "", "", 42,
          "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8")
void test_kdf(const char *kdk_hex, int func, const char *salt_hex, const char *info_hex, size_t keylen,
              const char *expect_hex)
{
    BSL_Data_t kdk_data;
    BSL_Data_Init(&kdk_data);
    TEST_ASSERT_EQUAL(0, BSL_TestUtils_DecodeBase16_cstr(&kdk_data, kdk_hex));

    BSL_Data_t salt_data;
    BSL_Data_Init(&salt_data);
    TEST_ASSERT_EQUAL(0, BSL_TestUtils_DecodeBase16_cstr(&salt_data, salt_hex));

    BSL_Data_t info_data;
    BSL_Data_Init(&info_data);
    TEST_ASSERT_EQUAL_INT(0, BSL_TestUtils_DecodeBase16_cstr(&info_data, info_hex));

    BSL_Data_t expect_data;
    BSL_Data_Init(&expect_data);
    TEST_ASSERT_EQUAL_INT(0, BSL_TestUtils_DecodeBase16_cstr(&expect_data, expect_hex));

    // convert bytedata to keyhandles
    TEST_ASSERT_EQUAL_INT(0, BSL_Crypto_AddRegistryKeyName("kdk", kdk_data.ptr, kdk_data.len));
    BSL_Crypto_KeyHandle_t kdk_handle;
    TEST_ASSERT_EQUAL_INT(0, BSL_Crypto_GetRegistryKeyName("kdk", &kdk_handle));

    TEST_ASSERT_EQUAL_INT(0, BSL_Crypto_AddRegistryKeyName("expect", expect_data.ptr, expect_data.len));
    BSL_Crypto_KeyHandle_t expect_handle;
    TEST_ASSERT_EQUAL_INT(0, BSL_Crypto_GetRegistryKeyName("expect", &expect_handle));

    BSL_Crypto_KeyHandle_t cek_handle;
    TEST_ASSERT_EQUAL_INT(0, BSL_Crypto_KDF(kdk_handle, func, &salt_data, &info_data, keylen, &cek_handle));

    TEST_ASSERT_TRUE(BSL_Crypto_CompareKeys(expect_handle, cek_handle));

    BSL_Crypto_KeyStats_t stats;
    BSL_Crypto_GetKeyStatistics(kdk_handle, &stats);
    TEST_ASSERT_EQUAL_size_t(1, stats.stats[BSL_CRYPTO_KEYSTATS_TIMES_USED]);
    TEST_ASSERT_EQUAL_size_t(keylen, stats.stats[BSL_CRYPTO_KEYSTATS_BYTES_PROCESSED]);

    BSL_Crypto_ReleaseKeyHandle(cek_handle);
    BSL_Crypto_ReleaseKeyHandle(expect_handle);
    BSL_Crypto_ReleaseKeyHandle(kdk_handle);
    BSL_Data_Deinit(&expect_data);
    BSL_Data_Deinit(&info_data);
    BSL_Data_Deinit(&salt_data);
    BSL_Data_Deinit(&kdk_data);
}

#define TEST_THREADS 10
static pthread_t threads[TEST_THREADS];

static void *add_key_to_reg_fn(void *arg)
{
    const char          *name        = (const char *)arg;
    static const uint8_t key_bytes[] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                                         0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF };
    int                  res         = BSL_Crypto_AddRegistryKeyName(name, key_bytes, sizeof(key_bytes));
    if (BSL_SUCCESS == res)
    {
        BSL_LOG_INFO("ADDED %s KEY TO CRYPTO REG", name);
        return (void *)name;
    }
    else
    {
        BSL_LOG_INFO("FAILED TO ADD %s KEY TO CRYPTO REG", name);
        return NULL;
    }
}

static void *get_key_from_reg_fn(void *arg)
{
    const char *name = (const char *)arg;

    BSL_Crypto_KeyHandle_t handle;
    int                    res = BSL_Crypto_GetRegistryKeyName(name, &handle);
    BSL_Crypto_ReleaseKeyHandle(handle);
    if (BSL_SUCCESS == res)
    {
        BSL_LOG_INFO("GOT %s KEY FROM CRYPTO REG", name);
        return (void *)name;
    }
    else
    {
        BSL_LOG_INFO("FAILED TO GET %s KEY FROM CRYPTO REG", name);
        return NULL;
    }
}

void test_add_key_concurrency(void)
{
    char names[TEST_THREADS][10];
    for (size_t i = 0; i < TEST_THREADS; i++)
    {
        sprintf(names[i], "thread%zu", i);
    }

    for (size_t i = 0; i < TEST_THREADS; i++)
    {
        if (pthread_create(threads + i, NULL, add_key_to_reg_fn, (void *)names[i]))
        {
            TEST_FAIL_MESSAGE("pthread_create() failed");
        }
    }

    for (size_t i = 0; i < TEST_THREADS; i++)
    {
        void *ret;
        if (pthread_join(threads[i], &ret))
        {
            TEST_FAIL_MESSAGE("pthread_join() failed");
        }
        TEST_ASSERT_NOT_NULL(ret);
    }

    for (size_t i = 0; i < TEST_THREADS; i++)
    {
        BSL_Crypto_KeyHandle_t handle;
        TEST_ASSERT_EQUAL(BSL_SUCCESS, BSL_Crypto_GetRegistryKeyName(names[i], &handle));
        BSL_Crypto_ReleaseKeyHandle(handle);
    }
}

void test_get_key_concurrency(void)
{
    char names[TEST_THREADS][10];
    for (size_t i = 0; i < TEST_THREADS; i++)
    {
        sprintf(names[i], "thread%zu", i);
    }

    static const uint8_t key_bytes[] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                                         0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF };
    for (size_t i = 0; i < TEST_THREADS; i++)
    {
        TEST_ASSERT_EQUAL(0, BSL_Crypto_AddRegistryKeyName(names[i], key_bytes, sizeof(key_bytes)));
    }

    for (size_t i = 0; i < TEST_THREADS; i++)
    {
        if (pthread_create(threads + i, NULL, get_key_from_reg_fn, (void *)names[i]))
        {
            TEST_FAIL_MESSAGE("pthread_create() failed");
        }
    }

    for (size_t i = 0; i < TEST_THREADS; i++)
    {
        void *ret;
        if (pthread_join(threads[i], &ret))
        {
            TEST_FAIL_MESSAGE("pthread_join() failed");
        }
        TEST_ASSERT_NOT_NULL(ret);
    }
}

void test_key_stats(void)
{
    BSL_Data_t key_id = BSL_DATA_INIT_VIEW_CSTR("testkeystats");

    BSL_Crypto_KeyHandle_t handle;
    BSL_Crypto_LoadKey(test_128, sizeof(test_128), &handle);
    TEST_ASSERT_NOT_NULL(handle);
    TEST_ASSERT_EQUAL_INT(0, BSL_Crypto_AddRegistryKey(&key_id, handle));

    test_encrypt("hello world!", "testkeystats");

    BSL_Crypto_KeyStats_t stats;
    BSL_Crypto_GetKeyStatistics(handle, &stats);
    TEST_ASSERT_EQUAL(1, stats.stats[BSL_CRYPTO_KEYSTATS_TIMES_USED]);
    TEST_ASSERT_EQUAL(14, stats.stats[BSL_CRYPTO_KEYSTATS_BYTES_PROCESSED]);

    test_encrypt("hello world again!", "testkeystats");

    BSL_Crypto_GetKeyStatistics(handle, &stats);
    TEST_ASSERT_EQUAL(2, stats.stats[BSL_CRYPTO_KEYSTATS_TIMES_USED]);
    TEST_ASSERT_EQUAL(34, stats.stats[BSL_CRYPTO_KEYSTATS_BYTES_PROCESSED]);

    BSL_Crypto_ReleaseKeyHandle(handle);
}
