/** @file
 * @ingroup unit_test
 * Test the OpenSSL EVP library behavior for BSL needs.
 */
#include "TestUtils.h"

#include <bsl/BPSecLib_Public.h>
#include <bsl/dynamic/MLibConfig.h>

#include <openssl/core_names.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/param_build.h>

#include <inttypes.h>
#include <unity.h>

#if !defined(OPENSSL_NO_ML_DSA)
#define OPENSSL_NO_ML_DSA (OPENSSL_VERSION_NUMBER < 0x30500000L)
#endif // OPENSSL_NO_ML_DSA

void test_ecdsa_load_sign(void)
{
    // Key from BPSec COSE example A.2
    static const char *key_x_hex =
        "02dfc49747f5d3d219fe6185744729fa1672ef7d11cb57ca0320c632be06ca3fdcc118e63140ba3ec57ea7b85d419568";
    static const char *key_y_hex =
        "4526e81bf0d9ea0924f05a3453ad75b92806671511544c993f6bd908a7a4239d476cfdfd74d6c68836488ad1e60b0e7d";
    static const char *key_d_hex =
        "3494803544d85a84d802400b50f51eea23b72d7d850b53cbf3006e5be2940d4a2c18d510a412efc7dc7875fbba22cca9";
    static const char *tbs_hex =
        "846a5369676e61747572653144a1013832584c8201662f2f7372632fa200012001890700028201692f2f6473742f7376638201692f2f73"
        "72632f7376638201662f2f7372632f821b000000bd51281400001a000f42404482a081c901010040466568656c6c6f";

    BSL_Data_t key_x = BSL_DATA_INIT_NULL;
    TEST_ASSERT_EQUAL_INT(0, BSL_TestUtils_DecodeBase16_cstr(&key_x, key_x_hex));
    BSL_Data_t key_y = BSL_DATA_INIT_NULL;
    TEST_ASSERT_EQUAL_INT(0, BSL_TestUtils_DecodeBase16_cstr(&key_y, key_y_hex));
    BSL_Data_t key_d = BSL_DATA_INIT_NULL;
    TEST_ASSERT_EQUAL_INT(0, BSL_TestUtils_DecodeBase16_cstr(&key_d, key_d_hex));
    BSL_Data_t tbs = BSL_DATA_INIT_NULL;
    TEST_ASSERT_EQUAL_INT(0, BSL_TestUtils_DecodeBase16_cstr(&tbs, tbs_hex));

    EVP_PKEY *key = NULL;
#if 1
    {
        OSSL_PARAM_BLD *param_bld = OSSL_PARAM_BLD_new();
        TEST_ASSERT_NOT_NULL(param_bld);
        TEST_ASSERT_EQUAL_INT(1, OSSL_PARAM_BLD_push_utf8_string(param_bld, OSSL_PKEY_PARAM_GROUP_NAME, "P-384", 0));

        // SEC1 point buffer 0x04 || X || Y
        BSL_Data_t pubdata;
        BSL_Data_InitBuffer(&pubdata, 1 + key_x.len + key_y.len);
        TEST_ASSERT_EQUAL_size_t(48, key_x.len);
        TEST_ASSERT_EQUAL_size_t(48, key_y.len);
        pubdata.ptr[0] = 0x04;
        memcpy(pubdata.ptr + 1, key_x.ptr, key_x.len);
        memcpy(pubdata.ptr + 1 + key_x.len, key_y.ptr, key_y.len);
        TEST_ASSERT_EQUAL_INT(
            1, OSSL_PARAM_BLD_push_octet_string(param_bld, OSSL_PKEY_PARAM_PUB_KEY, pubdata.ptr, pubdata.len));

        BIGNUM *key_d_bn = BN_bin2bn(key_d.ptr, (int)key_d.len, 0);
        TEST_ASSERT_EQUAL_INT(1, OSSL_PARAM_BLD_push_BN(param_bld, OSSL_PKEY_PARAM_PRIV_KEY, key_d_bn));

        OSSL_PARAM *params = OSSL_PARAM_BLD_to_param(param_bld);
        TEST_ASSERT_NOT_NULL(params);

        EVP_PKEY_CTX *keyctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
        TEST_ASSERT_NOT_NULL(keyctx);
        TEST_ASSERT_EQUAL_INT(1, EVP_PKEY_fromdata_init(keyctx));
        TEST_ASSERT_EQUAL_INT(1, EVP_PKEY_fromdata(keyctx, &key, EVP_PKEY_KEYPAIR, params));
        TEST_ASSERT_NOT_NULL(key);

        EVP_PKEY_CTX_free(keyctx);
        OSSL_PARAM_free(params);
        BN_free(key_d_bn);
        BSL_Data_Deinit(&pubdata);
        OSSL_PARAM_BLD_free(param_bld);
    }
#else
    EVP_PKEY *key = EVP_EC_gen("P-384");
#endif

    BSL_Data_t dersig = BSL_DATA_INIT_NULL;
    {
        EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
        TEST_ASSERT_NOT_NULL(mdctx);

        TEST_ASSERT_EQUAL_INT(1, EVP_DigestSignInit_ex(mdctx, NULL, SN_sha384, NULL, NULL, key, NULL));
        TEST_ASSERT_EQUAL_INT(1, EVP_DigestSignUpdate(mdctx, tbs.ptr, tbs.len));

        size_t dersig_len;
        TEST_ASSERT_EQUAL_INT(1, EVP_DigestSignFinal(mdctx, NULL, &dersig_len));
        TEST_ASSERT_GREATER_OR_EQUAL_size_t(96, dersig_len);

        BSL_Data_Resize(&dersig, dersig_len);
        TEST_ASSERT_NOT_NULL(dersig.ptr);
        int res = EVP_DigestSignFinal(mdctx, dersig.ptr, &dersig.len);
        ERR_print_errors_fp(stderr);
        TEST_ASSERT_EQUAL_INT(1, res);
        TEST_ASSERT_LESS_OR_EQUAL_size_t(dersig_len, dersig.len);

        EVP_MD_CTX_free(mdctx);
    }
    EVP_PKEY_free(key);

    BSL_Data_t catsig = BSL_DATA_INIT_NULL;
    {
        // internal structure conversion
        const uint8_t *offset    = dersig.ptr;
        ECDSA_SIG     *ecdsa_sig = d2i_ECDSA_SIG(NULL, &offset, (long)dersig.len);
        TEST_ASSERT_NOT_NULL(ecdsa_sig);

        const BIGNUM *r = NULL, *s = NULL;
        ECDSA_SIG_get0(ecdsa_sig, &r, &s);
        TEST_ASSERT_NOT_NULL(r);
        TEST_ASSERT_NOT_NULL(s);
        BSL_Data_Resize(&catsig, 96);
        BN_bn2binpad(r, catsig.ptr, 48);
        BN_bn2binpad(s, catsig.ptr + 48, 48);
        ECDSA_SIG_free(ecdsa_sig);
    }

    BSL_Data_Deinit(&catsig);
    BSL_Data_Deinit(&dersig);

    BSL_Data_Deinit(&tbs);
    BSL_Data_Deinit(&key_d);
    BSL_Data_Deinit(&key_y);
    BSL_Data_Deinit(&key_x);
}

void test_ecdsa_load_verify(void)
{
    // Key from BPSec COSE example A.2
    static const char *key_x_hex =
        "02dfc49747f5d3d219fe6185744729fa1672ef7d11cb57ca0320c632be06ca3fdcc118e63140ba3ec57ea7b85d419568";
    static const char *key_y_hex =
        "4526e81bf0d9ea0924f05a3453ad75b92806671511544c993f6bd908a7a4239d476cfdfd74d6c68836488ad1e60b0e7d";
    static const char *tbs_hex =
        "846a5369676e61747572653144a1013832584c8201662f2f7372632fa200012001890700028201692f2f6473742f7376638201692f2f73"
        "72632f7376638201662f2f7372632f821b000000bd51281400001a000f42404482a081c901010040466568656c6c6f";
    static const char *catsig_hex =
        "9c64328dfe9570262f5be687c35cc51ced48b8682d2a61d8baadfd3410233634251c2c1862b0a194b8503985931051a7"
        "7731a74a1514b83092d7c662e6dbcda2629af72b24bf1cc3c5e2552f54ddfcc1762e6bc46fd5e6c2137e4a695e563eae";
    static const char *dersig_hex =
        "3065"
        "0231009C64328DFE9570262F5BE687C35CC51CED48B8682D2A61D8BAADFD3410233634251C2C1862B0A194B8503985931051A7"
        "02307731A74A1514B83092D7C662E6DBCDA2629AF72B24BF1CC3C5E2552F54DDFCC1762E6BC46FD5E6C2137E4A695E563EAE";

    BSL_Data_t key_x = BSL_DATA_INIT_NULL;
    TEST_ASSERT_EQUAL_INT(0, BSL_TestUtils_DecodeBase16_cstr(&key_x, key_x_hex));
    BSL_Data_t key_y = BSL_DATA_INIT_NULL;
    TEST_ASSERT_EQUAL_INT(0, BSL_TestUtils_DecodeBase16_cstr(&key_y, key_y_hex));
    BSL_Data_t tbs = BSL_DATA_INIT_NULL;
    TEST_ASSERT_EQUAL_INT(0, BSL_TestUtils_DecodeBase16_cstr(&tbs, tbs_hex));
    BSL_Data_t catsig = BSL_DATA_INIT_NULL;
    TEST_ASSERT_EQUAL_INT(0, BSL_TestUtils_DecodeBase16_cstr(&catsig, catsig_hex));

    BSL_Data_t dersig = BSL_DATA_INIT_NULL;
    {
        // internal structure conversion
        ECDSA_SIG *ecdsa_sig = ECDSA_SIG_new();
        TEST_ASSERT_NOT_NULL(ecdsa_sig);

        BIGNUM *r = BN_bin2bn(catsig.ptr, 48, NULL);
        TEST_ASSERT_NOT_NULL(r);
        BIGNUM *s = BN_bin2bn(catsig.ptr + 48, 48, NULL);
        TEST_ASSERT_NOT_NULL(s);
        ECDSA_SIG_set0(ecdsa_sig, r, s);

        int derlen = i2d_ECDSA_SIG(ecdsa_sig, NULL);
        TEST_ASSERT_GREATER_THAN_INT(0, derlen);
        BSL_Data_Resize(&dersig, (size_t)derlen);

        uint8_t *offset = dersig.ptr;
        i2d_ECDSA_SIG(ecdsa_sig, &offset);

        ECDSA_SIG_free(ecdsa_sig);
    }
    TEST_ASSERT_TRUE(BSL_TestUtils_IsB16StrEqualTo(dersig_hex, dersig));

    EVP_PKEY *key = NULL;
    {
        OSSL_PARAM_BLD *param_bld = OSSL_PARAM_BLD_new();
        TEST_ASSERT_NOT_NULL(param_bld);
        TEST_ASSERT_EQUAL_INT(1, OSSL_PARAM_BLD_push_utf8_string(param_bld, OSSL_PKEY_PARAM_GROUP_NAME, "P-384", 0));

        // SEC1 point buffer 0x04 || X || Y
        BSL_Data_t pubdata;
        BSL_Data_InitBuffer(&pubdata, 1 + key_x.len + key_y.len);
        TEST_ASSERT_EQUAL_size_t(48, key_x.len);
        TEST_ASSERT_EQUAL_size_t(48, key_y.len);
        pubdata.ptr[0] = 0x04;
        memcpy(pubdata.ptr + 1, key_x.ptr, key_x.len);
        memcpy(pubdata.ptr + 1 + key_x.len, key_y.ptr, key_y.len);
        TEST_ASSERT_EQUAL_INT(
            1, OSSL_PARAM_BLD_push_octet_string(param_bld, OSSL_PKEY_PARAM_PUB_KEY, pubdata.ptr, pubdata.len));

        OSSL_PARAM *params = OSSL_PARAM_BLD_to_param(param_bld);
        TEST_ASSERT_NOT_NULL(params);

        EVP_PKEY_CTX *keyctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
        TEST_ASSERT_NOT_NULL(keyctx);
        TEST_ASSERT_EQUAL_INT(1, EVP_PKEY_fromdata_init(keyctx));
        TEST_ASSERT_EQUAL_INT(1, EVP_PKEY_fromdata(keyctx, &key, EVP_PKEY_KEYPAIR, params));
        TEST_ASSERT_NOT_NULL(key);

        EVP_PKEY_CTX_free(keyctx);
        OSSL_PARAM_free(params);
        BSL_Data_Deinit(&pubdata);
        OSSL_PARAM_BLD_free(param_bld);
    }

    {
        EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
        TEST_ASSERT_NOT_NULL(mdctx);

        TEST_ASSERT_EQUAL_INT(1, EVP_DigestVerifyInit_ex(mdctx, NULL, SN_sha384, NULL, NULL, key, NULL));
        TEST_ASSERT_EQUAL_INT(1, EVP_DigestVerifyUpdate(mdctx, tbs.ptr, tbs.len));
        int res = EVP_DigestVerifyFinal(mdctx, dersig.ptr, dersig.len);
        ERR_print_errors_fp(stderr);
        TEST_ASSERT_EQUAL_INT(1, res);

        EVP_MD_CTX_free(mdctx);
    }
    EVP_PKEY_free(key);

    BSL_Data_Deinit(&dersig);
    BSL_Data_Deinit(&catsig);
    BSL_Data_Deinit(&tbs);
    BSL_Data_Deinit(&key_y);
    BSL_Data_Deinit(&key_x);
}

void test_mldsa_load_sign(void)
{
#if OPENSSL_NO_ML_DSA
    TEST_IGNORE_MESSAGE("no ML-DSA");
#else
    EVP_PKEY_CTX *keyctx = EVP_PKEY_CTX_new_from_name(NULL, "ML-DSA-87", NULL);
    TEST_ASSERT_NOT_NULL(keyctx);
    int res = EVP_PKEY_keygen_init(keyctx);
    TEST_ASSERT_EQUAL_INT(0, res);

    EVP_PKEY_CTX_free(keyctx);
#endif // OPENSSL_NO_ML_DSA
}
