/** @file
 * @ingroup unit_test
 * Test the OpenSSL EVP library behavior for BSL needs.
 */
#include "TestUtils.h"

#include <bsl/BPSecLib_Public.h>
#include <bsl/dynamic/MLibConfig.h>

#include <openssl/evp.h>
#include <openssl/core_names.h>

#include <inttypes.h>
#include <unity.h>

#if !defined(OPENSSL_NO_ML_DSA)
#define OPENSSL_NO_ML_DSA (OPENSSL_VERSION_NUMBER < 0x30500000L)
#endif // OPENSSL_NO_ML_DSA

void test_mldsa_load_sign(void)
{
#if OPENSSL_NO_ML_DSA
    TEST_IGNORE_MESSAGE("no ML-DSA");
#endif // OPENSSL_NO_ML_DSA
    EVP_PKEY_CTX *keyctx = EVP_PKEY_CTX_new_from_name(NULL, "ML-DSA-87", NULL);
    TEST_ASSERT_NOT_NULL(keyctx);
    int res = EVP_PKEY_keygen_init(keyctx);
    TEST_ASSERT_EQUAL_INT(0, res);

    EVP_PKEY_CTX_free(keyctx);
}
