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
/** @file
 * 
 * @brief Specific low-level tests of the Default Security Context
 * 
 * Notes:
 *  - These tests use constructs defined in the BSL to exercise the Default Security Context
 *  - It uses test inputs and vectors from RFC9173 Appendix A.
 *  - It does NOT use any of the "Plumbing" inside the BSL.
 *  - It only directly calls the interfaces exposed by the Default Securit Context.
 *  - BCB internally is functionally complete, however it needs better integration with BPA to overwrite BTSD.
 * 
 * @ingroup unit-tests
 */
#include <stdlib.h>
#include <stdio.h>
#include <unity.h>

#include <BPSecLib.h>
#include <BPSecLib_MockBPA.h>
#include <backend/DeprecatedLibContext.h>
#include <security_context/DefaultSecContext.h>
#include <security_context/DefaultSecContext_Private.h>
#include <security_context/rfc9173.h>

#include "bsl_test_utils.h"

static BSL_TestContext_t LocalTestCtx;

void suiteSetUp(void)
{
    BSL_openlog();
    assert(0 == bsl_mock_bpa_init());
}

int suiteTearDown(int failures)
{
    bsl_mock_bpa_deinit();
    BSL_closelog();
    return failures;
}

void setUp(void)
{
    setenv("BSL_TEST_LOCAL_IPN_EID", "ipn:2.1", 1);
    memset(&LocalTestCtx, 0, sizeof(LocalTestCtx));
    TEST_ASSERT_EQUAL(0, BSL_LibCtx_Init(&LocalTestCtx.bsl));
    mock_bpa_ctr_init(&LocalTestCtx.mock_bpa_ctr);
    BSLTEST_SetupDefaultSecurityContext(&LocalTestCtx.bsl);
}

void tearDown(void)
{
    mock_bpa_ctr_deinit(&LocalTestCtx.mock_bpa_ctr);
    BSL_CryptoDeinit();
    TEST_ASSERT_EQUAL(0, BSL_LibCtx_Deinit(&LocalTestCtx.bsl));
}

/**
 * @brief Purpose: Exercise BIB applying security to a target payload block.
 *
 * Steps:
 *  - Get an unsecured bundle with a primary and payload block (From RFC9173)
 *  - Decode it into a BSL_BundleCtx struct
 *  - Create a BIB security operation with hard-coded arguments (From RFC9173 A1 ASB)
 *  - Run the DefaultSecuritContext's BSLX_ExecuteBIB function and confirm result is 0.
 *  - Capture the outcome from the above function to confirm 1 result (the authentication code)
 *  - Capture the auth code and ensure it matches the value in the test vector.
 * 
 * Notes:
 *  - Common repeated patterns are in the process of being factored out
 *  - All values are drawn from RFC9173 Appendix A.
 */
void test_DefaultSecuritContext_RFC9173_A1_BIB_Source(void)
{
    // This is the hex encoding of a simple bundle with no security.
    // Source: https://www.rfc-editor.org/rfc/rfc9173.html#appendix-A.1.1.3
    TEST_ASSERT_EQUAL(0, BSL_TestUtils_LoadBundleFromCBOR(&LocalTestCtx, RFC9173_TestVectors_AppendixA1.cbor_bundle_original));
    mock_bpa_ctr_t *mock_bpa_ctr = &LocalTestCtx.mock_bpa_ctr;

    BSL_SecOper_t bib_oper;
    BSL_SecOper_Init(&bib_oper, 
        RFC9173_TestVectors_AppendixA1.bib_asb_context_id,
        RFC9173_TestVectors_AppendixA1.bib_asb_sec_target, 
        RFC9173_TestVectors_AppendixA1.bib_asb_blk_num, 
        BSL_SECBLOCKTYPE_BIB, BSL_SECROLE_SOURCE);
    RFC9173_A1_Params bib_params = BSLTEST_GetRFC9173_A1Params(RFC9173_EXAMPLE_A1_KEY);
    BSL_SecOper_AppendParam(&bib_oper, &bib_params.sha_variant);
    BSL_SecOper_AppendParam(&bib_oper, &bib_params.scope_flags);
    BSL_SecOper_AppendParam(&bib_oper, &bib_params.test_key_id);

    BSL_SecOutcome_t sec_outcome;
    BSL_SecOutcome_Init(&sec_outcome, &bib_oper, 100000);

    TEST_ASSERT_EQUAL(0, BSLX_ExecuteBIB(&LocalTestCtx.bsl, mock_bpa_ctr->bundle, &bib_oper, &sec_outcome));

    TEST_ASSERT_EQUAL(1, BSL_SecOutcome_GetResultCount(&sec_outcome));
    const BSL_SecResult_t *bib_result = BSL_SecOutcome_GetResultAtIndex(&sec_outcome, 0);
    TEST_ASSERT_EQUAL(1, bib_result->context_id);
    TEST_ASSERT_EQUAL(1, bib_result->result_id);
    TEST_ASSERT_EQUAL(1, bib_result->target_block_num);
    TEST_ASSERT_EQUAL(true, BSLTEST_IsB16StrEqualTo(RFC9173_TestVectors_AppendixA1.cbor_hmac, BSL_SecResult_ResultAsData(bib_result)));

    BSL_SecOutcome_Deinit(&sec_outcome);
    BSL_SecOper_Deinit(&bib_oper);
}


/// @brief Purpose: Exercise BIB verifying a security block.
void test_DefaultSecuritContext_RFC9173_A1_BIB_Verifier(void)
{
}

/// @brief Purpose: Exercise BIB verifying a security block with cryptographic mismatch.
void test_DefaultSecuritContext_RFC9173_A1_BIB_Verifier_Failure(void)
{
}

/**
 * @brief Purpose: Exercise BCB applying security to a target payload block.
 *
 * Steps:
 *  - Get an unsecured bundle with a primary and payload block (From RFC9173)
 *  - Decode it into a BSL_BundleCtx struct
 *  - Create a BCB security operation with hard-coded arguments (From RFC9173 A2 ASB)
 *  - Run the DefaultSecuritContext's BSLX_ExecuteBCB function and confirm result is 0.
 *  - Capture the outcome from the above function to confirm 1 result (the auth tag) is present
 *  - Capture the auth tag and ensure it matches the value in the test vector.
 * 
 * Notes:
 *  - Incomplete since it does not modify the bundle BTSD (This still needs to be worked out)
 */
void test_DefaultSecuritContext_RFC9173_A2_BCB_Source(void)
{
    // Loads the bundle
    TEST_ASSERT_EQUAL(0, BSL_TestUtils_LoadBundleFromCBOR(&LocalTestCtx, RFC9173_TestVectors_AppendixA1.cbor_bundle_original));
    mock_bpa_ctr_t *mock_bpa_ctr = &LocalTestCtx.mock_bpa_ctr;

    // Begin hard coding the sec parameters and creating the sec operation.
    uint8_t        iv_buf[] = { 0x54, 0x77, 0x65, 0x6c, 0x76, 0x65, 0x31, 0x32, 0x31, 0x32, 0x31, 0x32 };
    BSL_Data_t     iv_data  = { .len = sizeof(iv_buf), .owned = 0, .ptr = iv_buf };
    BSL_SecParam_t param_iv;
    BSL_SecParam_InitBytestr(&param_iv, RFC9173_BCB_SECPARAM_IV, iv_data);

    BSL_SecParam_t param_aes_variant;
    BSL_SecParam_InitInt64(&param_aes_variant, RFC9173_BCB_SECPARAM_AESVARIANT, RFC9173_BCB_AES_VARIANT_A128GCM);

    uint8_t        wrapped_key_buf[] = { 0x69, 0xc4, 0x11, 0x27, 0x6f, 0xec, 0xdd, 0xc4, 0x78, 0x0d, 0xf4, 0x2c,
                                         0x8a, 0x2a, 0xf8, 0x92, 0x96, 0xfa, 0xbf, 0x34, 0xd7, 0xfa, 0xe7, 0x00 };
    BSL_Data_t     wrapped_key_data  = { .len = sizeof(wrapped_key_buf), .owned = 0, .ptr = wrapped_key_buf };
    BSL_SecParam_t param_wrapped_key;
    BSL_SecParam_InitBytestr(&param_wrapped_key, RFC9173_BCB_SECPARAM_WRAPPEDKEY, wrapped_key_data);

    BSL_SecParam_t param_scope_flags;
    BSL_SecParam_InitInt64(&param_scope_flags, RFC9173_BCB_SECPARAM_AADSCOPE, 0);

    BSL_SecParam_t param_test_key_id;
    BSL_SecParam_InitInt64(&param_test_key_id, BSL_SECPARAM_TYPE_INT_KEY_ID, RFC9173_EXAMPLE_A2_KEY);

    BSL_SecOper_t bcb_oper;
    BSL_SecOper_Init(&bcb_oper, 2, 1, 2, BSL_SECBLOCKTYPE_BCB, BSL_SECROLE_SOURCE);
    BSL_SecOper_AppendParam(&bcb_oper, &param_iv);
    BSL_SecOper_AppendParam(&bcb_oper, &param_aes_variant);
    BSL_SecOper_AppendParam(&bcb_oper, &param_wrapped_key);
    BSL_SecOper_AppendParam(&bcb_oper, &param_scope_flags);
    BSL_SecOper_AppendParam(&bcb_oper, &param_test_key_id);

    BSL_SecOutcome_t outcome;
    BSL_SecOutcome_Init(&outcome, &bcb_oper, 10000);

    // Execute BCB as source, confirm result is 0 (success)
    TEST_ASSERT_EQUAL(0, BSLX_ExecuteBCB(&LocalTestCtx.bsl, mock_bpa_ctr->bundle, &bcb_oper, &outcome));

    // The outcome should have one result (the auth tag)
    TEST_ASSERT_EQUAL(1, BSL_SecOutcome_GetResultCount(&outcome));
    const BSL_SecResult_t *auth_tag_result = BSL_SecOutcome_GetResultAtIndex(&outcome, 0);
    
    // Source: https://www.rfc-editor.org/rfc/rfc9173.html#appendix-A.2.3.2
    // See "payload auth tag"
    char *auth_tag_str = "efa4b5ac0108e3816c5606479801bc04";
    TEST_ASSERT_EQUAL(true, BSLTEST_IsB16StrEqualTo(auth_tag_str, BSL_SecResult_ResultAsData(auth_tag_result)));

    BSL_Data_t target_blk_tbsd;
    BSL_BundleContext_GetBlockMetadata(mock_bpa_ctr->bundle, 1, NULL, NULL, NULL, &target_blk_tbsd);

    BSL_LOG_DEBUG("Computed ciphertext:");
    char ct_c[target_blk_tbsd.len + 1];
    memcpy(ct_c, target_blk_tbsd.ptr, target_blk_tbsd.len);
    ct_c[target_blk_tbsd.len] = '\0';
    for (size_t i = 0; i < target_blk_tbsd.len; i++) {
        BSL_LOG_INFO("%02X", (unsigned char)ct_c[i]); // Prints each character as 2-digit uppercase hex, followed by a space
    }

    char * expected_ct = "3a09c1e63fe23a7f66a59c7303837241e070b02619fc59c5214a22f08cd70795e73e9a";
    TEST_ASSERT_EQUAL(true, BSLTEST_IsB16StrEqualTo(expected_ct, target_blk_tbsd));


    // TODO(bvb) Complete the BCB implementation to alter the BTSD in-place.
    // Source: https://www.rfc-editor.org/rfc/rfc9173.html#appendix-A.2.4
    char *encrypted_bundle_str = ("9f88070000820282010282028202018202820201820018281a000f4240850c0201"
                                 "0058508101020182028202018482014c5477656c7665313231323132820201820358"
                                 "1869c411276fecddc4780df42c8a2af89296fabf34d7fae7008204008181820150ef"
                                 "a4b5ac0108e3816c5606479801bc04850101000058233a09c1e63fe23a7f66a59c73"
                                 "03837241e070b02619fc59c5214a22f08cd70795e73e9aff");
    (void)encrypted_bundle_str;
    // TEST_ASSERT_EQUAL(0, mock_bpa_encode(mock_bpa_ctr));

    BSL_SecOutcome_Deinit(&outcome);
    BSL_SecOper_Deinit(&bcb_oper);
}

/// @brief Purpose: Exercises BCB as a security acceptor
void test_DefaultSecuritContext_RFC9173_A2_BCB_Acceptor(void)
{
    char *bundle_with_bcb =     ("9f88070000820282010282028202018202820201820018281a000f4240850c0201"
                                 "0058508101020182028202018482014c5477656c7665313231323132820201820358"
                                 "1869c411276fecddc4780df42c8a2af89296fabf34d7fae7008204008181820150ef"
                                 "a4b5ac0108e3816c5606479801bc04850101000058233a09c1e63fe23a7f66a59c73"
                                 "03837241e070b02619fc59c5214a22f08cd70795e73e9aff");

    // Loads the bundle
    TEST_ASSERT_EQUAL(0, BSL_TestUtils_LoadBundleFromCBOR(&LocalTestCtx, bundle_with_bcb));
    mock_bpa_ctr_t *mock_bpa_ctr = &LocalTestCtx.mock_bpa_ctr;

    // Begin hard coding the sec parameters and creating the sec operation.
    uint8_t        iv_buf[] = { 0x54, 0x77, 0x65, 0x6c, 0x76, 0x65, 0x31, 0x32, 0x31, 0x32, 0x31, 0x32 };
    BSL_Data_t     iv_data  = { .len = sizeof(iv_buf), .owned = 0, .ptr = iv_buf };
    BSL_SecParam_t param_iv;
    BSL_SecParam_InitBytestr(&param_iv, RFC9173_BCB_SECPARAM_IV, iv_data);

    BSL_SecParam_t param_aes_variant;
    BSL_SecParam_InitInt64(&param_aes_variant, RFC9173_BCB_SECPARAM_AESVARIANT, RFC9173_BCB_AES_VARIANT_A128GCM);

    uint8_t        wrapped_key_buf[] = { 0x69, 0xc4, 0x11, 0x27, 0x6f, 0xec, 0xdd, 0xc4, 0x78, 0x0d, 0xf4, 0x2c,
                                         0x8a, 0x2a, 0xf8, 0x92, 0x96, 0xfa, 0xbf, 0x34, 0xd7, 0xfa, 0xe7, 0x00 };
    BSL_Data_t     wrapped_key_data  = { .len = sizeof(wrapped_key_buf), .owned = 0, .ptr = wrapped_key_buf };
    BSL_SecParam_t param_wrapped_key;
    BSL_SecParam_InitBytestr(&param_wrapped_key, RFC9173_BCB_SECPARAM_WRAPPEDKEY, wrapped_key_data);

    BSL_SecParam_t param_scope_flags;
    BSL_SecParam_InitInt64(&param_scope_flags, RFC9173_BCB_SECPARAM_AADSCOPE, 0);

    BSL_SecParam_t param_test_key_id;
    BSL_SecParam_InitInt64(&param_test_key_id, BSL_SECPARAM_TYPE_INT_KEY_ID, RFC9173_EXAMPLE_A2_KEY);

    BSL_SecOper_t bcb_oper;
    BSL_SecOper_Init(&bcb_oper, 2, 1, 2, BSL_SECBLOCKTYPE_BCB, BSL_SECROLE_ACCEPTOR);
    BSL_SecOper_AppendParam(&bcb_oper, &param_iv);
    BSL_SecOper_AppendParam(&bcb_oper, &param_aes_variant);
    BSL_SecOper_AppendParam(&bcb_oper, &param_wrapped_key);
    BSL_SecOper_AppendParam(&bcb_oper, &param_scope_flags);
    BSL_SecOper_AppendParam(&bcb_oper, &param_test_key_id);

    BSL_SecOutcome_t outcome;
    BSL_SecOutcome_Init(&outcome, &bcb_oper, 10000);

    TEST_ASSERT_EQUAL(0, BSLX_ExecuteBCB(&LocalTestCtx.bsl, mock_bpa_ctr->bundle, &bcb_oper, &outcome));

    TEST_ASSERT_EQUAL(0, BSL_SecOutcome_GetResultCount(&outcome));

    BSL_Data_t target_blk_tbsd;
    BSL_BundleContext_GetBlockMetadata(mock_bpa_ctr->bundle, 1, NULL, NULL, NULL, &target_blk_tbsd);

    BSL_LOG_DEBUG("Computed PLAINTEXT:");
    char ct_c[target_blk_tbsd.len + 1];
    memcpy(ct_c, target_blk_tbsd.ptr, target_blk_tbsd.len);
    ct_c[target_blk_tbsd.len] = '\0';
    for (size_t i = 0; i < target_blk_tbsd.len; i++) {
        BSL_LOG_INFO("%02X", (unsigned char)ct_c[i]); // Prints each character as 2-digit uppercase hex, followed by a space
    }

    BSL_SecOutcome_Deinit(&outcome);
    BSL_SecOper_Deinit(&bcb_oper);

}

void test_ruhroh(void)
{

}

/// @brief Purpose: Exercises BCB as a security acceptor with cryptographic mismatch
void test_DefaultSecuritContext_RFC9173_A2_BCB_Acceptor_Failure(void)
{
    TEST_ASSERT_EQUAL(0, BSL_TestUtils_LoadBundleFromCBOR(&LocalTestCtx, RFC9173_TestVectors_AppendixA1.cbor_bundle_original));
    mock_bpa_ctr_t *mock_bpa_ctr = &LocalTestCtx.mock_bpa_ctr;
    BSL_BundleBlock_t *const *found = BSL_BundleBlockIdMap_cget(mock_bpa_ctr->bundle->blk_num, 1);
    if (!found)
    {
        BSL_LOG_INFO("sad");
    }
    else
    {
        BSL_LOG_INFO("NOT sad but %d", (*found)->blk_num);
    }

    // const size_t blk_list_len = BSL_BundleBlockList_size(mock_bpa_ctr->bundle->blks);
    // const BSL_BundleBlock_t *found;
    // BSL_BundleBlock_t *info = NULL;

    // size_t i;
    // for (i = 0; i < blk_list_len; i++)
    // {
    //     found = BSL_BundleBlockList_cget(mock_bpa_ctr->bundle->blks, i);
    //     if (found != NULL && (found->blk_num == 1))
    //     {
    //         info = (BSL_BundleBlock_t *) found;
    //         break;
    //     }
    // }

    // if (!info)
    // {
    //     BSL_LOG_INFO("sad ");
    // }
    // else
    // {
    //     BSL_LOG_INFO("NOT sad");
    // }
}
