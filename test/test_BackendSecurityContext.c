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
/** @file
 *
 * @brief Exercises the Security Context front-end interface.
 *
 * Notes:
 *  - These tests exercise the security context front-end interface.
 *  - They are mostly concerned with given bundles, blocks, and PolicyActionSets
 *  - They test correctness mostly by verifying that operations modify the bundle as intended
 *  - They are checked against test vectors in Appendex A of RFC9173.
 *
 * @ingroup unit-tests
 */
#include <stdlib.h>
#include <stdio.h>
#include <unity.h>

#include <BPSecLib_Private.h>
#include <BPSecLib_MockBPA.h>
#include <CryptoInterface.h>
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
    TEST_ASSERT_EQUAL(0, BSL_API_InitLib(&LocalTestCtx.bsl));
    mock_bpa_ctr_init(&LocalTestCtx.mock_bpa_ctr);
    BSL_TestUtils_SetupDefaultSecurityContext(&LocalTestCtx.bsl);
}

void tearDown(void)
{
    mock_bpa_ctr_deinit(&LocalTestCtx.mock_bpa_ctr);
    BSL_CryptoDeinit();
    TEST_ASSERT_EQUAL(0, BSL_API_DeinitLib(&LocalTestCtx.bsl));
}

/**
 * @brief Purpose: Creates a BIB block and adds it to the bundle, confirms it matches the test vector in RFC9173
 *
 * Steps:
 *  - Get an unsecured bundle with a primary and payload block (From RFC9173)
 *  - Create a BIB security operation with hard-coded arguments (From RFC9173 A1 ASB)
 *  - Use the high-level security context interface to apply the security operation
 *  - Confirm the bundle has the BIB block applied by comparing its encoding to expect in RFC9173.
 *
 * Notes:
 *  - Common repeated patterns are in the process of being factored out
 *  - All values are drawn from RFC9173 Appendix A.
 */
void ntest_SecurityContext_BIB_Source(void)
{
    TEST_ASSERT_EQUAL(
        0, BSL_TestUtils_LoadBundleFromCBOR(&LocalTestCtx, RFC9173_TestVectors_AppendixA1.cbor_bundle_original));
    mock_bpa_ctr_t *mock_bpa_ctr = &LocalTestCtx.mock_bpa_ctr;

    BIBTestContext bib_test_context;
    BSL_TestUtils_InitBIB_AppendixA1(&bib_test_context, BSL_SECROLE_SOURCE, RFC9173_EXAMPLE_A1_KEY);

    BSL_SecurityActionSet_t   *malloced_actionset   = BSL_TestUtils_InitMallocBIBActionSet(&bib_test_context);
    BSL_SecurityResponseSet_t *malloced_responseset = BSL_TestUtils_MallocEmptyPolicyResponse();

    TEST_ASSERT_EQUAL(0, BSL_SecCtx_ExecutePolicyActionSet(&LocalTestCtx.bsl, malloced_responseset,
                                                           &mock_bpa_ctr->bundle_ref, malloced_actionset));
    BSL_CanonicalBlock_t block;
    BSL_BundleCtx_GetBlockMetadata(&mock_bpa_ctr->bundle_ref, 2, &block);
    bool x = BSL_TestUtils_IsB16StrEqualTo(RFC9173_TestVectors_AppendixA1.cbor_bib_abs_sec_block,
                                           (BSL_Data_t) { .len = block.btsd_len, .ptr = block.btsd });
    TEST_ASSERT_TRUE(x);
    TEST_ASSERT_EQUAL(0, mock_bpa_encode(mock_bpa_ctr));
    bool is_expected =
        (BSL_TestUtils_IsB16StrEqualTo(RFC9173_TestVectors_AppendixA1.cbor_bundle_bib, mock_bpa_ctr->encoded));

    BSL_SecurityResponseSet_Deinit(malloced_responseset);
    BSL_SecurityActionSet_Deinit(malloced_actionset);
    free(malloced_responseset);
    free(malloced_actionset);

    TEST_ASSERT_TRUE(is_expected);
}

/**
 * @brief Purpose: Tests that running as role VERIFIER passes correctly when the cryptographic material matches.
 *
 * Steps:
 *  - Get a BIB secured bundle from RFC9173 Appendix A1.4.
 *  - Create a BIB-Verify security operation with hard-coded arguments (From RFC9173 A1 ASB)
 *  - Use the high-level security context interface to create a security outcome.
 *  - Confirm the bundle's BIB HMAC matches the outcome's HMAC.
 *
 * Notes:
 *  - Common repeated patterns are in the process of being factored out
 *  - All values are drawn from RFC9173 Appendix A.
 */
void test_SecurityContext_BIB_Verifier(void)
{
    TEST_ASSERT_EQUAL(0,
                      BSL_TestUtils_LoadBundleFromCBOR(&LocalTestCtx, RFC9173_TestVectors_AppendixA1.cbor_bundle_bib));
    mock_bpa_ctr_t *mock_bpa_ctr = &LocalTestCtx.mock_bpa_ctr;

    BIBTestContext bib_test_context;
    BSL_TestUtils_InitBIB_AppendixA1(&bib_test_context, BSL_SECROLE_VERIFIER, RFC9173_EXAMPLE_A1_KEY);

    BSL_SecurityActionSet_t   *malloced_actionset   = BSL_TestUtils_InitMallocBIBActionSet(&bib_test_context);
    BSL_SecurityResponseSet_t *malloced_responseset = BSL_TestUtils_MallocEmptyPolicyResponse();

    TEST_ASSERT_EQUAL(0, BSL_SecCtx_ExecutePolicyActionSet(&LocalTestCtx.bsl, malloced_responseset,
                                                           &mock_bpa_ctr->bundle_ref, malloced_actionset));
    TEST_ASSERT_EQUAL(0, mock_bpa_encode(mock_bpa_ctr));
    bool is_match =
        (BSL_TestUtils_IsB16StrEqualTo(RFC9173_TestVectors_AppendixA1.cbor_bundle_bib, mock_bpa_ctr->encoded));

    BSL_SecurityActionSet_Deinit(malloced_actionset);
    BSL_SecurityResponseSet_Deinit(malloced_responseset);
    free(malloced_actionset);
    free(malloced_responseset);

    TEST_ASSERT_TRUE(is_match);
}

/**
 * @brief Purpose: Test that a BIB verification operation does not pass when the cryptographic material does not match.
 *
 * Steps:
 *  - Get a BIB secured bundle from RFC9173 Appendix A1.4.
 *  - Create a BIB-Verify security operation with hard-coded arguments (From RFC9173 A1 ASB)
 *  - Manipulate the arguments so they use a different key
 *  - Use the high-level security context interface to create a security outcome.
 *  - Confirm that the execution failed (return code != 0)
 *
 * Notes:
 *  - Check more than return code, look deeper into outcome.
 */
void test_SecurityContext_BIB_Verifier_Failure(void)
{
    // TODO(bvb) Note that this is basically identical to above except different key, they should be consolidated
    TEST_ASSERT_EQUAL(0,
                      BSL_TestUtils_LoadBundleFromCBOR(&LocalTestCtx, RFC9173_TestVectors_AppendixA1.cbor_bundle_bib));
    mock_bpa_ctr_t *mock_bpa_ctr = &LocalTestCtx.mock_bpa_ctr;

    BIBTestContext bib_test_context;
    BSL_TestUtils_InitBIB_AppendixA1(&bib_test_context, BSL_SECROLE_VERIFIER, RFC9173_EXAMPLE_A2_KEY);

    // Note - switch to use the WRONG KEY
    bib_test_context.param_test_key._uint_value = RFC9173_EXAMPLE_A2_KEY;

    BSL_SecurityActionSet_t   *malloced_actionset   = BSL_TestUtils_InitMallocBIBActionSet(&bib_test_context);
    BSL_SecurityResponseSet_t *malloced_responseset = BSL_TestUtils_MallocEmptyPolicyResponse();

    TEST_ASSERT_NOT_EQUAL(BSL_SUCCESS,
                          BSL_SecCtx_ExecutePolicyActionSet(&LocalTestCtx.bsl, malloced_responseset,
                                                            &mock_bpa_ctr->bundle_ref, malloced_actionset));

    BSL_SecurityResponseSet_Deinit(malloced_responseset);
    BSL_SecurityActionSet_Deinit(malloced_actionset);
    free(malloced_actionset);
    free(malloced_responseset);
}

/**
 * @brief Tests that an acceptor will strip off the result and security block when the security operation validates
 * correctly.
 *
 * Steps:
 *  - Get a BIB secured bundle from RFC9173 Appendix A1.4.
 *  - Create a BIB-Acceptor security operation with hard-coded arguments (From RFC9173 A1 ASB)
 *  - Use the high-level security context interface to create a security outcome.
 *  - Confirm that the execution succeeds.
 *  - Check that the BIB result was removed from the bundle (by making sure the encoding matches bundle in A1.1)
 *
 */
void test_SecurityContext_BIB_Acceptor(void)
{
    TEST_ASSERT_EQUAL(0,
                      BSL_TestUtils_LoadBundleFromCBOR(&LocalTestCtx, RFC9173_TestVectors_AppendixA1.cbor_bundle_bib));
    mock_bpa_ctr_t *mock_bpa_ctr = &LocalTestCtx.mock_bpa_ctr;

    BIBTestContext bib_test_context;
    BSL_TestUtils_InitBIB_AppendixA1(&bib_test_context, BSL_SECROLE_ACCEPTOR, RFC9173_EXAMPLE_A1_KEY);

    BSL_SecurityActionSet_t   *malloced_actionset   = BSL_TestUtils_InitMallocBIBActionSet(&bib_test_context);
    BSL_SecurityResponseSet_t *malloced_responseset = BSL_TestUtils_MallocEmptyPolicyResponse();

    int  encode_result      = -1;
    bool is_equal_test_vec  = false;
    int  sec_context_result = BSL_SecCtx_ExecutePolicyActionSet(&LocalTestCtx.bsl, malloced_responseset,
                                                                &mock_bpa_ctr->bundle_ref, malloced_actionset);

    // Note, we use the goto statements to better cleanup if failure happens
    if (sec_context_result != 0)
        goto cleanup;

    encode_result = mock_bpa_encode(mock_bpa_ctr);
    if (encode_result != 0)
        goto cleanup;

    is_equal_test_vec =
        BSL_TestUtils_IsB16StrEqualTo(RFC9173_TestVectors_AppendixA1.cbor_bundle_original, mock_bpa_ctr->encoded);
    if (!is_equal_test_vec)
        goto cleanup;

cleanup:
    BSL_SecurityResponseSet_Deinit(malloced_responseset);
    BSL_SecurityActionSet_Deinit(malloced_actionset);
    free(malloced_actionset);
    free(malloced_responseset);

    TEST_ASSERT_EQUAL(0, sec_context_result);
    TEST_ASSERT_EQUAL(0, encode_result);
    TEST_ASSERT_TRUE(is_equal_test_vec);
}

// See RFC: https://www.rfc-editor.org/rfc/rfc9173.html#name-example-3-security-blocks-f
void test_RFC9173_AppendixA_Example3_Acceptor(void)
{
    const char *final_bundle = ("9f88070000820282010282028202018202820201820018281a000f4240850b0300"
                                "00585c8200020101820282030082820105820300828182015820cac6ce8e4c5dae57"
                                "988b757e49a6dd1431dc04763541b2845098265bc817241b81820158203ed614c0d9"
                                "7f49b3633627779aa18a338d212bf3c92b97759d9739cd50725596850c0401005834"
                                "8101020182028202018382014c5477656c7665313231323132820201820400818182"
                                "0150efa4b5ac0108e3816c5606479801bc0485070200004319012c85010100005823"
                                "3a09c1e63fe23a7f66a59c7303837241e070b02619fc59c5214a22f08cd70795e73e"
                                "9aff");
    TEST_ASSERT_EQUAL(0, BSL_TestUtils_LoadBundleFromCBOR(&LocalTestCtx, final_bundle));
    mock_bpa_ctr_t *mock_bpa_ctr = &LocalTestCtx.mock_bpa_ctr;

    BSL_PrimaryBlock_t primary_block = { 0 };
    BSL_BundleCtx_GetBundleMetadata(&mock_bpa_ctr->bundle_ref, &primary_block);
    TEST_ASSERT_EQUAL(4, primary_block.block_count);

    BSL_SecParam_t param_key = { 0 };
    BSL_SecParam_InitInt64(&param_key, BSL_SECPARAM_TYPE_INT_KEY_ID, RFC9173_EXAMPLE_A1_KEY);
    BSL_SecOper_t bib_oper_primary = { 0 };
    BSL_SecOper_Init(&bib_oper_primary, 1, 0, 3, BSL_SECBLOCKTYPE_BIB, BSL_SECROLE_ACCEPTOR,
                     BSL_POLICYACTION_DROP_BLOCK);
    BSL_SecOper_AppendParam(&bib_oper_primary, &param_key);
    BSL_SecOper_t bib_oper_ext_block = { 0 };
    BSL_SecOper_Init(&bib_oper_ext_block, 1, 2, 3, BSL_SECBLOCKTYPE_BIB, BSL_SECROLE_ACCEPTOR,
                     BSL_POLICYACTION_DROP_BLOCK);
    BSL_SecOper_AppendParam(&bib_oper_ext_block, &param_key);

    BSL_SecParam_t bcb_param_key = { 0 };
    BSL_SecParam_InitInt64(&bcb_param_key, BSL_SECPARAM_TYPE_INT_KEY_ID, RFC9173_EXAMPLE_A3_KEY);
    BSL_SecOper_t bcb_oper = { 0 };
    BSL_SecOper_Init(&bcb_oper, 2, 1, 4, BSL_SECBLOCKTYPE_BCB, BSL_SECROLE_ACCEPTOR, BSL_POLICYACTION_DROP_BLOCK);
    BSL_SecOper_AppendParam(&bcb_oper, &bcb_param_key);

    BSL_SecurityActionSet_t *malloced_actionset = calloc(1, BSL_SecurityActionSet_Sizeof());
    BSL_SecurityActionSet_Init(malloced_actionset);
    BSL_SecurityActionSet_AppendSecOper(malloced_actionset, &bib_oper_primary);
    BSL_SecurityActionSet_AppendSecOper(malloced_actionset, &bib_oper_ext_block);
    BSL_SecurityActionSet_AppendSecOper(malloced_actionset, &bcb_oper);

    BSL_SecurityResponseSet_t *malloced_responseset = BSL_TestUtils_MallocEmptyPolicyResponse();

    const int exec_result = BSL_SecCtx_ExecutePolicyActionSet(&LocalTestCtx.bsl, malloced_responseset,
                                                              &mock_bpa_ctr->bundle_ref, malloced_actionset);
    TEST_ASSERT_EQUAL(BSL_SUCCESS, exec_result);

    BSL_SecurityResponseSet_Deinit(malloced_responseset);
    BSL_SecurityActionSet_Deinit(malloced_actionset);

    free(malloced_actionset);
    free(malloced_responseset);
}

void test_RFC9173_AppendixA_Example3_Source(void)
{
    // See: https://www.rfc-editor.org/rfc/rfc9173.html#appendix-A.3.1
    const char *plain_bundle = ("9f88070000820282010282028202018202820201820018281a000f424085070200"
                                "004319012c85010100005823526561647920746f2067656e65726174652061203332"
                                "2d62797465207061796c6f6164ff");
    TEST_ASSERT_EQUAL(0, BSL_TestUtils_LoadBundleFromCBOR(&LocalTestCtx, plain_bundle));
    mock_bpa_ctr_t *mock_bpa_ctr = &LocalTestCtx.mock_bpa_ctr;

    // Confirm the bundle has two canonical blocks, the payload and bundle age block
    BSL_PrimaryBlock_t primary_block = { 0 };
    BSL_BundleCtx_GetBundleMetadata(&mock_bpa_ctr->bundle_ref, &primary_block);
    TEST_ASSERT_EQUAL(2, primary_block.block_count);

    BSL_SecParam_t param_key = { 0 };
    BSL_SecParam_InitInt64(&param_key, BSL_SECPARAM_TYPE_INT_KEY_ID, RFC9173_EXAMPLE_A1_KEY);

    BSL_SecParam_t param_sha_var = { 0 };
    BSL_SecParam_InitInt64(&param_sha_var, RFC9173_BIB_PARAMID_SHA_VARIANT, RFC9173_BIB_SHA_HMAC256);

    BSL_SecParam_t param_integ_scope = { 0 };
    BSL_SecParam_InitInt64(&param_integ_scope, RFC9173_BIB_PARAMID_INTEG_SCOPE_FLAG, 0);

    BSL_SecOper_t bib_oper_primary = { 0 };
    BSL_SecOper_Init(&bib_oper_primary, 1, 0, 3, BSL_SECBLOCKTYPE_BIB, BSL_SECROLE_SOURCE, BSL_POLICYACTION_DROP_BLOCK);
    BSL_SecOper_AppendParam(&bib_oper_primary, &param_key);
    BSL_SecOper_AppendParam(&bib_oper_primary, &param_sha_var);
    BSL_SecOper_AppendParam(&bib_oper_primary, &param_integ_scope);

    BSL_SecOper_t bib_oper_ext_block = { 0 };
    BSL_SecOper_Init(&bib_oper_ext_block, 1, 2, 3, BSL_SECBLOCKTYPE_BIB, BSL_SECROLE_SOURCE,
                     BSL_POLICYACTION_DROP_BLOCK);
    BSL_SecOper_AppendParam(&bib_oper_ext_block, &param_key);
    BSL_SecOper_AppendParam(&bib_oper_ext_block, &param_sha_var);
    BSL_SecOper_AppendParam(&bib_oper_ext_block, &param_integ_scope);

    BSL_SecParam_t bcb_param_key = { 0 };
    BSL_SecParam_InitInt64(&bcb_param_key, BSL_SECPARAM_TYPE_INT_KEY_ID, RFC9173_EXAMPLE_A3_KEY);

    BSL_SecParam_t bcb_scope = { 0 };
    BSL_SecParam_InitInt64(&bcb_scope, RFC9173_BCB_SECPARAM_AADSCOPE, 0);

    BSL_SecParam_t aes_variant = { 0 };
    BSL_SecParam_InitInt64(&aes_variant, RFC9173_BCB_SECPARAM_AESVARIANT, 1);

    BSL_SecOper_t bcb_oper = { 0 };
    BSL_SecOper_Init(&bcb_oper, 2, 1, 4, BSL_SECBLOCKTYPE_BCB, BSL_SECROLE_SOURCE, BSL_POLICYACTION_DROP_BLOCK);
    BSL_SecOper_AppendParam(&bcb_oper, &bcb_param_key);
    BSL_SecOper_AppendParam(&bcb_oper, &bcb_scope);
    BSL_SecOper_AppendParam(&bcb_oper, &aes_variant);

    BSL_SecurityActionSet_t *malloced_actionset = calloc(1, BSL_SecurityActionSet_Sizeof());
    BSL_SecurityActionSet_Init(malloced_actionset);
    BSL_SecurityActionSet_AppendSecOper(malloced_actionset, &bib_oper_primary);
    BSL_SecurityActionSet_AppendSecOper(malloced_actionset, &bib_oper_ext_block);
    BSL_SecurityActionSet_AppendSecOper(malloced_actionset, &bcb_oper);

    BSL_SecurityResponseSet_t *malloced_responseset = BSL_TestUtils_MallocEmptyPolicyResponse();

    const int exec_result = BSL_SecCtx_ExecutePolicyActionSet(&LocalTestCtx.bsl, malloced_responseset,
                                                              &mock_bpa_ctr->bundle_ref, malloced_actionset);
    TEST_ASSERT_EQUAL(BSL_SUCCESS, exec_result);

    // Should have created a new security block
    BSL_BundleCtx_GetBundleMetadata(&mock_bpa_ctr->bundle_ref, &primary_block);
    TEST_ASSERT_TRUE(primary_block.block_count >= 4);
    TEST_ASSERT_TRUE(primary_block.block_count <= 5);

    const size_t response_count = BSL_SecurityResponseSet_CountResponses(malloced_responseset);
    TEST_ASSERT_EQUAL(3, response_count);

    BSL_SecurityResponseSet_Deinit(malloced_responseset);
    BSL_SecurityActionSet_Deinit(malloced_actionset);

    free(malloced_actionset);
    free(malloced_responseset);
}

void test_RFC9173_AppendixA_Example4_Acceptor(void)
{
    // See: https://www.rfc-editor.org/rfc/rfc9173.html#appendix-A.4.5
    const char *final_bundle = ("9f88070000820282010282028202018202820201820018281a000f4240850b0300"
                                "005846438ed6208eb1c1ffb94d952175167df0902902064a2983910c4fb2340790bf"
                                "420a7d1921d5bf7c4721e02ab87a93ab1e0b75cf62e4948727c8b5dae46ed2af0543"
                                "9b88029191850c0201005849820301020182028202018382014c5477656c76653132"
                                "313231328202038204078281820150220ffc45c8a901999ecc60991dd78b29818201"
                                "50d2c51cb2481792dae8b21d848cede99b8501010000582390eab6457593379298a8"
                                "724e16e61f837488e127212b59ac91f8a86287b7d07630a122ff");
    TEST_ASSERT_EQUAL(0, BSL_TestUtils_LoadBundleFromCBOR(&LocalTestCtx, final_bundle));
    mock_bpa_ctr_t *mock_bpa_ctr = &LocalTestCtx.mock_bpa_ctr;

    // Confirm the bundle has 3 canonical blocks: payload, BIB, and BCB
    BSL_PrimaryBlock_t primary_block = { 0 };
    BSL_BundleCtx_GetBundleMetadata(&mock_bpa_ctr->bundle_ref, &primary_block);
    TEST_ASSERT_EQUAL(3, primary_block.block_count);

    BSL_CanonicalBlock_t bcb_block = { 0 };
    BSL_BundleCtx_GetBlockMetadata(&mock_bpa_ctr->bundle_ref, 2, &bcb_block);
    TEST_ASSERT_EQUAL(12, bcb_block.type_code);
    TEST_ASSERT_EQUAL(2, bcb_block.block_num);
    TEST_ASSERT_EQUAL(1, bcb_block.flags);

    // FIRST we must decrypt the BCB targets.
    BSL_SecParam_t bcb_param_key = { 0 };
    BSL_SecParam_InitInt64(&bcb_param_key, BSL_SECPARAM_TYPE_INT_KEY_ID, RFC9173_EXAMPLE_A4_BCB_KEY);
    BSL_SecParam_t bcb_scope = { 0 };
    BSL_SecParam_InitInt64(&bcb_scope, RFC9173_BCB_SECPARAM_AADSCOPE, 0x07);
    BSL_SecParam_t aes_variant = { 0 };
    BSL_SecParam_InitInt64(&aes_variant, RFC9173_BCB_SECPARAM_AESVARIANT, RFC9173_BCB_AES_VARIANT_A256GCM);

    BSL_SecOper_t bcb_op_tgt_payload = { 0 };
    BSL_SecOper_Init(&bcb_op_tgt_payload, 2, 1, 2, BSL_SECBLOCKTYPE_BCB, BSL_SECROLE_ACCEPTOR,
                     BSL_POLICYACTION_DROP_BLOCK);
    BSL_SecOper_AppendParam(&bcb_op_tgt_payload, &bcb_param_key);
    BSL_SecOper_AppendParam(&bcb_op_tgt_payload, &aes_variant);
    BSL_SecOper_AppendParam(&bcb_op_tgt_payload, &bcb_scope);

    BSL_SecOper_t bcb_op_tgt_bib = { 0 };
    BSL_SecOper_Init(&bcb_op_tgt_bib, 2, 3, 2, BSL_SECBLOCKTYPE_BCB, BSL_SECROLE_ACCEPTOR, BSL_POLICYACTION_DROP_BLOCK);
    BSL_SecOper_AppendParam(&bcb_op_tgt_bib, &bcb_param_key);
    BSL_SecOper_AppendParam(&bcb_op_tgt_bib, &aes_variant);
    BSL_SecOper_AppendParam(&bcb_op_tgt_bib, &bcb_scope);

    BSL_SecParam_t param_key = { 0 };
    BSL_SecParam_InitInt64(&param_key, BSL_SECPARAM_TYPE_INT_KEY_ID, RFC9173_EXAMPLE_A1_KEY);
    BSL_SecParam_t sha_variant = { 0 };
    BSL_SecParam_InitInt64(&sha_variant, RFC9173_BIB_PARAMID_SHA_VARIANT, RFC9173_BIB_SHA_HMAC384);
    BSL_SecParam_t scope_flag = { 0 };
    BSL_SecParam_InitInt64(&scope_flag, RFC9173_BIB_PARAMID_INTEG_SCOPE_FLAG, 0x07);

    BSL_SecOper_t bib_oper_payload = { 0 };
    BSL_SecOper_Init(&bib_oper_payload, 1, 1, 3, BSL_SECBLOCKTYPE_BIB, BSL_SECROLE_ACCEPTOR,
                     BSL_POLICYACTION_DROP_BLOCK);
    BSL_SecOper_AppendParam(&bib_oper_payload, &param_key);
    BSL_SecOper_AppendParam(&bib_oper_payload, &sha_variant);
    BSL_SecOper_AppendParam(&bib_oper_payload, &scope_flag);

    BSL_SecurityActionSet_t *malloced_actionset = calloc(1, BSL_SecurityActionSet_Sizeof());
    BSL_SecurityActionSet_Init(malloced_actionset);
    BSL_SecurityActionSet_AppendSecOper(malloced_actionset, &bcb_op_tgt_payload);
    BSL_SecurityActionSet_AppendSecOper(malloced_actionset, &bcb_op_tgt_bib);
    BSL_SecurityActionSet_AppendSecOper(malloced_actionset, &bib_oper_payload);

    BSL_SecurityResponseSet_t *malloced_responseset = BSL_TestUtils_MallocEmptyPolicyResponse();

    const int exec_result = BSL_SecCtx_ExecutePolicyActionSet(&LocalTestCtx.bsl, malloced_responseset,
                                                              &mock_bpa_ctr->bundle_ref, malloced_actionset);
    TEST_ASSERT_EQUAL(BSL_SUCCESS, exec_result);

    // After all the security results have been stripped, this is the bundle's result.
    // See: https://www.rfc-editor.org/rfc/rfc9173.html#appendix-A.4.1
    const char *expected_processed_bundle = ("9f88070000820282010282028202018202820201820018281a000f424085010100"
                                             "005823526561647920746f2067656e657261746520612033322d6279746520706179"
                                             "6c6f6164ff");
    TEST_ASSERT_EQUAL(0, mock_bpa_encode(mock_bpa_ctr));
    TEST_ASSERT_TRUE(BSL_TestUtils_IsB16StrEqualTo(expected_processed_bundle, mock_bpa_ctr->encoded));

    BSL_SecurityResponseSet_Deinit(malloced_responseset);
    BSL_SecurityActionSet_Deinit(malloced_actionset);

    free(malloced_actionset);
    free(malloced_responseset);
}

void test_RFC9173_AppendixA_Example4_Source(void)
{
    const char *original_bundle = ("9f88070000820282010282028202018202820201820018281a000f424085010100"
                                   "005823526561647920746f2067656e657261746520612033322d6279746520706179"
                                   "6c6f6164ff");
    TEST_ASSERT_EQUAL(0, BSL_TestUtils_LoadBundleFromCBOR(&LocalTestCtx, original_bundle));
    mock_bpa_ctr_t *mock_bpa_ctr = &LocalTestCtx.mock_bpa_ctr;

    BSL_PrimaryBlock_t primary_block = { 0 };
    BSL_BundleCtx_GetBundleMetadata(&mock_bpa_ctr->bundle_ref, &primary_block);
    TEST_ASSERT_EQUAL(1, primary_block.block_count);

    BSL_SecParam_t param_key = { 0 };
    BSL_SecParam_InitInt64(&param_key, BSL_SECPARAM_TYPE_INT_KEY_ID, RFC9173_EXAMPLE_A1_KEY);
    BSL_SecParam_t sha_variant = { 0 };
    BSL_SecParam_InitInt64(&sha_variant, RFC9173_BIB_PARAMID_SHA_VARIANT, RFC9173_BIB_SHA_HMAC384);
    BSL_SecParam_t scope_flag = { 0 };
    BSL_SecParam_InitInt64(&scope_flag, RFC9173_BIB_PARAMID_INTEG_SCOPE_FLAG, 0x07);

    BSL_SecOper_t bib_oper_payload = { 0 };
    BSL_SecOper_Init(&bib_oper_payload, 1, 1, 2, BSL_SECBLOCKTYPE_BIB, BSL_SECROLE_SOURCE, BSL_POLICYACTION_DROP_BLOCK);
    BSL_SecOper_AppendParam(&bib_oper_payload, &param_key);
    BSL_SecOper_AppendParam(&bib_oper_payload, &sha_variant);
    BSL_SecOper_AppendParam(&bib_oper_payload, &scope_flag);

    BSL_SecParam_t bcb_param_key = { 0 };
    BSL_SecParam_InitInt64(&bcb_param_key, BSL_SECPARAM_TYPE_INT_KEY_ID, RFC9173_EXAMPLE_A4_BCB_KEY);
    BSL_SecParam_t bcb_scope = { 0 };
    BSL_SecParam_InitInt64(&bcb_scope, RFC9173_BCB_SECPARAM_AADSCOPE, 0x07);
    BSL_SecParam_t aes_variant = { 0 };
    BSL_SecParam_InitInt64(&aes_variant, RFC9173_BCB_SECPARAM_AESVARIANT, RFC9173_BCB_AES_VARIANT_A256GCM);
    uint8_t        iv[]     = { 0x54, 0x77, 0x65, 0x6c, 0x76, 0x65, 0x31, 0x32, 0x31, 0x32, 0x31, 0x32 };
    BSL_Data_t     iv_data  = { .len = sizeof(iv), .ptr = iv };
    BSL_SecParam_t init_vec = { 0 };
    BSL_SecParam_InitBytestr(&init_vec, BSL_SECPARAM_TYPE_IV, iv_data);

    BSL_SecOper_t bcb_op_tgt_payload = { 0 };
    BSL_SecOper_Init(&bcb_op_tgt_payload, 2, 1, 3, BSL_SECBLOCKTYPE_BCB, BSL_SECROLE_SOURCE,
                     BSL_POLICYACTION_DROP_BLOCK);
    BSL_SecOper_AppendParam(&bcb_op_tgt_payload, &bcb_param_key);
    BSL_SecOper_AppendParam(&bcb_op_tgt_payload, &aes_variant);
    BSL_SecOper_AppendParam(&bcb_op_tgt_payload, &bcb_scope);
    BSL_SecOper_AppendParam(&bcb_op_tgt_payload, &init_vec);

    BSL_SecOper_t bcb_op_tgt_bib = { 0 };
    BSL_SecOper_Init(&bcb_op_tgt_bib, 2, 2, 3, BSL_SECBLOCKTYPE_BCB, BSL_SECROLE_SOURCE, BSL_POLICYACTION_DROP_BLOCK);
    BSL_SecOper_AppendParam(&bcb_op_tgt_bib, &bcb_param_key);
    BSL_SecOper_AppendParam(&bcb_op_tgt_bib, &aes_variant);
    BSL_SecOper_AppendParam(&bcb_op_tgt_bib, &bcb_scope);
    BSL_SecOper_AppendParam(&bcb_op_tgt_bib, &init_vec);

    BSL_SecurityActionSet_t *malloced_actionset = calloc(1, BSL_SecurityActionSet_Sizeof());
    BSL_SecurityActionSet_Init(malloced_actionset);
    BSL_SecurityActionSet_AppendSecOper(malloced_actionset, &bcb_op_tgt_payload);
    BSL_SecurityActionSet_AppendSecOper(malloced_actionset, &bcb_op_tgt_bib);
    BSL_SecurityActionSet_AppendSecOper(malloced_actionset, &bib_oper_payload);

    BSL_SecurityResponseSet_t *malloced_responseset = BSL_TestUtils_MallocEmptyPolicyResponse();

    const int exec_result = BSL_SecCtx_ExecutePolicyActionSet(&LocalTestCtx.bsl, malloced_responseset,
                                                              &mock_bpa_ctr->bundle_ref, malloced_actionset);
    TEST_ASSERT_EQUAL(BSL_SUCCESS, exec_result);

    BSL_PrimaryBlock_t prim_blk;
    BSL_BundleCtx_GetBundleMetadata(&mock_bpa_ctr->bundle_ref, &prim_blk);
    TEST_ASSERT_TRUE(prim_blk.block_count >= 3 && prim_blk.block_count <= 4);

    BSL_SecurityResponseSet_Deinit(malloced_responseset);
    BSL_SecurityActionSet_Deinit(malloced_actionset);

    free(malloced_actionset);
    free(malloced_responseset);
}
