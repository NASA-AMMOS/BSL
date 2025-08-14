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
 * @brief Specific low-level tests of the Default Security Context
 *
 * Notes:
 *  - These tests use constructs defined in the BSL to exercise the Default Security Context
 *  - It uses test inputs and vectors from RFC9173 Appendix A.
 *  - It does NOT use any of the "Plumbing" inside the BSL.
 *  - It only directly calls the interfaces exposed by the Default Security Context.
 *  - BCB internally is functionally complete, however it needs better integration with BPA to overwrite BTSD.
 *
 * @ingroup unit-tests
 */
#include <stdlib.h>
#include <stdio.h>
#include <unity.h>

#include <BPSecLib_Private.h>
#include <mock_bpa/MockBPA.h>
#include <CryptoInterface.h>

#include <backend/PublicInterfaceImpl.h>
#include <security_context/DefaultSecContext.h>
#include <security_context/DefaultSecContext_Private.h>
#include <security_context/rfc9173.h>

#include "bsl_test_utils.h"

static BSL_TestContext_t LocalTestCtx;

void suiteSetUp(void)
{
    BSL_openlog();
    assert(0 == bsl_mock_bpa_agent_init());
}

int suiteTearDown(int failures)
{
    bsl_mock_bpa_agent_deinit();
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
 * @brief Purpose: Exercise BIB applying security to a target payload block.
 *
 * Steps:
 *  - Get an unsecured bundle with a primary and payload block (From RFC9173)
 *  - Decode it into a BSL_BundleCtx struct
 *  - Create a BIB security operation with hard-coded arguments (From RFC9173 A1 ASB)
 *  - Run the DefaultSecuritContext's BSLX_BIB_Execute function and confirm result is 0.
 *  - Capture the outcome from the above function to confirm 1 result (the authentication code)
 *  - Capture the auth code and ensure it matches the value in the test vector.
 *
 * Notes:
 *  - Common repeated patterns are in the process of being factored out
 *  - All values are drawn from RFC9173 Appendix A.
 */
void test_RFC9173_AppendixA_Example1_BIB_Source(void)
{
    BSL_Crypto_SetRngGenerator(rfc9173_byte_gen_fn_a1);

    TEST_ASSERT_EQUAL(
        0, BSL_TestUtils_LoadBundleFromCBOR(&LocalTestCtx, RFC9173_TestVectors_AppendixA1.cbor_bundle_original));
    mock_bpa_ctr_t *mock_bpa_ctr = &LocalTestCtx.mock_bpa_ctr;

    BIBTestContext bib_test_context;
    BSL_TestUtils_InitBIB_AppendixA1(&bib_test_context, BSL_SECROLE_SOURCE, RFC9173_EXAMPLE_A1_KEY);

    BSL_SecOutcome_t *sec_outcome = BSL_CALLOC(BSL_SecOutcome_Sizeof(), 1);
    BSL_SecOutcome_Init(sec_outcome, &bib_test_context.sec_oper, 100000);

    /// Confirm running BIB as source executes without error
    int bib_exec_status =
        BSLX_BIB_Execute(&LocalTestCtx.bsl, &mock_bpa_ctr->bundle_ref, &bib_test_context.sec_oper, sec_outcome);
    TEST_ASSERT_EQUAL(BSL_SUCCESS, bib_exec_status);

    /// Confirm it produced only 1 result
    TEST_ASSERT_EQUAL(1, BSL_SecOutcome_CountResults(sec_outcome));
    const BSL_SecResult_t *bib_result = BSL_SecOutcome_GetResultAtIndex(sec_outcome, 0);

    /// Confirm the context and result result is the right ID (Defined in RFC)
    TEST_ASSERT_EQUAL(RFC9173_CONTEXTID_BIB_HMAC_SHA2, bib_result->context_id);
    TEST_ASSERT_EQUAL(RFC9173_BIB_RESULTID_HMAC, bib_result->result_id);
    TEST_ASSERT_EQUAL(1, bib_result->target_block_num);

    /// Confirm the actual HMAC signature matches what is in the RFC
    TEST_ASSERT_EQUAL(sizeof(ApxA1_HMAC), bib_result->_bytelen);
    TEST_ASSERT_TRUE(memcmp(ApxA1_HMAC, bib_result->_bytes, sizeof(ApxA1_HMAC)) == 0);

    BSL_SecOutcome_Deinit(sec_outcome);
    BSL_SecOper_Deinit(&bib_test_context.sec_oper);
    BSL_FREE(sec_outcome);
}

// /// @brief Purpose: Exercise BIB verifying a security block.
// void test_DefaultSecuritContext_RFC9173_A1_BIB_Verifier(void) {}

// /// @brief Purpose: Exercise BIB verifying a security block with cryptographic mismatch.
// void test_DefaultSecuritContext_RFC9173_A1_BIB_Verifier_Failure(void) {}

/**
 * @brief Purpose: Exercise BCB applying security to a target payload block.
 *
 * Steps:
 *  - Get an unsecured bundle with a primary and payload block (From RFC9173)
 *  - Decode it into a BSL_BundleCtx struct
 *  - Create a BCB security operation with hard-coded arguments (From RFC9173 A2 ASB)
 *  - Run the DefaultSecuritContext's BSLX_BCB_Execute function and confirm result is 0.
 *  - Capture the outcome from the above function to confirm 1 result (the auth tag) is present
 *  - Capture the auth tag and ensure it matches the value in the test vector.
 *
 * Notes:
 *  - Incomplete since it does not modify the bundle BTSD (This still needs to be worked out)
 */
void test_RFC9173_AppendixA_Example2_BCB_Source(void)
{
    BSL_Crypto_SetRngGenerator(rfc9173_byte_gen_fn_a2_cek);
    // Loads the bundle
    TEST_ASSERT_EQUAL(
        0, BSL_TestUtils_LoadBundleFromCBOR(&LocalTestCtx, RFC9173_TestVectors_AppendixA1.cbor_bundle_original));
    mock_bpa_ctr_t *mock_bpa_ctr = &LocalTestCtx.mock_bpa_ctr;

    BCBTestContext bcb_test_context;
    BSL_TestUtils_InitBCB_Appendix2(&bcb_test_context, BSL_SECROLE_SOURCE);

    BSL_SecOutcome_t *outcome = BSL_CALLOC(BSL_SecOutcome_Sizeof(), 1);
    BSL_SecOutcome_Init(outcome, &bcb_test_context.sec_oper, 10000);

    // Execute BCB as source, confirm result is 0 (success)
    int bcb_exec_result =
        BSLX_BCB_Execute(&LocalTestCtx.bsl, &mock_bpa_ctr->bundle_ref, &bcb_test_context.sec_oper, outcome);
    TEST_ASSERT_EQUAL(BSL_SUCCESS, bcb_exec_result);

    // Confirm the output produces one result (the AES-GCM auth code)
    TEST_ASSERT_EQUAL(1, BSL_SecOutcome_CountResults(outcome));
    const BSL_SecResult_t *auth_tag_result = BSL_SecOutcome_GetResultAtIndex(outcome, 0);

    // Confirm that AUTHTAG result id is there
    TEST_ASSERT_EQUAL(RFC9173_BCB_RESULTID_AUTHTAG, auth_tag_result->result_id);

    // Confirm expected vs actual auth tag byte length's match and they are equal
    TEST_ASSERT_EQUAL(sizeof(ApxA2_AuthTag), auth_tag_result->_bytelen);
    TEST_ASSERT_EQUAL_MEMORY(ApxA2_AuthTag, auth_tag_result->_bytes, sizeof(ApxA2_AuthTag));

    BSL_CanonicalBlock_t target_block;
    BSL_BundleCtx_GetBlockMetadata(&mock_bpa_ctr->bundle_ref, 1, &target_block);
    uint8_t logstr[500];
    BSL_LOG_INFO("EXPECTED payload: %s",
                 BSL_Log_DumpAsHexString(logstr, sizeof(logstr), ApxA2_Ciphertext, sizeof(ApxA2_Ciphertext)));
    BSL_LOG_INFO("ACTUAL payload:   %s",
                 BSL_Log_DumpAsHexString(logstr, sizeof(logstr), target_block.btsd, target_block.btsd_len));
    TEST_ASSERT_TRUE(memcmp(ApxA2_Ciphertext, target_block.btsd, sizeof(ApxA2_Ciphertext)) == 0);

    BSL_SecOutcome_Deinit(outcome);
    BSL_SecOper_Deinit(&bcb_test_context.sec_oper);
    BSL_FREE(outcome);
}

void test_RFC9173_AppendixA_Example2_BCB_Acceptor(void)
{
    TEST_ASSERT_EQUAL(0,
                      BSL_TestUtils_LoadBundleFromCBOR(&LocalTestCtx, RFC9173_TestVectors_AppendixA2.cbor_bundle_bcb));
    mock_bpa_ctr_t *mock_bpa_ctr = &LocalTestCtx.mock_bpa_ctr;

    BCBTestContext bcb_test_context;
    BSL_TestUtils_InitBCB_Appendix2(&bcb_test_context, BSL_SECROLE_ACCEPTOR);

    BSL_SecOutcome_t *outcome = BSL_CALLOC(BSL_SecOutcome_Sizeof(), 1);
    BSL_SecOutcome_Init(outcome, &bcb_test_context.sec_oper, 10000);

    /// Confirm that BCB executes with SUCCESS
    int bcb_exec_result =
        BSLX_BCB_Execute(&LocalTestCtx.bsl, &mock_bpa_ctr->bundle_ref, &bcb_test_context.sec_oper, outcome);
    TEST_ASSERT_EQUAL(BSL_SUCCESS, bcb_exec_result);

    /// Confirm that running as ACCEPTOR consumes result.
    size_t result_count = BSL_SecOutcome_CountResults(outcome);
    TEST_ASSERT_EQUAL(0, result_count);

    /// Confirm that the target block is decrypted correctly.
    BSL_CanonicalBlock_t target_block;
    BSL_BundleCtx_GetBlockMetadata(&mock_bpa_ctr->bundle_ref, 1, &target_block);
    TEST_ASSERT_EQUAL(sizeof(ApxA2_PayloadData), target_block.btsd_len);
    uint8_t logstr[500];
    BSL_LOG_INFO("EXPECTED payload: %s",
                 BSL_Log_DumpAsHexString(logstr, sizeof(logstr), ApxA2_PayloadData, sizeof(ApxA2_PayloadData)));
    BSL_LOG_INFO("ACTUAL payload:   %s",
                 BSL_Log_DumpAsHexString(logstr, sizeof(logstr), target_block.btsd, target_block.btsd_len));
    TEST_ASSERT_TRUE(memcmp(ApxA2_PayloadData, target_block.btsd, sizeof(ApxA2_PayloadData)) == 0);

    BSL_SecOutcome_Deinit(outcome);
    BSL_SecOper_Deinit(&bcb_test_context.sec_oper);
    BSL_FREE(outcome);
}

// /// @brief Purpose: Exercises BCB as a security acceptor
// void test_DefaultSecuritContext_RFC9173_A2_BCB_Acceptor(void) {}

// /// @brief Purpose: Exercises BCB as a security acceptor with cryptographic mismatch
// void test_DefaultSecuritContext_RFC9173_A2_BCB_Acceptor_Failure(void) {}
