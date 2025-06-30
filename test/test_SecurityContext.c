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

#include <BPSecLib.h>
#include <BPSecLib_MockBPA.h>

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
void test_SecurityContext_BIB_Source(void)
{
    TEST_ASSERT_EQUAL(0, BSL_TestUtils_LoadBundleFromCBOR(&LocalTestCtx, RFC9173_TestVectors_AppendixA1.cbor_bundle_original));
    mock_bpa_ctr_t *mock_bpa_ctr = &LocalTestCtx.mock_bpa_ctr;

    RFC9173_A1_Params bib_params = BSLTEST_GetRFC9173_A1Params(RFC9173_EXAMPLE_A1_KEY);
    BSL_SecParam_t *parm_list[3] = {&bib_params.sha_variant, &bib_params.scope_flags, &bib_params.test_key_id};
    BSL_PolicyActionSet_t *malloced_actionset = BSLTEST_InitMallocBIBActionSet(BSL_SECROLE_SOURCE, 3, parm_list);
    BSL_PolicyResponseSet_t *malloced_responseset = BSLTEST_MallocEmptyPolicyResponse();

    // TODO, implement this function
    BSL_SecCtx_ExecutePolicyActionSetNew(&LocalTestCtx.bsl, malloced_responseset, mock_bpa_ctr->bundle, malloced_actionset);

    TEST_ASSERT_EQUAL(0, BSL_SecCtx_ExecutePolicyActionSet(&LocalTestCtx.bsl, mock_bpa_ctr->bundle, malloced_actionset));
    TEST_ASSERT_EQUAL(0, mock_bpa_encode(mock_bpa_ctr));
    bool is_expected = (BSLTEST_IsB16StrEqualTo(RFC9173_TestVectors_AppendixA1.cbor_bundle_bib, mock_bpa_ctr->encoded));

    BSL_PolicyActionSet_Deinit(malloced_actionset);
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
    TEST_ASSERT_EQUAL(0, BSL_TestUtils_LoadBundleFromCBOR(&LocalTestCtx, RFC9173_TestVectors_AppendixA1.cbor_bundle_bib));
    mock_bpa_ctr_t *mock_bpa_ctr = &LocalTestCtx.mock_bpa_ctr;

    RFC9173_A1_Params bib_params = BSLTEST_GetRFC9173_A1Params(RFC9173_EXAMPLE_A1_KEY);
    BSL_SecParam_t *parm_list[3] = {&bib_params.sha_variant, &bib_params.scope_flags, &bib_params.test_key_id};
    BSL_PolicyActionSet_t *malloced_actionset = BSLTEST_InitMallocBIBActionSet(BSL_SECROLE_VERIFIER, 3, parm_list);

    TEST_ASSERT_EQUAL(0, BSL_SecCtx_ExecutePolicyActionSet(&LocalTestCtx.bsl, mock_bpa_ctr->bundle, malloced_actionset));
    TEST_ASSERT_EQUAL(0, mock_bpa_encode(mock_bpa_ctr));
    bool is_match = (BSLTEST_IsB16StrEqualTo(RFC9173_TestVectors_AppendixA1.cbor_bundle_bib, mock_bpa_ctr->encoded));
    
    BSL_PolicyActionSet_Deinit(malloced_actionset);
    free(malloced_actionset);

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
    TEST_ASSERT_EQUAL(0, BSL_TestUtils_LoadBundleFromCBOR(&LocalTestCtx, RFC9173_TestVectors_AppendixA1.cbor_bundle_bib));
    mock_bpa_ctr_t *mock_bpa_ctr = &LocalTestCtx.mock_bpa_ctr;

    // Note, this is an INCORRECT key
    RFC9173_A1_Params bib_params = BSLTEST_GetRFC9173_A1Params(RFC9173_EXAMPLE_A2_KEY);
    BSL_SecParam_t *parm_list[3] = {&bib_params.sha_variant, &bib_params.scope_flags, &bib_params.test_key_id};
    BSL_PolicyActionSet_t *malloced_actionset = BSLTEST_InitMallocBIBActionSet(BSL_SECROLE_VERIFIER, 3, parm_list);

    TEST_ASSERT_NOT_EQUAL(0, BSL_SecCtx_ExecutePolicyActionSet(&LocalTestCtx.bsl, mock_bpa_ctr->bundle, malloced_actionset));
    
    BSL_PolicyActionSet_Deinit(malloced_actionset);
    free(malloced_actionset);
}

/**
 * @brief Tests that an acceptor will strip off the result and security block when the security operation validates correctly.
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
    TEST_ASSERT_EQUAL(0, BSL_TestUtils_LoadBundleFromCBOR(&LocalTestCtx, RFC9173_TestVectors_AppendixA1.cbor_bundle_bib));
    mock_bpa_ctr_t *mock_bpa_ctr = &LocalTestCtx.mock_bpa_ctr;

    RFC9173_A1_Params bib_params = BSLTEST_GetRFC9173_A1Params(RFC9173_EXAMPLE_A1_KEY);
    BSL_SecParam_t *parm_list[3] = {&bib_params.sha_variant, &bib_params.scope_flags, &bib_params.test_key_id};
    BSL_PolicyActionSet_t *malloced_actionset = BSLTEST_InitMallocBIBActionSet(BSL_SECROLE_ACCEPTOR, 3, parm_list);

    TEST_ASSERT_EQUAL(0, BSL_SecCtx_ExecutePolicyActionSet(&LocalTestCtx.bsl, mock_bpa_ctr->bundle, malloced_actionset));
    TEST_ASSERT_EQUAL(0, mock_bpa_encode(mock_bpa_ctr));
    TEST_ASSERT_TRUE(BSLTEST_IsB16StrEqualTo(RFC9173_TestVectors_AppendixA1.cbor_bundle_original, mock_bpa_ctr->encoded));
    
    BSL_PolicyActionSet_Deinit(malloced_actionset);
    free(malloced_actionset);
}

/// @brief Purpose: Apply a BCB block to a bundle using example from RFC9173 Appendix A2
void test_SecurityContext_BCB_Source(void)
{
}

/// @brief Purpose: Quickly fail when BCB is given role VERIFIER (invalid/illegal state)
void test_SecurityContext_BCB_Verifier_Failure(void)
{
}

/// @brief Purpose: Validate, decrypt, and remove BCB block from bundle when valid
void test_SecurityContext_BCB_Acceptor(void)
{
}

/// @brief Purpose: Validate and return error when cryptographic operation fails.
void test_SecurityContext_BCB_Acceptor_Failure(void)
{
}
