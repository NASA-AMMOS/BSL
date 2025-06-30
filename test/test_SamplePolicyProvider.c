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
 * @brief Specific low-level tests of the Sample Policy Provider
 *
 * Notes:
 *
 * @ingroup unit-tests
 */
#include <unity.h>

#include <BPSecLib_Private.h>

#include <bsl_mock_bpa.h>
#include <bsl_mock_bpa_eid.h>
#include <bsl_mock_bpa_decode.h>
#include "bsl_test_utils.h"

#include <policy_provider/SamplePolicyProvider.h>

static BSL_TestContext_t LocalTestCtx;

void setUp(void)
{
    BSL_openlog();
    assert(0 == bsl_mock_bpa_init());
    setenv("BSL_TEST_LOCAL_IPN_EID", "ipn:2.1", 1);
    memset(&LocalTestCtx, 0, sizeof(LocalTestCtx));
    TEST_ASSERT_EQUAL(0, BSL_API_InitLib(&LocalTestCtx.bsl));
    mock_bpa_ctr_init(&LocalTestCtx.mock_bpa_ctr);
}

void tearDown(void)
{
    mock_bpa_ctr_deinit(&LocalTestCtx.mock_bpa_ctr);
    // BSL_BundleCtx_Deinit(LocalTestCtx.bundle);
    TEST_ASSERT_EQUAL(0, BSL_API_DeinitLib(&LocalTestCtx.bsl));
    bsl_mock_bpa_deinit();
    BSL_closelog();
}

/**
 * Creates a rule: At location "APPIN", Bundles FROM anywhere, Bundles TO anywhere,
 *                 must contain a BIB block covering the payload.
 */
/**
 * @brief Purpose: Exercise the Rule and Predicate primitives to for BIB in a given bundle
 *
 * Steps:
 *  - Use an example Bundle with primary, payload, and BIB block over the payload (From RFC9173)
 *  - Create a predicate to match any bundle using wildcards (at location APPIN)
 *  - Create a rule to verify a BIB covers the payload block for any Bundle matching the predicate.
 *  - Use this to create a Security Operation for verifying the BIB
 *  - Check that the Security Operation has an ID=2 and targets the payload block (1)
 *
 * Notes:
 *  - Common repeated patterns are in the process of being factored out
 *  - All values are drawn from RFC9173 Appendix A.
 */
void test_SamplePolicyProvider_WildcardPolicyRuleVerifiesBIB(void)
{
    // Load the sample Bundle with a BIB block.
    TEST_ASSERT_EQUAL(0,
                      BSL_TestUtils_LoadBundleFromCBOR(&LocalTestCtx, RFC9173_TestVectors_AppendixA1.cbor_bundle_bib));

    // Create a predicate: "At location APPIN, match Bundles from anywhere, to anywhere, with any security source"
    BSLP_PolicyPredicate_t predicate;
    BSLP_PolicyPredicate_Init(&predicate, BSL_POLICYLOCATION_APPIN, BSL_TestUtils_GetEidPatternFromText("*:**"),
                              BSL_TestUtils_GetEidPatternFromText("*:**"), BSL_TestUtils_GetEidPatternFromText("*:**"));

    // Create a rule to verify the bundle contains a BIB block covering the payload
    BSLP_PolicyRule_t rule;
    BSLP_PolicyRule_Init(&rule, "Confirm bundle has BIB protecting payload", &predicate, 1, BSL_SECROLE_VERIFIER,
                         BSL_SECBLOCKTYPE_BIB, BSL_BLOCK_TYPE_PAYLOAD, BSL_POLICYACTION_DROP_BUNDLE);

    // Now evaluate the rule to get as a SecOper
    // This populates it with actual parameters.
    BSL_SecOper_t sec_oper;
    TEST_ASSERT_EQUAL(0, BSLP_PolicyRule_EvaluateAsSecOper(&rule, &sec_oper, &LocalTestCtx.mock_bpa_ctr.bundle_ref,
                                                           BSL_POLICYLOCATION_APPIN));

    // Confirm the security operation uses BIB
    TEST_ASSERT_EQUAL(true, BSL_SecOper_IsBIB(&sec_oper));

    // Confirm the target of the security operation is the payload block
    TEST_ASSERT_EQUAL(1, sec_oper.target_block_num);

    // Confirm the block ID of the BIB block is 2.
    // TEST_ASSERT_EQUAL(2, sec_oper.sec_block_num);

    // TODO - Test security parameters.

    BSLP_PolicyRule_Deinit(&rule);
    BSLP_PolicyPredicate_Deinit(&predicate);
}

// TODO(bvb) more tests with more granular predicates and rules
