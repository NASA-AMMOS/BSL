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
 * @brief Exercises the Policy Provider front-end interface(*)
 * 
 * Notes:
 *  - There is one leaky absraction (it does import SamplePolicyProvider.h) for concrete struct def size.
 * 
 * @ingroup unit-tests
 */

#include <inttypes.h>
#include <unity.h>

#include <BPSecLib.h>
#include <BPSecLib_MockBPA.h>
// TODO(bvb) This should be removed. This level should only include the front-end.
#include <policy_provider/SamplePolicyProvider.h>

#include "bsl_test_utils.h"


static BSL_TestContext_t LocalTestCtx;

void setUp(void)
{
    BSL_openlog();
    assert(0 == bsl_mock_bpa_init());
    setenv("BSL_TEST_LOCAL_IPN_EID", "ipn:2.1", 1);
    memset(&LocalTestCtx, 0, sizeof(LocalTestCtx));
    TEST_ASSERT_EQUAL(0, BSL_LibCtx_Init(&LocalTestCtx.bsl));
    LocalTestCtx.bsl.policy_provider = calloc(sizeof(BSL_PolicyProvider_t), 1);
    mock_bpa_ctr_init(&LocalTestCtx.mock_bpa_ctr);
}

void tearDown(void)
{
    mock_bpa_ctr_deinit(&LocalTestCtx.mock_bpa_ctr);
    TEST_ASSERT_EQUAL(0, BSL_LibCtx_Deinit(&LocalTestCtx.bsl));
    bsl_mock_bpa_deinit();
    BSL_closelog();
}

/**
 * @brief Purpose: Query an empty ruleset produces no responses
 */
void test_PolicyProvider_InspectEmptyRuleset(void)
{
    strncpy(LocalTestCtx.bsl.policy_provider->name, "Unit Test Policy Provider!", sizeof(LocalTestCtx.bsl.policy_provider->name));
    LocalTestCtx.bsl.policy_provider->rule_capacity = sizeof(LocalTestCtx.bsl.policy_provider->rules) / sizeof(BSLP_PolicyRule_t);
    TEST_ASSERT_EQUAL(0, BSL_TestUtils_LoadBundleFromCBOR(&LocalTestCtx, RFC9173_TestVectors_AppendixA1.cbor_bundle_bib));

    BSL_PolicyActionSet_t action_set = { 0 };
    TEST_ASSERT_EQUAL(0, BSL_PolicyProvider_InspectActions(LocalTestCtx.bsl.policy_provider, &action_set,
                                                           LocalTestCtx.mock_bpa_ctr.bundle, BSL_POLICYLOCATION_APPIN));
    TEST_ASSERT_EQUAL(0, BSL_PolicyActionSet_CountSecOpers(&action_set));
    TEST_ASSERT_EQUAL(0, BSL_PolicyActionSet_GetErrCode(&action_set));
}

/**
 * @brief Purpose: Match a wildcard predicate to produce an Action to verify BIB (but no parameters).
 * 
 * Notes:
 *  - This is a subset of the following test and can probably be removed.
 */
void test_PolicyProvider_InspectSingleBIBRuleset(void)
{
    {
        strncpy(LocalTestCtx.bsl.policy_provider->name, "Unit Test Policy Provider!", sizeof(LocalTestCtx.bsl.policy_provider->name));
        LocalTestCtx.bsl.policy_provider->rule_capacity = sizeof(LocalTestCtx.bsl.policy_provider->rules) / sizeof(BSLP_PolicyRule_t);

        BSLP_PolicyPredicate_t predicate = {0};
        BSLP_PolicyPredicate_Init(&predicate, BSL_POLICYLOCATION_APPIN, GetEIDPatternFromText("*:**"),
                                  GetEIDPatternFromText("*:**"), GetEIDPatternFromText("*:**"));
        BSLP_PolicyRule_t rule = {0};
        BSLP_PolicyRule_Init(&rule, "Verify BIB on APPIN from anywhere", predicate, 1, BSL_SECROLE_VERIFIER, BSL_SECBLOCKTYPE_BIB, BSL_BLOCK_TYPE_PAYLOAD);
        LocalTestCtx.bsl.policy_provider->rules[LocalTestCtx.bsl.policy_provider->rule_count++] = rule;
    }

    TEST_ASSERT_EQUAL(0, BSL_TestUtils_LoadBundleFromCBOR(&LocalTestCtx, RFC9173_TestVectors_AppendixA1.cbor_bundle_bib));

    BSL_PolicyActionSet_t action_set = { 0 };
    TEST_ASSERT_EQUAL(0, BSL_PolicyProvider_InspectActions(LocalTestCtx.bsl.policy_provider, &action_set, LocalTestCtx.mock_bpa_ctr.bundle, BSL_POLICYLOCATION_APPIN));
    TEST_ASSERT_EQUAL(1, BSL_PolicyActionSet_CountSecOpers(&action_set));
    TEST_ASSERT_EQUAL(0, BSL_PolicyActionSet_GetErrCode(&action_set));
}

/**
 * @brief: Purpose: Match a wildcard rule to verify BIB for all bundles and produce an action with specific parameters.
 */
void test_PolicyProvider_Inspect_RFC9173_BIB(void)
{
    strncpy(LocalTestCtx.bsl.policy_provider->name, "Unit Test Policy Provider!", sizeof(LocalTestCtx.bsl.policy_provider->name));
    LocalTestCtx.bsl.policy_provider->rule_capacity = sizeof(LocalTestCtx.bsl.policy_provider->rules) / sizeof(BSLP_PolicyRule_t);

    BSLP_PolicyPredicate_t predicate = {0};
    BSLP_PolicyPredicate_Init(&predicate, BSL_POLICYLOCATION_APPIN, GetEIDPatternFromText("*:**"),
                                GetEIDPatternFromText("*:**"), GetEIDPatternFromText("*:**"));

    BSLP_PolicyRule_t *rule = &LocalTestCtx.bsl.policy_provider->rules[LocalTestCtx.bsl.policy_provider->rule_count++];
    BSLP_PolicyRule_Init(rule, "Verify BIB on APPIN from anywhere", predicate, 1, BSL_SECROLE_VERIFIER, BSL_SECBLOCKTYPE_BIB, BSL_BLOCK_TYPE_PAYLOAD);
    RFC9173_A1_Params bib_params = BSLTEST_GetRFC9173_A1Params(RFC9173_EXAMPLE_A1_KEY);
    BSLP_PolicyRule_AddParam(rule, &bib_params.sha_variant);
    BSLP_PolicyRule_AddParam(rule, &bib_params.scope_flags);
    BSLP_PolicyRule_AddParam(rule, &bib_params.test_key_id);

    TEST_ASSERT_EQUAL(0, BSL_TestUtils_LoadBundleFromCBOR(&LocalTestCtx, RFC9173_TestVectors_AppendixA1.cbor_bundle_bib));

    BSL_PolicyActionSet_t action_set = { 0 };
    TEST_ASSERT_EQUAL(0, BSL_PolicyProvider_InspectActions(LocalTestCtx.bsl.policy_provider, &action_set, LocalTestCtx.mock_bpa_ctr.bundle, BSL_POLICYLOCATION_APPIN));
    TEST_ASSERT_EQUAL(1, BSL_PolicyActionSet_CountSecOpers(&action_set));
    TEST_ASSERT_EQUAL(0, BSL_PolicyActionSet_GetErrCode(&action_set));
    TEST_ASSERT_EQUAL(3, BSL_SecOper_GetParamLen(BSL_PolicyActionSet_GetSecOperAtIndex(&action_set, 0)));

    BSL_PolicyActionSet_Deinit(&action_set);
}

// TODO - test with also setting sec pararms and other things and test the RFC 9173 things.