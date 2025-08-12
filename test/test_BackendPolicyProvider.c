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
 * @brief Exercises the Policy Provider front-end interface(*)
 *
 * Notes:
 *  - There is one leaky abstraction (it does import SamplePolicyProvider.h) for concrete struct def size.
 *
 * @ingroup unit-tests
 */

#include <inttypes.h>
#include <unity.h>

#include <BPSecLib_Private.h>
#include <BPSecLib_Public.h>
#include <mock_bpa/MockBPA.h>

#include <policy_provider/SamplePolicyProvider.h>

#include "bsl_test_utils.h"

static BSL_TestContext_t LocalTestCtx;

void setUp(void)
{
    BSL_openlog();
    memset(&LocalTestCtx, 0, sizeof(LocalTestCtx));
    assert(0 == bsl_mock_bpa_agent_init());
    setenv("BSL_TEST_LOCAL_IPN_EID", "ipn:2.1", 1);
    TEST_ASSERT_EQUAL(0, BSL_API_InitLib(&LocalTestCtx.bsl));

    BSL_PolicyDesc_t policy_desc = { 0 };
    policy_desc.user_data        = calloc(sizeof(BSLP_PolicyProvider_t), 1);
    policy_desc.query_fn         = BSLP_QueryPolicy;
    policy_desc.finalize_fn      = BSLP_FinalizePolicy;
    policy_desc.deinit_fn        = BSLP_Deinit;
    assert(BSL_API_RegisterPolicyProvider(&LocalTestCtx.bsl, policy_desc) == 0);

    mock_bpa_ctr_init(&LocalTestCtx.mock_bpa_ctr);
}

void tearDown(void)
{
    mock_bpa_ctr_deinit(&LocalTestCtx.mock_bpa_ctr);
    TEST_ASSERT_EQUAL(0, BSL_API_DeinitLib(&LocalTestCtx.bsl));
    bsl_mock_bpa_agent_deinit();
    BSL_closelog();
}

/**
 * @brief Purpose: Query an empty ruleset produces no responses
 */
void test_PolicyProvider_InspectEmptyRuleset(void)
{
    BSLP_PolicyProvider_t *policy = LocalTestCtx.bsl.policy_registry.user_data;

    strncpy(policy->name, "Unit Test Policy Provider!", sizeof(policy->name));
    TEST_ASSERT_EQUAL(0,
                      BSL_TestUtils_LoadBundleFromCBOR(&LocalTestCtx, RFC9173_TestVectors_AppendixA1.cbor_bundle_bib));

    BSL_SecurityActionSet_t action_set = { 0 };
    TEST_ASSERT_EQUAL(0, BSL_PolicyRegistry_InspectActions(&LocalTestCtx.bsl, &action_set,
                                                           &LocalTestCtx.mock_bpa_ctr.bundle_ref,
                                                           BSL_POLICYLOCATION_APPIN));
    TEST_ASSERT_EQUAL(0, BSL_SecurityActionSet_CountSecOpers(&action_set));
    TEST_ASSERT_EQUAL(0, BSL_SecurityActionSet_GetErrCode(&action_set));
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
        BSLP_PolicyProvider_t *policy = LocalTestCtx.bsl.policy_registry.user_data;
        strncpy(policy->name, "Unit Test Policy Provider!", sizeof(policy->name));

        BSLP_PolicyPredicate_t *predicate = &policy->predicates[policy->predicate_count++];
        BSLP_PolicyPredicate_Init(predicate, BSL_POLICYLOCATION_APPIN, BSL_TestUtils_GetEidPatternFromText("*:**"),
                                  BSL_TestUtils_GetEidPatternFromText("*:**"),
                                  BSL_TestUtils_GetEidPatternFromText("*:**"));

        BSLP_PolicyRule_t *rule = &policy->rules[policy->rule_count++];
        BSLP_PolicyRule_Init(rule, "Verify BIB on APPIN from anywhere", predicate, 1, BSL_SECROLE_VERIFIER,
                             BSL_SECBLOCKTYPE_BIB, BSL_BLOCK_TYPE_PAYLOAD, BSL_POLICYACTION_DROP_BUNDLE);
    }

    TEST_ASSERT_EQUAL(0,
                      BSL_TestUtils_LoadBundleFromCBOR(&LocalTestCtx, RFC9173_TestVectors_AppendixA1.cbor_bundle_bib));

    BSL_SecurityActionSet_t action_set = { 0 };
    TEST_ASSERT_EQUAL(0, BSL_PolicyRegistry_InspectActions(&LocalTestCtx.bsl, &action_set,
                                                           &LocalTestCtx.mock_bpa_ctr.bundle_ref,
                                                           BSL_POLICYLOCATION_APPIN));
    TEST_ASSERT_EQUAL(1, BSL_SecurityActionSet_CountSecOpers(&action_set));
    TEST_ASSERT_EQUAL(0, BSL_SecurityActionSet_GetErrCode(&action_set));
}

/**
 * @brief: Purpose: Match a wildcard rule to verify BIB for all bundles and produce an action with specific parameters.
 */
void test_PolicyProvider_Inspect_RFC9173_BIB(void)
{
    BSLP_PolicyProvider_t *policy = LocalTestCtx.bsl.policy_registry.user_data;
    strncpy(policy->name, "Unit Test Policy Provider!", sizeof(policy->name));

    BSLP_PolicyPredicate_t *predicate = &policy->predicates[policy->predicate_count++];
    BSLP_PolicyPredicate_Init(predicate, BSL_POLICYLOCATION_APPIN, BSL_TestUtils_GetEidPatternFromText("*:**"),
                              BSL_TestUtils_GetEidPatternFromText("*:**"), BSL_TestUtils_GetEidPatternFromText("*:**"));

    BSLP_PolicyRule_t *rule = &policy->rules[policy->rule_count++];
    BSLP_PolicyRule_Init(rule, "Verify BIB on APPIN from anywhere", predicate, 1, BSL_SECROLE_VERIFIER,
                         BSL_SECBLOCKTYPE_BIB, BSL_BLOCK_TYPE_PAYLOAD, BSL_POLICYACTION_DROP_BUNDLE);
    RFC9173_A1_Params bib_params = BSL_TestUtils_GetRFC9173_A1Params(RFC9173_EXAMPLE_A1_KEY);
    BSLP_PolicyRule_AddParam(rule, &bib_params.sha_variant);
    BSLP_PolicyRule_AddParam(rule, &bib_params.scope_flags);
    BSLP_PolicyRule_AddParam(rule, &bib_params.test_key_id);

    TEST_ASSERT_EQUAL(0,
                      BSL_TestUtils_LoadBundleFromCBOR(&LocalTestCtx, RFC9173_TestVectors_AppendixA1.cbor_bundle_bib));

    BSL_SecurityActionSet_t action_set = { 0 };
    TEST_ASSERT_EQUAL(0, BSL_PolicyRegistry_InspectActions(&LocalTestCtx.bsl, &action_set,
                                                           &LocalTestCtx.mock_bpa_ctr.bundle_ref,
                                                           BSL_POLICYLOCATION_APPIN));
    TEST_ASSERT_EQUAL(1, BSL_SecurityActionSet_CountSecOpers(&action_set));
    TEST_ASSERT_EQUAL(0, BSL_SecurityActionSet_GetErrCode(&action_set));
    TEST_ASSERT_EQUAL(3, BSL_SecOper_CountParams(BSL_SecurityActionSet_GetSecOperAtIndex(&action_set, 0)));

    BSL_SecurityActionSet_Deinit(&action_set);
}

// TODO - test with also setting sec pararms and other things and test the RFC 9173 things.
