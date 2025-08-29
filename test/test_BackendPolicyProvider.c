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
    policy_desc.user_data        = BSL_CALLOC(1, sizeof(BSLP_PolicyProvider_t));
    policy_desc.query_fn         = BSLP_QueryPolicy;
    policy_desc.finalize_fn      = BSLP_FinalizePolicy;
    policy_desc.deinit_fn        = BSLP_Deinit;

    TEST_ASSERT_EQUAL(0, BSL_API_RegisterPolicyProvider(&LocalTestCtx.bsl, BSL_SAMPLE_PP_ID, policy_desc));

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
    BSLP_PolicyProvider_t *policy = BSL_PolicyDict_get(LocalTestCtx.bsl.policy_reg, BSL_SAMPLE_PP_ID)->user_data;
    string_init_set_str(policy->name, "Unit Test Policy Provider!");
    TEST_ASSERT_EQUAL(0,
                      BSL_TestUtils_LoadBundleFromCBOR(&LocalTestCtx, RFC9173_TestVectors_AppendixA1.cbor_bundle_bib));

    BSL_SecurityActionSet_t action_set = { 0 };
    TEST_ASSERT_EQUAL(0, BSL_PolicyRegistry_InspectActions(&LocalTestCtx.bsl, &action_set,
                                                           &LocalTestCtx.mock_bpa_ctr.bundle_ref,
                                                           BSL_POLICYLOCATION_APPIN));
    TEST_ASSERT_EQUAL(1, BSL_SecurityActionSet_CountActions(&action_set));
    const BSL_SecurityAction_t *act = BSL_SecurityActionSet_GetActionAtIndex(&action_set, 0);
    TEST_ASSERT_EQUAL(BSL_SAMPLE_PP_ID, act->pp_id);
    TEST_ASSERT_EQUAL(0, BSL_SecurityAction_CountSecOpers(act));

    BSL_SecurityActionSet_Deinit(&action_set);
    string_clear(policy->name);
}

/**
 * @brief Purpose: Match a wildcard predicate to produce an Action to verify BIB (but no parameters).
 *
 * Notes:
 *  - This is a subset of the following test and can probably be removed.
 */
void test_PolicyProvider_InspectSingleBIBRuleset(void)
{
    BSLP_PolicyProvider_t *policy = BSL_PolicyDict_get(LocalTestCtx.bsl.policy_reg, BSL_SAMPLE_PP_ID)->user_data;
    string_init_set_str(policy->name, "Unit Test Policy Provider!");

    BSLP_PolicyPredicate_t *predicate = &policy->predicates[policy->predicate_count++];
    BSLP_PolicyPredicate_Init(predicate, BSL_POLICYLOCATION_APPIN, BSL_TestUtils_GetEidPatternFromText("*:**"),
                              BSL_TestUtils_GetEidPatternFromText("*:**"), BSL_TestUtils_GetEidPatternFromText("*:**"));

    BSLP_PolicyRule_t *rule = &policy->rules[policy->rule_count++];
    BSLP_PolicyRule_Init(rule, "Verify BIB on APPIN from anywhere", predicate, 1, BSL_SECROLE_VERIFIER,
                         BSL_SECBLOCKTYPE_BIB, BSL_BLOCK_TYPE_PAYLOAD, BSL_POLICYACTION_DROP_BUNDLE);

    TEST_ASSERT_EQUAL(0,
                      BSL_TestUtils_LoadBundleFromCBOR(&LocalTestCtx, RFC9173_TestVectors_AppendixA1.cbor_bundle_bib));

    BSL_SecurityActionSet_t action_set = { 0 };
    TEST_ASSERT_EQUAL(0, BSL_PolicyRegistry_InspectActions(&LocalTestCtx.bsl, &action_set,
                                                           &LocalTestCtx.mock_bpa_ctr.bundle_ref,
                                                           BSL_POLICYLOCATION_APPIN));
    TEST_ASSERT_EQUAL(1, BSL_SecurityActionSet_CountActions(&action_set));
    TEST_ASSERT_EQUAL(1, BSL_SecurityAction_CountSecOpers(BSL_SecurityActionSet_GetActionAtIndex(&action_set, 0)));

    BSL_SecurityActionSet_Deinit(&action_set);
    string_clear(policy->name);
}

/**
 * @brief: Purpose: Match a wildcard rule to verify BIB for all bundles and produce an action with specific parameters.
 */
void test_PolicyProvider_Inspect_RFC9173_BIB(void)
{
    BSLP_PolicyProvider_t *policy = BSL_PolicyDict_get(LocalTestCtx.bsl.policy_reg, BSL_SAMPLE_PP_ID)->user_data;
    string_init_set_str(policy->name, "Unit Test Policy Provider!");

    BSLP_PolicyPredicate_t *predicate = &policy->predicates[policy->predicate_count++];
    BSLP_PolicyPredicate_Init(predicate, BSL_POLICYLOCATION_APPIN, BSL_TestUtils_GetEidPatternFromText("*:**"),
                              BSL_TestUtils_GetEidPatternFromText("*:**"), BSL_TestUtils_GetEidPatternFromText("*:**"));

    BSLP_PolicyRule_t *rule = &policy->rules[policy->rule_count++];
    BSLP_PolicyRule_Init(rule, "Verify BIB on APPIN from anywhere", predicate, 1, BSL_SECROLE_VERIFIER,
                         BSL_SECBLOCKTYPE_BIB, BSL_BLOCK_TYPE_PAYLOAD, BSL_POLICYACTION_DROP_BUNDLE);
    RFC9173_A1_Params bib_params = BSL_TestUtils_GetRFC9173_A1Params(RFC9173_EXAMPLE_A1_KEY);
    BSLP_PolicyRule_MoveParam(rule, &bib_params.sha_variant);
    BSLP_PolicyRule_MoveParam(rule, &bib_params.scope_flags);
    BSLP_PolicyRule_MoveParam(rule, &bib_params.test_key_id);

    TEST_ASSERT_EQUAL(0,
                      BSL_TestUtils_LoadBundleFromCBOR(&LocalTestCtx, RFC9173_TestVectors_AppendixA1.cbor_bundle_bib));

    BSL_SecurityActionSet_t action_set = { 0 };
    TEST_ASSERT_EQUAL(0, BSL_PolicyRegistry_InspectActions(&LocalTestCtx.bsl, &action_set,
                                                           &LocalTestCtx.mock_bpa_ctr.bundle_ref,
                                                           BSL_POLICYLOCATION_APPIN));
    const BSL_SecurityAction_t *act = BSL_SecurityActionSet_GetActionAtIndex(&action_set, 0);
    TEST_ASSERT_EQUAL(BSL_SAMPLE_PP_ID, act->pp_id);
    TEST_ASSERT_EQUAL(1, BSL_SecurityAction_CountSecOpers(act));
    TEST_ASSERT_EQUAL(3, BSL_SecOper_CountParams(BSL_SecurityAction_GetSecOperAtIndex(act, 0)));

    BSL_SecurityActionSet_Deinit(&action_set);
    string_clear(policy->name);
}

// TODO - test with also setting sec pararms and other things and test the RFC 9173 things.

/**
 * 2 PPs: First has role to source BIB over primary,  second has role to source BIB over payloads
 * Assert actions have correct pp_ids
 */
void test_MultiplePolicyProviders(void)
{
    BSL_PolicyDesc_t policy_desc_2 = { 0 };
    policy_desc_2.user_data        = BSL_CALLOC(1, sizeof(BSLP_PolicyProvider_t));
    policy_desc_2.query_fn         = BSLP_QueryPolicy;
    policy_desc_2.finalize_fn      = BSLP_FinalizePolicy;
    policy_desc_2.deinit_fn        = BSLP_Deinit;
    TEST_ASSERT_EQUAL(0, BSL_API_RegisterPolicyProvider(&LocalTestCtx.bsl, BSL_SAMPLE_PP_ID_2, policy_desc_2));

    BSLP_PolicyProvider_t *policy = BSL_PolicyDict_get(LocalTestCtx.bsl.policy_reg, BSL_SAMPLE_PP_ID)->user_data;
    policy->pp_id                 = BSL_SAMPLE_PP_ID;
    string_init_set_str(policy->name, "Unit Test Policy Provider 1!");

    BSLP_PolicyProvider_t *policy2 = BSL_PolicyDict_get(LocalTestCtx.bsl.policy_reg, BSL_SAMPLE_PP_ID_2)->user_data;
    policy2->pp_id                 = BSL_SAMPLE_PP_ID_2;
    string_init_set_str(policy2->name, "Unit Test Policy Provider 2!");

    BSLP_PolicyPredicate_t *predicate = &policy->predicates[policy->predicate_count++];
    BSLP_PolicyPredicate_Init(predicate, BSL_POLICYLOCATION_APPIN, BSL_TestUtils_GetEidPatternFromText("*:**"),
                              BSL_TestUtils_GetEidPatternFromText("*:**"), BSL_TestUtils_GetEidPatternFromText("*:**"));

    BSLP_PolicyRule_t *rule = &policy->rules[policy->rule_count++];
    BSLP_PolicyRule_Init(rule, "Source BIB over primary on APPIN from anywhere", predicate, 1, BSL_SECROLE_SOURCE,
                         BSL_SECBLOCKTYPE_BIB, BSL_BLOCK_TYPE_PRIMARY, BSL_POLICYACTION_DROP_BUNDLE);
    RFC9173_A1_Params bib_params = BSL_TestUtils_GetRFC9173_A1Params(RFC9173_EXAMPLE_A1_KEY);
    BSLP_PolicyRule_MoveParam(rule, &bib_params.sha_variant);
    BSLP_PolicyRule_MoveParam(rule, &bib_params.scope_flags);
    BSLP_PolicyRule_MoveParam(rule, &bib_params.test_key_id);

    BSLP_PolicyPredicate_t *predicate2 = &policy2->predicates[policy2->predicate_count++];
    BSLP_PolicyPredicate_Init(predicate2, BSL_POLICYLOCATION_APPIN, BSL_TestUtils_GetEidPatternFromText("*:**"),
                              BSL_TestUtils_GetEidPatternFromText("*:**"), BSL_TestUtils_GetEidPatternFromText("*:**"));

    BSLP_PolicyRule_t *rule2 = &policy2->rules[policy2->rule_count++];
    BSLP_PolicyRule_Init(rule2, "Source BIB over payload on APPIN from anywhere", predicate2, 1, BSL_SECROLE_SOURCE,
                         BSL_SECBLOCKTYPE_BIB, BSL_BLOCK_TYPE_PAYLOAD, BSL_POLICYACTION_DROP_BUNDLE);
    RFC9173_A1_Params bib_params2 = BSL_TestUtils_GetRFC9173_A1Params(RFC9173_EXAMPLE_A1_KEY);
    BSLP_PolicyRule_MoveParam(rule2, &bib_params2.sha_variant);
    BSLP_PolicyRule_MoveParam(rule2, &bib_params2.scope_flags);
    BSLP_PolicyRule_MoveParam(rule2, &bib_params2.test_key_id);

    TEST_ASSERT_EQUAL(
        0, BSL_TestUtils_LoadBundleFromCBOR(&LocalTestCtx, RFC9173_TestVectors_AppendixA1.cbor_bundle_original));

    BSL_SecurityActionSet_t action_set = { 0 };
    TEST_ASSERT_EQUAL(0, BSL_PolicyRegistry_InspectActions(&LocalTestCtx.bsl, &action_set,
                                                           &LocalTestCtx.mock_bpa_ctr.bundle_ref,
                                                           BSL_POLICYLOCATION_APPIN));

    TEST_ASSERT_EQUAL(2, BSL_SecurityActionSet_CountActions(&action_set));

    for (size_t i = 0; i < action_set.action_count; i++)
    {
        const BSL_SecurityAction_t *act = BSL_SecurityActionSet_GetActionAtIndex(&action_set, i);
        TEST_ASSERT_EQUAL(1, BSL_SecurityAction_CountSecOpers(act));

        const BSL_SecOper_t *secop = BSL_SecurityAction_GetSecOperAtIndex(act, 0);
        if (secop->target_block_num == 0)
        {
            TEST_ASSERT_EQUAL(BSL_SAMPLE_PP_ID, act->pp_id);
        }
        else if (secop->target_block_num == 1)
        {
            TEST_ASSERT_EQUAL(BSL_SAMPLE_PP_ID_2, act->pp_id);
        }
        else
        {
            TEST_FAIL();
        }
    }

    BSL_SecurityResponseSet_t *response_set = BSL_TestUtils_MallocEmptyPolicyResponse();

    TEST_ASSERT_EQUAL(0, BSL_PolicyRegistry_FinalizeActions(&LocalTestCtx.bsl, &action_set,
                                                            &LocalTestCtx.mock_bpa_ctr.bundle_ref, response_set));

    BSL_SecurityActionSet_Deinit(&action_set);
    BSL_FREE(response_set);
    string_clear(policy->name);
    string_clear(policy2->name);
}
