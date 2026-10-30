/*
 * Copyright (c) 2025-2026 The Johns Hopkins University Applied Physics
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
 * @ingroup unit_test
 */
#include "DefaultScUtils.h"

#include <bsl/BPSecLib_Private.h>
#include <bsl/sample_pp/SamplePolicyProvider.h>
#include <bsl/mock_bpa/MockBPA.h>

#include <unity.h>

static BSL_TestContext_t LocalTestCtx;

void suiteSetUp(void)
{
    TEST_ASSERT_EQUAL_INT(0, BSL_HostDescriptors_Set(MockBPA_Agent_Descriptors(NULL)));
    mock_bpa_LogOpen();
}

int suiteTearDown(int failures)
{
    mock_bpa_LogClose();
    BSL_HostDescriptors_Clear();
    return failures;
}

void setUp(void)
{
    setenv("BSL_TEST_LOCAL_IPN_EID", "ipn:2.1", 1);
    TEST_ASSERT_EQUAL(0, BSL_TestContext_Init(&LocalTestCtx));
}

void tearDown(void)
{
    TEST_ASSERT_EQUAL(0, BSL_TestContext_Deinit(&LocalTestCtx));
}

void test_SamplePolicyProvider_GetRuleById(void)
{
    BSLP_PolicyProvider_t *provider = BSLP_PolicyProvider_New(1);

    BSLP_PolicyRule_t rule;
    BSLP_PolicyRule_InitFrom(&rule, 42, "rule 42", 1, BSL_SECROLE_VERIFIER, BSL_SECBLOCKTYPE_BIB,
                             BSL_BLOCK_TYPE_PAYLOAD, BSL_POLICYACTION_DROP_BUNDLE);

    BSLP_PolicyPredicate_t predicate;
    BSLP_PolicyPredicate_InitFrom(&predicate, BSL_POLICYLOCATION_APPIN, "*:**", "*:**", "*:**");
    TEST_ASSERT_EQUAL(BSL_SUCCESS, BSLP_PolicyProvider_AddRule(provider, &rule, &predicate));

    const BSLP_PolicyRule_t *found = BSLP_PolicyProvider_GetRuleById(provider, 42);
    TEST_ASSERT_NOT_NULL(found);
    TEST_ASSERT_EQUAL(42, found->rule_id);
    TEST_ASSERT_EQUAL_STRING("rule 42", m_string_get_cstr(found->description));
    TEST_ASSERT_NULL(BSLP_PolicyProvider_GetRuleById(provider, 7));

    BSLP_PolicyProvider_Destroy(provider);
}

void test_SamplePolicyProvider_RejectsDuplicateRuleId(void)
{
    BSLP_PolicyProvider_t *provider = BSLP_PolicyProvider_New(1);

    BSLP_PolicyRule_t rule;
    BSLP_PolicyRule_InitFrom(&rule, 42, "original", 1, BSL_SECROLE_VERIFIER, BSL_SECBLOCKTYPE_BIB,
                             BSL_BLOCK_TYPE_PAYLOAD, BSL_POLICYACTION_DROP_BUNDLE);
    BSLP_PolicyPredicate_t predicate;
    BSLP_PolicyPredicate_InitFrom(&predicate, BSL_POLICYLOCATION_APPIN, "*:**", "*:**", "*:**");
    TEST_ASSERT_EQUAL(BSL_SUCCESS, BSLP_PolicyProvider_AddRule(provider, &rule, &predicate));

    BSLP_PolicyRule_InitFrom(&rule, 42, "duplicate", 1, BSL_SECROLE_VERIFIER, BSL_SECBLOCKTYPE_BIB,
                             BSL_BLOCK_TYPE_PAYLOAD, BSL_POLICYACTION_DROP_BUNDLE);
    BSLP_PolicyPredicate_InitFrom(&predicate, BSL_POLICYLOCATION_APPIN, "*:**", "*:**", "*:**");
    TEST_ASSERT_EQUAL(BSL_ERR_POLICY_CONFIG, BSLP_PolicyProvider_AddRule(provider, &rule, &predicate));
    TEST_ASSERT_EQUAL(1, BSLP_PolicyProvider_RuleCount(provider));
    TEST_ASSERT_EQUAL_STRING("original", m_string_get_cstr(BSLP_PolicyProvider_GetRuleById(provider, 42)->description));

    BSLP_PolicyRule_Deinit(&rule);
    BSLP_PolicyPredicate_Deinit(&predicate);
    BSLP_PolicyProvider_Destroy(provider);
}

void test_SamplePolicyProvider_RemoveRuleById(void)
{
    BSLP_PolicyProvider_t *provider = BSLP_PolicyProvider_New(1);

    BSLP_PolicyRule_t rule;
    BSLP_PolicyRule_InitFrom(&rule, 42, "rule 42", 1, BSL_SECROLE_VERIFIER, BSL_SECBLOCKTYPE_BIB,
                             BSL_BLOCK_TYPE_PAYLOAD, BSL_POLICYACTION_DROP_BUNDLE);

    BSLP_PolicyPredicate_t predicate;
    BSLP_PolicyPredicate_InitFrom(&predicate, BSL_POLICYLOCATION_APPIN, "*:**", "*:**", "*:**");
    TEST_ASSERT_EQUAL(BSL_SUCCESS, BSLP_PolicyProvider_AddRule(provider, &rule, &predicate));
    TEST_ASSERT_EQUAL(1, BSLP_PolicyProvider_RuleCount(provider));

    TEST_ASSERT_EQUAL(BSL_SUCCESS, BSLP_PolicyProvider_RemoveRuleById(provider, 42));
    TEST_ASSERT_EQUAL(0, BSLP_PolicyProvider_RuleCount(provider));
    TEST_ASSERT_NULL(BSLP_PolicyProvider_GetRuleById(provider, 42));
    TEST_ASSERT_EQUAL(BSL_ERR_POLICY_CONFIG, BSLP_PolicyProvider_RemoveRuleById(provider, 42));

    BSLP_PolicyProvider_Destroy(provider);
}

void test_SamplePolicyProvider_ClearRules(void)
{
    BSLP_PolicyProvider_t *provider = BSLP_PolicyProvider_New(1);

    BSLP_PolicyRule_t rule;
    BSLP_PolicyRule_InitFrom(&rule, 1, "rule 1", 1, BSL_SECROLE_VERIFIER, BSL_SECBLOCKTYPE_BIB, BSL_BLOCK_TYPE_PAYLOAD, BSL_POLICYACTION_DROP_BUNDLE);
    BSLP_PolicyPredicate_t predicate;
    BSLP_PolicyPredicate_InitFrom(&predicate, BSL_POLICYLOCATION_APPIN, "*:**", "*:**", "*:**");
    TEST_ASSERT_EQUAL(BSL_SUCCESS, BSLP_PolicyProvider_AddRule(provider, &rule, &predicate));

    BSLP_PolicyRule_InitFrom(&rule, 2, "rule 2", 2, BSL_SECROLE_ACCEPTOR, BSL_SECBLOCKTYPE_BCB, BSL_BLOCK_TYPE_PRIMARY, BSL_POLICYACTION_NOTHING);
    BSLP_PolicyPredicate_InitFrom(&predicate, BSL_POLICYLOCATION_CLOUT, "ipn:1.*", "ipn:2.*", "ipn:3.*");
    TEST_ASSERT_EQUAL(BSL_SUCCESS, BSLP_PolicyProvider_AddRule(provider, &rule, &predicate));
    TEST_ASSERT_EQUAL(2, BSLP_PolicyProvider_RuleCount(provider));

    BSLP_PolicyProvider_ClearRules(provider);

    TEST_ASSERT_EQUAL(0, BSLP_PolicyProvider_RuleCount(provider));
    TEST_ASSERT_NULL(BSLP_PolicyProvider_GetRuleById(provider, 42));
    TEST_ASSERT_NULL(BSLP_PolicyProvider_GetRuleById(provider, 7));

    BSLP_PolicyProvider_Destroy(provider);
}

void test_SamplePolicyProvider_ReplaceRuleById(void)
{
    BSLP_PolicyProvider_t *provider = BSLP_PolicyProvider_New(1);

    BSLP_PolicyRule_t rule;
    BSLP_PolicyRule_InitFrom(&rule, 42, "original", 1, BSL_SECROLE_VERIFIER, BSL_SECBLOCKTYPE_BIB,
                             BSL_BLOCK_TYPE_PAYLOAD, BSL_POLICYACTION_DROP_BUNDLE);
    BSLP_PolicyPredicate_t predicate;
    BSLP_PolicyPredicate_InitFrom(&predicate, BSL_POLICYLOCATION_APPIN, "*:**", "*:**", "*:**");
    TEST_ASSERT_EQUAL(BSL_SUCCESS, BSLP_PolicyProvider_AddRule(provider, &rule, &predicate));

    BSLP_PolicyRule_t replacement;
    BSLP_PolicyRule_InitFrom(&replacement, 42, "replacement without predicate", 1, BSL_SECROLE_VERIFIER,
                             BSL_SECBLOCKTYPE_BIB, BSL_BLOCK_TYPE_PAYLOAD, BSL_POLICYACTION_DROP_BUNDLE);
    TEST_ASSERT_EQUAL(BSL_SUCCESS, BSLP_PolicyProvider_ReplaceRuleById(provider, 42, &replacement, NULL));
    TEST_ASSERT_EQUAL(1, BSLP_PolicyProvider_RuleCount(provider));

    const BSLP_PolicyRule_t *found = BSLP_PolicyProvider_GetRuleById(provider, 42);
    TEST_ASSERT_NOT_NULL(found);
    TEST_ASSERT_EQUAL_STRING("replacement without predicate", m_string_get_cstr(found->description));

    TEST_ASSERT_EQUAL(0,
                      BSL_TestUtils_LoadBundleFromCBOR(&LocalTestCtx, RFC9173_TestVectors_AppendixA1.hex_bundle_bib));
    BSL_SecurityActionSet_t action_set;
    BSL_SecurityActionSet_Init(&action_set);
    TEST_ASSERT_EQUAL(BSL_SUCCESS, BSLP_QueryPolicy(provider, &action_set, &LocalTestCtx.mock_bpa_ctr.bundle_ref,
                                                    BSL_POLICYLOCATION_APPIN));
    TEST_ASSERT_EQUAL(1, BSL_SecurityActionSet_CountActions(&action_set));
    TEST_ASSERT_EQUAL(1, BSL_SecurityAction_CountSecOpers(BSL_SecurityActionSet_GetActionAtIndex(&action_set, 0)));
    BSL_SecurityActionSet_Deinit(&action_set);

    BSLP_PolicyRule_InitFrom(&replacement, 42, "replacement", 2, BSL_SECROLE_ACCEPTOR, BSL_SECBLOCKTYPE_BCB,
                             BSL_BLOCK_TYPE_PRIMARY, BSL_POLICYACTION_NOTHING);
    BSLP_PolicyPredicate_t replacement_predicate;
    BSLP_PolicyPredicate_InitFrom(&replacement_predicate, BSL_POLICYLOCATION_CLOUT, "ipn:1.*", "ipn:2.*", "ipn:3.*");
    TEST_ASSERT_EQUAL(BSL_SUCCESS,
                      BSLP_PolicyProvider_ReplaceRuleById(provider, 42, &replacement, &replacement_predicate));
    TEST_ASSERT_EQUAL(1, BSLP_PolicyProvider_RuleCount(provider));
    TEST_ASSERT_NULL(replacement_predicate.src_eid_pattern.handle);
    TEST_ASSERT_NULL(replacement_predicate.secsrc_eid_pattern.handle);
    TEST_ASSERT_NULL(replacement_predicate.dst_eid_pattern.handle);

    found = BSLP_PolicyProvider_GetRuleById(provider, 42);
    TEST_ASSERT_NOT_NULL(found);
    TEST_ASSERT_EQUAL_STRING("replacement", m_string_get_cstr(found->description));
    TEST_ASSERT_EQUAL(2, found->context_id);
    TEST_ASSERT_EQUAL(BSL_SECROLE_ACCEPTOR, found->role);
    TEST_ASSERT_EQUAL(BSL_SECBLOCKTYPE_BCB, found->sec_block_type);

    BSLP_PolicyRule_t missing;
    BSLP_PolicyRule_InitFrom(&missing, 7, "missing", 1, BSL_SECROLE_VERIFIER, BSL_SECBLOCKTYPE_BIB,
                             BSL_BLOCK_TYPE_PAYLOAD, BSL_POLICYACTION_DROP_BUNDLE);
    BSLP_PolicyPredicate_t missing_predicate;
    BSLP_PolicyPredicate_InitFrom(&missing_predicate, BSL_POLICYLOCATION_APPIN, "*:**", "*:**", "*:**");
    TEST_ASSERT_EQUAL(BSL_ERR_POLICY_CONFIG,
                      BSLP_PolicyProvider_ReplaceRuleById(provider, 7, &missing, &missing_predicate));
    TEST_ASSERT_EQUAL(7, missing.rule_id);
    BSLP_PolicyRule_Deinit(&missing);
    BSLP_PolicyPredicate_Deinit(&missing_predicate);

    BSLP_PolicyProvider_Destroy(provider);
}

/**
 * @brief Purpose: Exercise the Rule and Predicate primitives to for BIB in a given bundle.
 *
 * Creates a rule: At location "APPIN", Bundles FROM anywhere, Bundles TO anywhere,
 *                 must contain a BIB block covering the payload.
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
                      BSL_TestUtils_LoadBundleFromCBOR(&LocalTestCtx, RFC9173_TestVectors_AppendixA1.hex_bundle_bib));

    // Create a predicate: "At location APPIN, match Bundles from anywhere, to anywhere, with any security source"
    BSLP_PolicyPredicate_t predicate;
    BSLP_PolicyPredicate_InitFrom(&predicate, BSL_POLICYLOCATION_APPIN, "*:**", "*:**", "*:**");

    // Create a rule to verify the bundle contains a BIB block covering the payload
    BSLP_PolicyRule_t rule;
    BSLP_PolicyRule_InitFrom(&rule, 1, "Confirm bundle has BIB protecting payload", 1, BSL_SECROLE_VERIFIER,
                             BSL_SECBLOCKTYPE_BIB, BSL_BLOCK_TYPE_PAYLOAD, BSL_POLICYACTION_DROP_BUNDLE);

    // Now evaluate the rule to get as a SecOper
    // This populates it with actual parameters.
    BSL_SecOper_t sec_oper;
    BSL_SecOper_Init(&sec_oper);
    TEST_ASSERT_EQUAL(0, BSLP_PolicyRule_EvaluateAsSecOper(&rule, &predicate, &sec_oper,
                                                           &LocalTestCtx.mock_bpa_ctr.bundle_ref,
                                                           BSL_POLICYLOCATION_APPIN));

    // Confirm the security operation uses BIB
    TEST_ASSERT_EQUAL(true, BSL_SecOper_IsBIB(&sec_oper));

    // Confirm the target of the security operation is the payload block
    TEST_ASSERT_EQUAL(1, sec_oper.target_block_num);

    // Confirm the block ID of the BIB block is 2.
    // TEST_ASSERT_EQUAL(2, sec_oper.sec_block_num);

    // TODO - Test security parameters.

    BSL_SecOper_Deinit(&sec_oper);
    BSLP_PolicyRule_Deinit(&rule);
    BSLP_PolicyPredicate_Deinit(&predicate);
}
