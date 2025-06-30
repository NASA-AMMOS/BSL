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
#include <unity.h>

#include <BPSecLib_Public.h>
#include <CryptoInterface.h>
#include <backend/SecurityActionSet.h>
#include <backend/SecurityResultSet.h>
#include <policy_provider/SamplePolicyProvider.h>
#include <security_context/rfc9173.h>

#include "bsl_test_utils.h"

static BSL_TestContext_t LocalTestCtx = { 0 };

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

    /// Register the policy provider with some rules
    BSL_PolicyDesc_t policy_desc = { 0 };
    policy_desc.user_data        = calloc(sizeof(BSLP_PolicyProvider_t), 1);
    policy_desc.query_fn         = BSLP_QueryPolicy;
    policy_desc.deinit_fn        = BSLP_Deinit;
    TEST_ASSERT_EQUAL(0, BSL_API_RegisterPolicyProvider(&LocalTestCtx.bsl, policy_desc));

    BSLP_PolicyProvider_t *policy = LocalTestCtx.bsl.policy_registry.user_data;
    strncpy(policy->name, "Unit Test Policy Provider!", sizeof(policy->name));

    BSL_SecParam_t param_scope_flag = { 0 };
    BSL_SecParam_InitInt64(&param_scope_flag, RFC9173_BIB_PARAMID_INTEG_SCOPE_FLAG, 0);
    BSL_SecParam_t param_sha_variant = { 0 };
    BSL_SecParam_InitInt64(&param_sha_variant, RFC9173_BIB_PARAMID_SHA_VARIANT, RFC9173_BIB_SHA_HMAC512);
    BSL_SecParam_t param_test_key_correct = { 0 };
    BSL_SecParam_InitInt64(&param_test_key_correct, BSL_SECPARAM_TYPE_INT_KEY_ID, RFC9173_EXAMPLE_A1_KEY);
    BSL_SecParam_t param_test_key_bad = { 0 };
    BSL_SecParam_InitInt64(&param_test_key_bad, BSL_SECPARAM_TYPE_INT_KEY_ID, RFC9173_EXAMPLE_A2_KEY);

    // Create a rule to Accept BIB blocks on all bundle from everywhere/to everywhere at APPIN (app ingress)
    BSLP_PolicyPredicate_t *predicate_all_appin = &policy->predicates[policy->predicate_count++];
    BSLP_PolicyPredicate_Init(predicate_all_appin, BSL_POLICYLOCATION_APPIN,
                              BSL_TestUtils_GetEidPatternFromText("*:**"), BSL_TestUtils_GetEidPatternFromText("*:**"),
                              BSL_TestUtils_GetEidPatternFromText("*:**"));
    BSLP_PolicyRule_t *rule_accept_bib = &policy->rules[policy->rule_count++];
    BSLP_PolicyRule_Init(rule_accept_bib, "Accept BIB on APPIN from anywhere", predicate_all_appin, 1,
                         BSL_SECROLE_ACCEPTOR, BSL_SECBLOCKTYPE_BIB, BSL_BLOCK_TYPE_PAYLOAD,
                         BSL_POLICYACTION_DROP_BUNDLE);
    BSLP_PolicyRule_AddParam(rule_accept_bib, &param_sha_variant);
    BSLP_PolicyRule_AddParam(rule_accept_bib, &param_scope_flag);
    BSLP_PolicyRule_AddParam(rule_accept_bib, &param_test_key_correct);

    BSLP_PolicyPredicate_t *predicate_all_appout = &policy->predicates[policy->predicate_count++];
    BSLP_PolicyPredicate_Init(predicate_all_appout, BSL_POLICYLOCATION_APPOUT,
                              BSL_TestUtils_GetEidPatternFromText("*:**"), BSL_TestUtils_GetEidPatternFromText("*:**"),
                              BSL_TestUtils_GetEidPatternFromText("*:**"));
    BSLP_PolicyRule_t *rule_source_bib = &policy->rules[policy->rule_count++];
    BSLP_PolicyRule_Init(rule_source_bib, "Create/Source BIB on appout from anywhere", predicate_all_appout, 1,
                         BSL_SECROLE_SOURCE, BSL_SECBLOCKTYPE_BIB, BSL_BLOCK_TYPE_PAYLOAD,
                         BSL_POLICYACTION_DROP_BUNDLE);
    BSLP_PolicyRule_AddParam(rule_source_bib, &param_sha_variant);
    BSLP_PolicyRule_AddParam(rule_source_bib, &param_scope_flag);
    BSLP_PolicyRule_AddParam(rule_source_bib, &param_test_key_correct);

    /// Create a rule to verify BIB's at CLA Ingress
    BSLP_PolicyPredicate_t *predicate_all_cl_in = &policy->predicates[policy->predicate_count++];
    BSLP_PolicyPredicate_Init(predicate_all_cl_in, BSL_POLICYLOCATION_CLIN, BSL_TestUtils_GetEidPatternFromText("*:**"),
                              BSL_TestUtils_GetEidPatternFromText("*:**"), BSL_TestUtils_GetEidPatternFromText("*:**"));
    BSLP_PolicyRule_t *rule_verify_bib_cl_in = &policy->rules[policy->rule_count++];
    BSLP_PolicyRule_Init(rule_verify_bib_cl_in, "Verify BIB on CL in to/from anywhere.", predicate_all_cl_in, 1,
                         BSL_SECROLE_ACCEPTOR, BSL_SECBLOCKTYPE_BIB, BSL_BLOCK_TYPE_PAYLOAD,
                         BSL_POLICYACTION_DROP_BLOCK);
    BSLP_PolicyRule_AddParam(rule_verify_bib_cl_in, &param_sha_variant);
    BSLP_PolicyRule_AddParam(rule_verify_bib_cl_in, &param_scope_flag);
    BSLP_PolicyRule_AddParam(rule_verify_bib_cl_in, &param_test_key_bad);

    /// Register the Security Context
    BSL_TestUtils_SetupDefaultSecurityContext(&LocalTestCtx.bsl);
}

void tearDown(void)
{
    mock_bpa_ctr_deinit(&LocalTestCtx.mock_bpa_ctr);
    BSL_CryptoDeinit();
    TEST_ASSERT_EQUAL(0, BSL_API_DeinitLib(&LocalTestCtx.bsl));
}

/**
 * This test reproduces RFC9173 test vector.
 *
 * 1. It loads the plan bundle from the CBOR.
 * 2. It queries security to produce the security action set
 *    (It should be populated correctly)
 * 3. It calls ApplySecurity to create the BIB block
 * 4. It confirms that it matches the output of RFC9173 test vector 1.
 */
void test_SourceSimpleBIB(void)
{
    TEST_ASSERT_EQUAL(
        0, BSL_TestUtils_LoadBundleFromCBOR(&LocalTestCtx, RFC9173_TestVectors_AppendixA1.cbor_bundle_original));

    // Ensure there's only one block (the payload block)
    BSL_PrimaryBlock_t primary_block = { 0 };
    BSL_BundleCtx_GetBundleMetadata(&LocalTestCtx.mock_bpa_ctr.bundle_ref, &primary_block);
    TEST_ASSERT_EQUAL(1, primary_block.block_count);

    BSL_SecurityActionSet_t action_set = { 0 };
    {

        // NOTE! This is an example for the BPA to use BSL
        // Query for all security operations for a particular bundle
        int query_result = BSL_API_QuerySecurity(&LocalTestCtx.bsl, &action_set, &LocalTestCtx.mock_bpa_ctr.bundle_ref,
                                                 BSL_POLICYLOCATION_APPOUT);

        TEST_ASSERT_EQUAL(0, query_result);
        // We know that it contains one operation (Add a BIB block to payload)
        TEST_ASSERT_EQUAL(1, action_set.sec_operations_count);
    }

    {
        BSL_SecurityResponseSet_t response_set = { 0 };

        // Note! This is the next part for BPA to use BSL
        // This manipulates the bundle per the policy-defined security operations
        int apply_result =
            BSL_API_ApplySecurity(&LocalTestCtx.bsl, &response_set, &LocalTestCtx.mock_bpa_ctr.bundle_ref, &action_set);

        // Ensure it returns 0 for success
        TEST_ASSERT_EQUAL(0, apply_result);

        // Now test that the BIB block is created.
        BSL_BundleCtx_GetBundleMetadata(&LocalTestCtx.mock_bpa_ctr.bundle_ref, &primary_block);
        // We confirm there are 2 canonical blocks (1 for payload, 1 for the newly created BIB block)
        TEST_ASSERT_EQUAL(2, primary_block.block_count);
    }

    // Check that it matches the RFC9173 example BIB test vector
    TEST_ASSERT_EQUAL(0, mock_bpa_encode(&LocalTestCtx.mock_bpa_ctr));
    bool is_expected = (BSL_TestUtils_IsB16StrEqualTo(RFC9173_TestVectors_AppendixA1.cbor_bundle_bib,
                                                      LocalTestCtx.mock_bpa_ctr.encoded));

    BSL_SecurityActionSet_Deinit(&action_set);

    TEST_ASSERT_TRUE(is_expected);
}

void test_API_StripBIBOnSuccess(void) {}

/**
 * Use a peculiar rule where we only remove the security's targets block if the operation failed.
 */
void test_API_RemoveFailedBlock(void)
{

    // Load a Bundle with a BIB block covering the payload from the RFC9173 examples.
    TEST_ASSERT_EQUAL(0,
                      BSL_TestUtils_LoadBundleFromCBOR(&LocalTestCtx, RFC9173_TestVectors_AppendixA1.cbor_bundle_bib));

    // First, just confirm there are two blocks (BIB and payload)
    BSL_PrimaryBlock_t primary_block = { 0 };
    BSL_BundleCtx_GetBundleMetadata(&LocalTestCtx.mock_bpa_ctr.bundle_ref, &primary_block);
    TEST_ASSERT_EQUAL(2, primary_block.block_count);

    BSL_SecurityActionSet_t action_set = { 0 };

    int query_result = BSL_API_QuerySecurity(&LocalTestCtx.bsl, &action_set, &LocalTestCtx.mock_bpa_ctr.bundle_ref,
                                             BSL_POLICYLOCATION_CLIN);

    TEST_ASSERT_EQUAL(0, query_result);
    TEST_ASSERT_EQUAL(1, action_set.sec_operations_count);

    // We know that we should expect one failure in the result.
    BSL_SecurityResponseSet_t response_set = { 0 };

    int apply_result =
        BSL_API_ApplySecurity(&LocalTestCtx.bsl, &response_set, &LocalTestCtx.mock_bpa_ctr.bundle_ref, &action_set);

    TEST_ASSERT_EQUAL(0, apply_result);
    // We purposely made a failing BIB block.
    TEST_ASSERT_EQUAL(1, response_set.failure_count);

    // Now, make sure there are no blocks! The security operation was stripped AND the target block that
    // could not be verified was stripped.
    BSL_BundleCtx_GetBundleMetadata(&LocalTestCtx.mock_bpa_ctr.bundle_ref, &primary_block);
    TEST_ASSERT_EQUAL(0, primary_block.block_count);

    BSL_SecurityActionSet_Deinit(&action_set);
}

void test_API_DropBundleOnFailedBlock(void) {}
