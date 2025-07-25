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

#define TEST_CASE(...)

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
    BSL_SecParam_InitStr(&param_test_key_correct, BSL_SECPARAM_TYPE_KEY_ID, RFC9173_EXAMPLE_A1_KEY);
    BSL_SecParam_t param_test_key_bad = { 0 };
    BSL_SecParam_InitStr(&param_test_key_bad, BSL_SECPARAM_TYPE_KEY_ID, RFC9173_EXAMPLE_A2_KEY);

    // test bib accepting with good key, bad key (drop bundle), bad key (drop block), bad key (nothing)
    // CLIN, SRC=ipn:1.1, ACCEPTOR, BIB, PAYLOAD, DROP BLOCK, good key
    BSLP_PolicyPredicate_t *predicate_1 = &policy->predicates[policy->predicate_count++];
    BSLP_PolicyPredicate_Init(predicate_1, BSL_POLICYLOCATION_CLIN,
                              BSL_TestUtils_GetEidPatternFromText("ipn:*.1.1"), BSL_TestUtils_GetEidPatternFromText("*:**"),
                              BSL_TestUtils_GetEidPatternFromText("*:**"));
    BSLP_PolicyRule_t *rule_1 = &policy->rules[policy->rule_count++];
    BSLP_PolicyRule_Init(   rule_1, "ACCEPT BIB OVER PAYLOAD AT CLIN FILTER(SRC=ipn:1.1) WITH POLICY DROP BLOCK", 
                            predicate_1, 1, BSL_SECROLE_ACCEPTOR, BSL_SECBLOCKTYPE_BIB, BSL_BLOCK_TYPE_PAYLOAD,
                            BSL_POLICYACTION_DROP_BLOCK);
    BSLP_PolicyRule_AddParam(rule_1, &param_sha_variant);
    BSLP_PolicyRule_AddParam(rule_1, &param_scope_flag);
    BSLP_PolicyRule_AddParam(rule_1, &param_test_key_correct);

    // CLIN, SRC=ipn:1.2, ACCEPTOR, BIB, PAYLOAD, DROP BUNDLE, bad key
    BSLP_PolicyPredicate_t *predicate_2 = &policy->predicates[policy->predicate_count++];
    BSLP_PolicyPredicate_Init(predicate_2, BSL_POLICYLOCATION_CLIN,
                              BSL_TestUtils_GetEidPatternFromText("ipn:*.1.2"), BSL_TestUtils_GetEidPatternFromText("*:**"),
                              BSL_TestUtils_GetEidPatternFromText("*:**"));
    BSLP_PolicyRule_t *rule_2 = &policy->rules[policy->rule_count++];
    BSLP_PolicyRule_Init(   rule_2, "ACCEPT BIB OVER PAYLOAD AT CLIN FILTER(SRC=ipn:1.2)", 
                            predicate_2, 1, BSL_SECROLE_ACCEPTOR, BSL_SECBLOCKTYPE_BIB, BSL_BLOCK_TYPE_PAYLOAD,
                            BSL_POLICYACTION_DROP_BUNDLE);
    BSLP_PolicyRule_AddParam(rule_2, &param_sha_variant);
    BSLP_PolicyRule_AddParam(rule_2, &param_scope_flag);
    BSLP_PolicyRule_AddParam(rule_2, &param_test_key_bad);


    // CLIN, SRC=ipn:1.3, ACCEPTOR, BIB, PAYLOAD, DROP BLOCK, bad key
    BSLP_PolicyPredicate_t *predicate_3 = &policy->predicates[policy->predicate_count++];
    BSLP_PolicyPredicate_Init(predicate_3, BSL_POLICYLOCATION_CLIN,
                              BSL_TestUtils_GetEidPatternFromText("ipn:*.1.3"), BSL_TestUtils_GetEidPatternFromText("*:**"),
                              BSL_TestUtils_GetEidPatternFromText("*:**"));
    BSLP_PolicyRule_t *rule_3 = &policy->rules[policy->rule_count++];
    BSLP_PolicyRule_Init(   rule_3, "ACCEPT BIB OVER PAYLOAD AT CLIN FILTER(SRC=ipn:1.3)", 
                            predicate_3, 1, BSL_SECROLE_ACCEPTOR, BSL_SECBLOCKTYPE_BIB, BSL_BLOCK_TYPE_PAYLOAD,
                            BSL_POLICYACTION_DROP_BLOCK);
    BSLP_PolicyRule_AddParam(rule_3, &param_sha_variant);
    BSLP_PolicyRule_AddParam(rule_3, &param_scope_flag);
    BSLP_PolicyRule_AddParam(rule_3, &param_test_key_bad);

    // CLIN, SRC=ipn:1.4, ACCEPTOR, BIB, PAYLOAD, NOTHING, bad key
    BSLP_PolicyPredicate_t *predicate_4 = &policy->predicates[policy->predicate_count++];
    BSLP_PolicyPredicate_Init(predicate_4, BSL_POLICYLOCATION_CLIN,
                              BSL_TestUtils_GetEidPatternFromText("ipn:*.1.4"), BSL_TestUtils_GetEidPatternFromText("*:**"),
                              BSL_TestUtils_GetEidPatternFromText("*:**"));
    BSLP_PolicyRule_t *rule_4 = &policy->rules[policy->rule_count++];
    BSLP_PolicyRule_Init(   rule_4, "ACCEPT BIB OVER PAYLOAD AT CLIN FILTER(SRC=ipn:1.4)", 
                            predicate_4, 1, BSL_SECROLE_ACCEPTOR, BSL_SECBLOCKTYPE_BIB, BSL_BLOCK_TYPE_PAYLOAD,
                            BSL_POLICYACTION_NOTHING);
    BSLP_PolicyRule_AddParam(rule_4, &param_sha_variant);
    BSLP_PolicyRule_AddParam(rule_4, &param_scope_flag);
    BSLP_PolicyRule_AddParam(rule_4, &param_test_key_bad);

    // test bcb accepting with good key, bad key (drop bundle), bad key (drop block), bad key (nothing)
    // CLIN, SRC=ipn:1.5, ACCEPTOR, BCB, PAYLOAD, DROP BLOCK, good key
    BSLP_PolicyPredicate_t *predicate_5 = &policy->predicates[policy->predicate_count++];
    BSLP_PolicyPredicate_Init(predicate_5, BSL_POLICYLOCATION_CLIN,
                              BSL_TestUtils_GetEidPatternFromText("ipn:*.1.5"), BSL_TestUtils_GetEidPatternFromText("*:**"),
                              BSL_TestUtils_GetEidPatternFromText("*:**"));
    BSLP_PolicyRule_t *rule_5 = &policy->rules[policy->rule_count++];
    BSLP_PolicyRule_Init(   rule_5, "ACCEPT BCB OVER PAYLOAD AT CLIN FILTER(SRC=ipn:1.5) WITH POLICY DROP BLOCK", 
                            predicate_5, 1, BSL_SECROLE_ACCEPTOR, BSL_SECBLOCKTYPE_BCB, BSL_BLOCK_TYPE_PAYLOAD,
                            BSL_POLICYACTION_DROP_BLOCK);
    BSLP_PolicyRule_AddParam(rule_5, &param_sha_variant);
    BSLP_PolicyRule_AddParam(rule_5, &param_scope_flag);
    BSLP_PolicyRule_AddParam(rule_5, &param_test_key_correct);

    // CLIN, SRC=ipn:1.6, ACCEPTOR, BCB, PAYLOAD, DROP BUNDLE, bad key
    BSLP_PolicyPredicate_t *predicate_6 = &policy->predicates[policy->predicate_count++];
    BSLP_PolicyPredicate_Init(predicate_6, BSL_POLICYLOCATION_CLIN,
                              BSL_TestUtils_GetEidPatternFromText("ipn:*.1.6"), BSL_TestUtils_GetEidPatternFromText("*:**"),
                              BSL_TestUtils_GetEidPatternFromText("*:**"));
    BSLP_PolicyRule_t *rule_6 = &policy->rules[policy->rule_count++];
    BSLP_PolicyRule_Init(   rule_6, "ACCEPT BCB OVER PAYLOAD AT CLIN FILTER(SRC=ipn:1.6)", 
                            predicate_6, 1, BSL_SECROLE_ACCEPTOR, BSL_SECBLOCKTYPE_BCB, BSL_BLOCK_TYPE_PAYLOAD,
                            BSL_POLICYACTION_DROP_BUNDLE);
    BSLP_PolicyRule_AddParam(rule_6, &param_sha_variant);
    BSLP_PolicyRule_AddParam(rule_6, &param_scope_flag);
    BSLP_PolicyRule_AddParam(rule_6, &param_test_key_bad);

    // CLIN, SRC=ipn:1.7, ACCEPTOR, BCB, PAYLOAD, DROP BLOCK, bad key
    BSLP_PolicyPredicate_t *predicate_7 = &policy->predicates[policy->predicate_count++];
    BSLP_PolicyPredicate_Init(predicate_7, BSL_POLICYLOCATION_CLIN,
                              BSL_TestUtils_GetEidPatternFromText("ipn:*.1.7"), BSL_TestUtils_GetEidPatternFromText("*:**"),
                              BSL_TestUtils_GetEidPatternFromText("*:**"));
    BSLP_PolicyRule_t *rule_7 = &policy->rules[policy->rule_count++];
    BSLP_PolicyRule_Init(   rule_7, "ACCEPT BCB OVER PAYLOAD AT CLIN FILTER(SRC=ipn:1.7)", 
                            predicate_7, 1, BSL_SECROLE_ACCEPTOR, BSL_SECBLOCKTYPE_BCB, BSL_BLOCK_TYPE_PAYLOAD,
                            BSL_POLICYACTION_DROP_BLOCK);
    BSLP_PolicyRule_AddParam(rule_7, &param_sha_variant);
    BSLP_PolicyRule_AddParam(rule_7, &param_scope_flag);
    BSLP_PolicyRule_AddParam(rule_7, &param_test_key_bad);

    // CLIN, SRC=ipn:1.8, ACCEPTOR, BCB, PAYLOAD, NOTHING, bad key
    BSLP_PolicyPredicate_t *predicate_8 = &policy->predicates[policy->predicate_count++];
    BSLP_PolicyPredicate_Init(predicate_8, BSL_POLICYLOCATION_CLIN,
                              BSL_TestUtils_GetEidPatternFromText("ipn:*.1.8"), BSL_TestUtils_GetEidPatternFromText("*:**"),
                              BSL_TestUtils_GetEidPatternFromText("*:**"));
    BSLP_PolicyRule_t *rule_8 = &policy->rules[policy->rule_count++];
    BSLP_PolicyRule_Init(   rule_8, "ACCEPT BCB OVER PAYLOAD AT CLIN FILTER(SRC=ipn:1.8)", 
                            predicate_8, 1, BSL_SECROLE_ACCEPTOR, BSL_SECBLOCKTYPE_BCB, BSL_BLOCK_TYPE_PAYLOAD,
                            BSL_POLICYACTION_NOTHING);
    BSLP_PolicyRule_AddParam(rule_8, &param_sha_variant);
    BSLP_PolicyRule_AddParam(rule_8, &param_scope_flag);
    BSLP_PolicyRule_AddParam(rule_8, &param_test_key_bad);

    // test bib & bcb accpeting with good key, bad key (drop bundle), bad key (drop block), bad key (nothing)
    // CLIN, SRC=ipn:1.9, ACCEPTOR, BIB, PAYLOAD, DROP BLOCK, good key
    // CLIN, SRC=ipn:1.9, ACCEPTOR, BCB, PAYLOAD, DROP BLOCK, good key
    // CLIN, SRC=ipn:1.10, ACCEPTOR, BIB, PAYLOAD, DROP BUNDLE, bad key
    // CLIN, SRC=ipn:1.10, ACCEPTOR, BCB, PAYLOAD, DROP BUNDLE, bad key
    // CLIN, SRC=ipn:1.11, ACCEPTOR, BIB, PAYLOAD, DROP BLOCK, bad key
    // CLIN, SRC=ipn:1.11, ACCEPTOR, BCB, PAYLOAD, DROP BLOCK, bad key
    // CLIN, SRC=ipn:1.12, ACCEPTOR, BIB, PAYLOAD, NOTHING, bad key
    // CLIN, SRC=ipn:1.12, ACCEPTOR, BCB, PAYLOAD, NOTHING, bad key

    // test bib sourcing with good key, bad key (drop bundle), bad key (drop block), bad key (nothing)
    // CLOUT, DEST=ipn:1.1, SOURCE, BIB, PAYLOAD, DROP BLOCK, good key
    // CLOUT, DEST=ipn:1.2, SOURCE, BIB, PAYLOAD, DROP BUNDLE, bad key
    // CLOUT, DEST=ipn:1.3, SOURCE, BIB, PAYLOAD, DROP BLOCK, bad key
    // CLOUT, DEST=ipn:1.4, SOURCE, BIB, PAYLOAD, NOTHING, bad key

    // test bcb sourcing with good key, bad key (drop bundle), bad key (drop block), bad key (nothing)
    // CLOUT, DEST=ipn:1.5, SOURCE, BCB, PAYLOAD, DROP BLOCK, good key
    // CLOUT, DEST=ipn:1.6, SOURCE, BCB, PAYLOAD, DROP BUNDLE, bad key
    // CLOUT, DEST=ipn:1.7, SOURCE, BCB, PAYLOAD, DROP BLOCK, bad key
    // CLOUT, DEST=ipn:1.8, SOURCE, BCB, PAYLOAD, NOTHING, bad key

    // test bib & bcb sourcing with good key, bad key (drop bundle), bad key (drop block), bad key (nothing)
    // CLOUT, DEST=ipn:1.9, SOURCE, BIB, PAYLOAD, DROP BLOCK, good key
    // CLOUT, DEST=ipn:1.9, SOURCE, BCB, PAYLOAD, DROP BLOCK, good key
    // CLOUT, DEST=ipn:1.10, SOURCE, BIB, PAYLOAD, DROP BUNDLE, bad key
    // CLOUT, DEST=ipn:1.10, SOURCE, BCB, PAYLOAD, DROP BUNDLE, bad key
    // CLOUT, DEST=ipn:1.11, SOURCE, BIB, PAYLOAD, DROP BLOCK, bad key
    // CLOUT, DEST=ipn:1.11, SOURCE, BCB, PAYLOAD, DROP BLOCK, bad key
    // CLOUT, DEST=ipn:1.12, SOURCE, BIB, PAYLOAD, NOTHING, bad key
    // CLOUT, DEST=ipn:1.12, SOURCE, BCB, PAYLOAD, NOTHING, bad key

    // test bib verif with good key, bad key (drop bundle), bad key (drop block), bad key (nothing)
    // APPIN, DEST=ipn:1.1, VERIF, BIB, PAYLOAD, DROP BLOCK, good key
    // APPIN, DEST=ipn:1.2, VERIF, BIB, PAYLOAD, DROP BUNDLE, bad key
    // APPIN, DEST=ipn:1.3, VERIF, BIB, PAYLOAD, DROP BLOCK, bad key
    // APPIN, DEST=ipn:1.4, VERIF, BIB, PAYLOAD, NOTHING, bad key

    // test bcb verif with good key, bad key (drop bundle), bad key (drop block), bad key (nothing)
    // APPIN, DEST=ipn:1.5, VERIF, BCB, PAYLOAD, DROP BLOCK, good key
    // APPIN, DEST=ipn:1.6, VERIF, BCB, PAYLOAD, DROP BUNDLE, bad key
    // APPIN, DEST=ipn:1.7, VERIF, BCB, PAYLOAD, DROP BLOCK, bad key
    // APPIN, DEST=ipn:1.8, VERIF, BCB, PAYLOAD, NOTHING, bad key

    // test bib & bcb verif with good key, bad key (drop bundle), bad key (drop block), bad key (nothing)
    // APPIN, DEST=ipn:1.9, VERIF, BIB, PAYLOAD, DROP BLOCK, good key
    // APPIN, DEST=ipn:1.9, VERIF, BCB, PAYLOAD, DROP BLOCK, good key
    // APPIN, DEST=ipn:1.10, VERIF, BIB, PAYLOAD, DROP BUNDLE, bad key
    // APPIN, DEST=ipn:1.10, VERIF, BCB, PAYLOAD, DROP BUNDLE, bad key
    // APPIN, DEST=ipn:1.11, VERIF, BIB, PAYLOAD, DROP BLOCK, bad key
    // APPIN, DEST=ipn:1.11, VERIF, BCB, PAYLOAD, DROP BLOCK, bad key
    // APPIN, DEST=ipn:1.12, VERIF, BIB, PAYLOAD, NOTHING, bad key
    // APPIN, DEST=ipn:1.12, VERIF, BCB, PAYLOAD, NOTHING, bad key

    // Create a rule to Accept BIB blocks on all bundle from everywhere/to everywhere at APPIN (app ingress)
    
    /*
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

    // clout: verify bib, drop bundle on fail
    BSLP_PolicyPredicate_t *predicate_app_clout_drop_bundle = &policy->predicates[policy->predicate_count++];
    BSLP_PolicyPredicate_Init(predicate_app_clout_drop_bundle, BSL_POLICYLOCATION_CLOUT, BSL_TestUtils_GetEidPatternFromText("*:**"),
                              BSL_TestUtils_GetEidPatternFromText("*:**"), BSL_TestUtils_GetEidPatternFromText("*:**"));
    BSLP_PolicyRule_t *rule_verify_bib_clout = &policy->rules[policy->rule_count++];
    BSLP_PolicyRule_Init(rule_verify_bib_clout, "Verify BIB on clout", predicate_app_clout_drop_bundle, 1,
                         BSL_SECROLE_VERIFIER, BSL_SECBLOCKTYPE_BIB, BSL_BLOCK_TYPE_PAYLOAD,
                         BSL_POLICYACTION_DROP_BLOCK);
    BSLP_PolicyRule_AddParam(rule_verify_bib_clout, &param_sha_variant);
    BSLP_PolicyRule_AddParam(rule_verify_bib_clout, &param_scope_flag);
    BSLP_PolicyRule_AddParam(rule_verify_bib_clout, &param_test_key_correct);

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

    /// Create a rule to accept BIB's at CLA Ingress
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
    */

    /// Register the Security Context
    BSL_TestUtils_SetupDefaultSecurityContext(&LocalTestCtx.bsl);
}

void tearDown(void)
{
    mock_bpa_ctr_deinit(&LocalTestCtx.mock_bpa_ctr);
    BSL_CryptoDeinit();
    TEST_ASSERT_EQUAL(0, BSL_API_DeinitLib(&LocalTestCtx.bsl));
}

TEST_CASE(BSL_POLICYLOCATION_CLIN, "ipn:1.1", NULL, NULL, BSL_SECROLE_ACCEPTOR, BSL_SECBLOCKTYPE_BIB, BSL_BLOCK_TYPE_PAYLOAD, BSL_POLICYACTION_DROP_BLOCK, true, 1, 1)
TEST_CASE(BSL_POLICYLOCATION_CLIN, "ipn:1.3", NULL, NULL, BSL_SECROLE_ACCEPTOR, BSL_SECBLOCKTYPE_BIB, BSL_BLOCK_TYPE_PAYLOAD, BSL_POLICYACTION_DROP_BLOCK, false, 1, 1)
void test_comprehensive(BSL_PolicyLocation_e policy_loc, 
    const char *src_eid, const char *dest_eid, const char *secsrc_eid, 
    BSL_SecRole_e sec_role, BSL_SecBlockType_e sec_block_type, uint8_t target_block, 
    BSL_PolicyAction_e policy_act, bool good_key, int sec_blks_ct, int expected_act_ct)
{
    (void) policy_loc;
    (void) src_eid;
    (void) dest_eid;
    (void) secsrc_eid;
    (void) sec_role;
    (void) sec_block_type;
    (void) target_block;
    (void) policy_act;
    (void) good_key;
    (void) sec_blks_ct;
    (void) expected_act_ct;

    BSL_PrimaryBlock_t primary_block = { 0 };
    BSL_SecurityActionSet_t action_set = { 0 };
    BSL_SecurityResponseSet_t response_set = { 0 };

    int query_result = -1;
    int apply_result = -1;

    switch(sec_role)
    {
        // dest [16,17].[18,19]
        // src [26,27].[28,29]
        // secsrc [36,37].[38,39]

        // ipn*.**
        case BSL_SECROLE_ACCEPTOR:
            (void) sec_role;
            char *ba = malloc(strlen(RFC9173_TestVectors_AppendixA1.cbor_bundle_bib)+1);
            strcpy(ba, RFC9173_TestVectors_AppendixA1.cbor_bundle_bib);
            if (src_eid)
            {
                int num1, num2;
                if (sscanf(src_eid, "ipn:%d.%d", &num1, &num2) != 2) {
                    printf("Invalid format.\n");
                    return;
                }

                char buf[3];
                snprintf(buf, sizeof(buf), "%02d", num1);
                ba[26] = buf[0];
                ba[27] = buf[1];

                snprintf(buf, sizeof(buf), "%02d", num2);
                ba[28] = buf[0];
                ba[29] = buf[1];

            }

            BSL_LOG_INFO("DA BUNDLE %s", ba);

            TEST_ASSERT_EQUAL(0, BSL_TestUtils_LoadBundleFromCBOR(&LocalTestCtx, ba));

            BSL_BundleCtx_GetBundleMetadata(&LocalTestCtx.mock_bpa_ctr.bundle_ref, &primary_block);
            TEST_ASSERT_EQUAL(1+sec_blks_ct, primary_block.block_count);

            query_result = BSL_API_QuerySecurity(&LocalTestCtx.bsl, &action_set, &LocalTestCtx.mock_bpa_ctr.bundle_ref, policy_loc);
            TEST_ASSERT_EQUAL(0, query_result);
            TEST_ASSERT_EQUAL(expected_act_ct, action_set.sec_operations_count);

            apply_result = BSL_API_ApplySecurity(&LocalTestCtx.bsl, &response_set, &LocalTestCtx.mock_bpa_ctr.bundle_ref, &action_set);
            TEST_ASSERT_EQUAL(0, apply_result);
            TEST_ASSERT_EQUAL((good_key) ? 0 : expected_act_ct, response_set.failure_count);

            BSL_BundleCtx_GetBundleMetadata(&LocalTestCtx.mock_bpa_ctr.bundle_ref, &primary_block);
            if (good_key)
            {
                // accepted sec blocks
                TEST_ASSERT_EQUAL(1, primary_block.block_count);
            }
            else 
            {
                if (policy_act == BSL_POLICYACTION_DROP_BLOCK)
                {
                    TEST_ASSERT_EQUAL(0, primary_block.block_count);
                }
                else if (policy_act == BSL_POLICYACTION_NOTHING)
                {
                    TEST_ASSERT_EQUAL(1+sec_blks_ct, primary_block.block_count);
                }
                else
                {
                    //TODO
                }
            }

            BSL_SecurityActionSet_Deinit(&action_set);
            free(ba);
            break;
        case BSL_SECROLE_VERIFIER:
            TEST_ASSERT_EQUAL(0, BSL_TestUtils_LoadBundleFromCBOR(&LocalTestCtx, RFC9173_TestVectors_AppendixA1.cbor_bundle_bib));

            BSL_BundleCtx_GetBundleMetadata(&LocalTestCtx.mock_bpa_ctr.bundle_ref, &primary_block);
            TEST_ASSERT_EQUAL(1+sec_blks_ct, primary_block.block_count);

            query_result = BSL_API_QuerySecurity(&LocalTestCtx.bsl, &action_set, &LocalTestCtx.mock_bpa_ctr.bundle_ref, policy_loc);
            TEST_ASSERT_EQUAL(0, query_result);
            TEST_ASSERT_EQUAL(expected_act_ct, action_set.sec_operations_count);

            apply_result = BSL_API_ApplySecurity(&LocalTestCtx.bsl, &response_set, &LocalTestCtx.mock_bpa_ctr.bundle_ref, &action_set);
            TEST_ASSERT_EQUAL(0, apply_result);
            TEST_ASSERT_EQUAL((good_key) ? 0 : expected_act_ct, response_set.failure_count);

            break;
        case BSL_SECROLE_SOURCE:
            TEST_ASSERT_EQUAL(0, BSL_TestUtils_LoadBundleFromCBOR(&LocalTestCtx, RFC9173_TestVectors_AppendixA1.cbor_bundle_original));

            BSL_BundleCtx_GetBundleMetadata(&LocalTestCtx.mock_bpa_ctr.bundle_ref, &primary_block);
            TEST_ASSERT_EQUAL(1, primary_block.block_count);

            query_result = BSL_API_QuerySecurity(&LocalTestCtx.bsl, &action_set, &LocalTestCtx.mock_bpa_ctr.bundle_ref, policy_loc);
            TEST_ASSERT_EQUAL(0, query_result);
            TEST_ASSERT_EQUAL(expected_act_ct, action_set.sec_operations_count);

            apply_result = BSL_API_ApplySecurity(&LocalTestCtx.bsl, &response_set, &LocalTestCtx.mock_bpa_ctr.bundle_ref, &action_set);
            TEST_ASSERT_EQUAL(0, apply_result);
            TEST_ASSERT_EQUAL((good_key) ? 0 : expected_act_ct, response_set.failure_count);

            break;
    }

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
/*
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

void test_API_StripBIBOnSuccess(void) 
{
    TEST_ASSERT_EQUAL(0, BSL_TestUtils_LoadBundleFromCBOR(&LocalTestCtx, RFC9173_TestVectors_AppendixA1.cbor_bundle_bib));

    BSL_PrimaryBlock_t primary_block = { 0 };
    BSL_BundleCtx_GetBundleMetadata(&LocalTestCtx.mock_bpa_ctr.bundle_ref, &primary_block);
    TEST_ASSERT_EQUAL(2, primary_block.block_count);

    // should be bib
    BSL_CanonicalBlock_t res;
    TEST_ASSERT_EQUAL(0, BSL_BundleCtx_GetBlockMetadata(&LocalTestCtx.mock_bpa_ctr.bundle_ref, 2, &res));
    TEST_ASSERT_EQUAL(11, res.type_code);

    BSL_SecurityActionSet_t action_set = { 0 };
    int query_result = BSL_API_QuerySecurity(&LocalTestCtx.bsl, &action_set, &LocalTestCtx.mock_bpa_ctr.bundle_ref, BSL_POLICYLOCATION_APPIN);

    TEST_ASSERT_EQUAL(0, query_result);
    TEST_ASSERT_EQUAL(1, action_set.sec_operations_count);

    BSL_SecurityResponseSet_t response_set = { 0 };
    int apply_result = BSL_API_ApplySecurity(&LocalTestCtx.bsl, &response_set, &LocalTestCtx.mock_bpa_ctr.bundle_ref, &action_set);

    TEST_ASSERT_EQUAL(0, apply_result);
    TEST_ASSERT_EQUAL(0, response_set.failure_count);

    for (int i = response_set.total_operations - 1; i >= 0; i--)
    {
        TEST_ASSERT_EQUAL(0, response_set.results[i]);
        BSL_LOG_INFO("PASSED RESULT %d",i);
    }

    BSL_BundleCtx_GetBundleMetadata(&LocalTestCtx.mock_bpa_ctr.bundle_ref, &primary_block);
    TEST_ASSERT_EQUAL(1, primary_block.block_count);

    // no more bib
    TEST_ASSERT_NOT_EQUAL(0, BSL_BundleCtx_GetBlockMetadata(&LocalTestCtx.mock_bpa_ctr.bundle_ref, 2, &res));

    BSL_SecurityActionSet_Deinit(&action_set);
}
*/

/**
 * Use a peculiar rule where we only remove the security's targets block if the operation failed.
 */
/*
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

void test_API_DropBundleOnFailedBlock(void) 
{

}

void test_API_SimpleBIBVerify(void) 
{
    TEST_ASSERT_EQUAL(
        0, BSL_TestUtils_LoadBundleFromCBOR(&LocalTestCtx, RFC9173_TestVectors_AppendixA1.cbor_bundle_bib));

    BSL_PrimaryBlock_t primary_block = { 0 };
    BSL_BundleCtx_GetBundleMetadata(&LocalTestCtx.mock_bpa_ctr.bundle_ref, &primary_block);
    TEST_ASSERT_EQUAL(2, primary_block.block_count);

    BSL_SecurityActionSet_t action_set = { 0 };

    int query_result = BSL_API_QuerySecurity(&LocalTestCtx.bsl, &action_set, &LocalTestCtx.mock_bpa_ctr.bundle_ref,
                                                 BSL_POLICYLOCATION_CLOUT);

    TEST_ASSERT_EQUAL(0, query_result);
    TEST_ASSERT_EQUAL(1, action_set.sec_operations_count);
    BSL_SecurityResponseSet_t response_set = { 0 };

    BSL_LOG_INFO("bipped up swagged out");

    int apply_result =
        BSL_API_ApplySecurity(&LocalTestCtx.bsl, &response_set, &LocalTestCtx.mock_bpa_ctr.bundle_ref, &action_set);

    TEST_ASSERT_EQUAL(0, apply_result);

    BSL_BundleCtx_GetBundleMetadata(&LocalTestCtx.mock_bpa_ctr.bundle_ref, &primary_block);
    TEST_ASSERT_EQUAL(2, primary_block.block_count);

    TEST_ASSERT_EQUAL(0, mock_bpa_encode(&LocalTestCtx.mock_bpa_ctr));
    bool is_expected = (BSL_TestUtils_IsB16StrEqualTo(RFC9173_TestVectors_AppendixA1.cbor_bundle_bib,
                                                      LocalTestCtx.mock_bpa_ctr.encoded));

    BSL_SecurityActionSet_Deinit(&action_set);

    TEST_ASSERT_TRUE(is_expected);
}
*/