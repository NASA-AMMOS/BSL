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

static BSL_TestContext_t       LocalTestCtx = { 0 };
static BSL_SecurityActionSet_t action_set   = { 0 };

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
    memset(&action_set, 0, sizeof(action_set));

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
    BSL_SecParam_t param_scope_flag_7 = { 0 };
    BSL_SecParam_InitInt64(&param_scope_flag_7, RFC9173_BIB_PARAMID_INTEG_SCOPE_FLAG, 0x7);
    BSL_SecParam_t param_sha_variant = { 0 };
    BSL_SecParam_InitInt64(&param_sha_variant, RFC9173_BIB_PARAMID_SHA_VARIANT, RFC9173_BIB_SHA_HMAC512);
    BSL_SecParam_t param_sha_variant_384 = { 0 };
    BSL_SecParam_InitInt64(&param_sha_variant_384, RFC9173_BIB_PARAMID_SHA_VARIANT, RFC9173_BIB_SHA_HMAC384);

    BSL_SecParam_t param_aes_variant = { 0 };
    BSL_SecParam_InitInt64(&param_aes_variant, RFC9173_BCB_SECPARAM_AESVARIANT, RFC9173_BCB_AES_VARIANT_A128GCM);
    BSL_SecParam_t param_aes_variant_256 = { 0 };
    BSL_SecParam_InitInt64(&param_aes_variant_256, RFC9173_BCB_SECPARAM_AESVARIANT, RFC9173_BCB_AES_VARIANT_A256GCM);
    BSL_SecParam_t param_aad_scope_flag = { 0 };
    BSL_SecParam_InitInt64(&param_aad_scope_flag, RFC9173_BCB_SECPARAM_AADSCOPE, 0);

    BSL_SecParam_t param_auth_tag = { 0 };
    BSL_Data_t     authtag_data;
    BSL_Data_Init(&authtag_data);
    authtag_data.ptr = (uint8_t *)ApxA2_AuthTag;
    authtag_data.len = sizeof(ApxA2_AuthTag);
    BSL_SecParam_InitBytestr(&param_auth_tag, BSL_SECPARAM_TYPE_AUTH_TAG, authtag_data);

    BSL_SecParam_t param_iv = { 0 };
    BSL_Data_t     iv_data;
    BSL_Data_Init(&iv_data);
    iv_data.ptr = (uint8_t *)ApxA2_InitVec;
    iv_data.len = sizeof(ApxA2_InitVec);
    BSL_SecParam_InitBytestr(&param_iv, RFC9173_BCB_SECPARAM_IV, iv_data);

    BSL_SecParam_t param_wrapped_key = { 0 };
    BSL_Data_t     wrapkey_data;
    BSL_Data_Init(&wrapkey_data);
    wrapkey_data.ptr = (uint8_t *)ApxA2_WrappedKey;
    wrapkey_data.len = sizeof(ApxA2_WrappedKey);
    BSL_SecParam_InitBytestr(&param_wrapped_key, RFC9173_BCB_SECPARAM_WRAPPEDKEY, wrapkey_data);

    BSL_SecParam_t param_test_bib_key_correct = { 0 };
    BSL_SecParam_InitStr(&param_test_bib_key_correct, BSL_SECPARAM_TYPE_KEY_ID, RFC9173_EXAMPLE_A1_KEY);
    BSL_SecParam_t param_test_bib_key_bad = { 0 };
    BSL_SecParam_InitStr(&param_test_bib_key_bad, BSL_SECPARAM_TYPE_KEY_ID, RFC9173_EXAMPLE_A2_KEY);
    BSL_SecParam_t param_test_bcb_key_correct = { 0 };
    BSL_SecParam_InitStr(&param_test_bcb_key_correct, BSL_SECPARAM_TYPE_KEY_ID, RFC9173_EXAMPLE_A2_KEY);
    BSL_SecParam_t param_test_bcb_key_bad = { 0 };
    BSL_SecParam_InitStr(&param_test_bcb_key_bad, BSL_SECPARAM_TYPE_KEY_ID, RFC9173_EXAMPLE_A1_KEY);
    BSL_SecParam_t param_test_bcb_2_key_correct = { 0 };
    BSL_SecParam_InitStr(&param_test_bcb_2_key_correct, BSL_SECPARAM_TYPE_KEY_ID, RFC9173_EXAMPLE_A4_BCB_KEY);
    BSL_SecParam_t param_test_bcb_2_key_bad = { 0 };
    BSL_SecParam_InitStr(&param_test_bcb_2_key_bad, BSL_SECPARAM_TYPE_KEY_ID, RFC9173_EXAMPLE_A1_KEY);

    // test bib accepting with good key, bad key (drop bundle), bad key (drop block), bad key (nothing)
    // CLIN, SRC=ipn:1.1, ACCEPTOR, BIB, PAYLOAD, DROP BLOCK, good key
    BSLP_PolicyPredicate_t *predicate_1 = &policy->predicates[policy->predicate_count++];
    BSLP_PolicyPredicate_Init(predicate_1, BSL_POLICYLOCATION_CLIN, BSL_TestUtils_GetEidPatternFromText("ipn:*.1.1"),
                              BSL_TestUtils_GetEidPatternFromText("*:**"), BSL_TestUtils_GetEidPatternFromText("*:**"));
    BSLP_PolicyRule_t *rule_1 = &policy->rules[policy->rule_count++];
    BSLP_PolicyRule_Init(rule_1, "ACCEPT BIB OVER PAYLOAD AT CLIN FILTER(SRC=ipn:1.1) WITH POLICY DROP BLOCK",
                         predicate_1, 1, BSL_SECROLE_ACCEPTOR, BSL_SECBLOCKTYPE_BIB, BSL_BLOCK_TYPE_PAYLOAD,
                         BSL_POLICYACTION_DROP_BLOCK);
    BSLP_PolicyRule_AddParam(rule_1, &param_sha_variant);
    BSLP_PolicyRule_AddParam(rule_1, &param_scope_flag);
    BSLP_PolicyRule_AddParam(rule_1, &param_test_bib_key_correct);

    // CLIN, SRC=ipn:1.2, ACCEPTOR, BIB, PAYLOAD, DROP BUNDLE, bad key
    BSLP_PolicyPredicate_t *predicate_2 = &policy->predicates[policy->predicate_count++];
    BSLP_PolicyPredicate_Init(predicate_2, BSL_POLICYLOCATION_CLIN, BSL_TestUtils_GetEidPatternFromText("ipn:*.1.2"),
                              BSL_TestUtils_GetEidPatternFromText("*:**"), BSL_TestUtils_GetEidPatternFromText("*:**"));
    BSLP_PolicyRule_t *rule_2 = &policy->rules[policy->rule_count++];
    BSLP_PolicyRule_Init(rule_2, "ACCEPT BIB OVER PAYLOAD AT CLIN FILTER(SRC=ipn:1.2)", predicate_2, 1,
                         BSL_SECROLE_ACCEPTOR, BSL_SECBLOCKTYPE_BIB, BSL_BLOCK_TYPE_PAYLOAD,
                         BSL_POLICYACTION_DROP_BUNDLE);
    BSLP_PolicyRule_AddParam(rule_2, &param_sha_variant);
    BSLP_PolicyRule_AddParam(rule_2, &param_scope_flag);
    BSLP_PolicyRule_AddParam(rule_2, &param_test_bib_key_bad);

    // CLIN, SRC=ipn:1.3, ACCEPTOR, BIB, PAYLOAD, DROP BLOCK, bad key
    BSLP_PolicyPredicate_t *predicate_3 = &policy->predicates[policy->predicate_count++];
    BSLP_PolicyPredicate_Init(predicate_3, BSL_POLICYLOCATION_CLIN, BSL_TestUtils_GetEidPatternFromText("ipn:*.1.3"),
                              BSL_TestUtils_GetEidPatternFromText("*:**"), BSL_TestUtils_GetEidPatternFromText("*:**"));
    BSLP_PolicyRule_t *rule_3 = &policy->rules[policy->rule_count++];
    BSLP_PolicyRule_Init(rule_3, "ACCEPT BIB OVER PAYLOAD AT CLIN FILTER(SRC=ipn:1.3)", predicate_3, 1,
                         BSL_SECROLE_ACCEPTOR, BSL_SECBLOCKTYPE_BIB, BSL_BLOCK_TYPE_PAYLOAD,
                         BSL_POLICYACTION_DROP_BLOCK);
    BSLP_PolicyRule_AddParam(rule_3, &param_sha_variant);
    BSLP_PolicyRule_AddParam(rule_3, &param_scope_flag);
    BSLP_PolicyRule_AddParam(rule_3, &param_test_bib_key_bad);

    // CLIN, SRC=ipn:1.4, ACCEPTOR, BIB, PAYLOAD, NOTHING, bad key
    BSLP_PolicyPredicate_t *predicate_4 = &policy->predicates[policy->predicate_count++];
    BSLP_PolicyPredicate_Init(predicate_4, BSL_POLICYLOCATION_CLIN, BSL_TestUtils_GetEidPatternFromText("ipn:*.1.4"),
                              BSL_TestUtils_GetEidPatternFromText("*:**"), BSL_TestUtils_GetEidPatternFromText("*:**"));
    BSLP_PolicyRule_t *rule_4 = &policy->rules[policy->rule_count++];
    BSLP_PolicyRule_Init(rule_4, "ACCEPT BIB OVER PAYLOAD AT CLIN FILTER(SRC=ipn:1.4)", predicate_4, 1,
                         BSL_SECROLE_ACCEPTOR, BSL_SECBLOCKTYPE_BIB, BSL_BLOCK_TYPE_PAYLOAD, BSL_POLICYACTION_NOTHING);
    BSLP_PolicyRule_AddParam(rule_4, &param_sha_variant);
    BSLP_PolicyRule_AddParam(rule_4, &param_scope_flag);
    BSLP_PolicyRule_AddParam(rule_4, &param_test_bib_key_bad);

    // test bcb accepting with good key, bad key (drop bundle), bad key (drop block), bad key (nothing)
    // CLIN, SRC=ipn:1.5, ACCEPTOR, BCB, PAYLOAD, DROP BLOCK, good key
    BSLP_PolicyPredicate_t *predicate_5 = &policy->predicates[policy->predicate_count++];
    BSLP_PolicyPredicate_Init(predicate_5, BSL_POLICYLOCATION_CLIN, BSL_TestUtils_GetEidPatternFromText("ipn:*.1.5"),
                              BSL_TestUtils_GetEidPatternFromText("*:**"), BSL_TestUtils_GetEidPatternFromText("*:**"));
    BSLP_PolicyRule_t *rule_5 = &policy->rules[policy->rule_count++];
    BSLP_PolicyRule_Init(rule_5, "ACCEPT BCB OVER PAYLOAD AT CLIN FILTER(SRC=ipn:1.5) WITH POLICY DROP BLOCK",
                         predicate_5, 2, BSL_SECROLE_ACCEPTOR, BSL_SECBLOCKTYPE_BCB, BSL_BLOCK_TYPE_PAYLOAD,
                         BSL_POLICYACTION_DROP_BLOCK);
    BSLP_PolicyRule_AddParam(rule_5, &param_test_bcb_key_correct);
    BSLP_PolicyRule_AddParam(rule_5, &param_iv);
    BSLP_PolicyRule_AddParam(rule_5, &param_wrapped_key);
    BSLP_PolicyRule_AddParam(rule_5, &param_auth_tag);
    BSLP_PolicyRule_AddParam(rule_5, &param_aes_variant);

    // CLIN, SRC=ipn:1.6, ACCEPTOR, BCB, PAYLOAD, DROP BUNDLE, bad key
    BSLP_PolicyPredicate_t *predicate_6 = &policy->predicates[policy->predicate_count++];
    BSLP_PolicyPredicate_Init(predicate_6, BSL_POLICYLOCATION_CLIN, BSL_TestUtils_GetEidPatternFromText("ipn:*.1.6"),
                              BSL_TestUtils_GetEidPatternFromText("*:**"), BSL_TestUtils_GetEidPatternFromText("*:**"));
    BSLP_PolicyRule_t *rule_6 = &policy->rules[policy->rule_count++];
    BSLP_PolicyRule_Init(rule_6, "ACCEPT BCB OVER PAYLOAD AT CLIN FILTER(SRC=ipn:1.6)", predicate_6, 2,
                         BSL_SECROLE_ACCEPTOR, BSL_SECBLOCKTYPE_BCB, BSL_BLOCK_TYPE_PAYLOAD,
                         BSL_POLICYACTION_DROP_BUNDLE);
    BSLP_PolicyRule_AddParam(rule_6, &param_test_bcb_key_bad);
    BSLP_PolicyRule_AddParam(rule_6, &param_iv);
    BSLP_PolicyRule_AddParam(rule_6, &param_wrapped_key);
    BSLP_PolicyRule_AddParam(rule_6, &param_auth_tag);
    BSLP_PolicyRule_AddParam(rule_6, &param_aes_variant);

    // CLIN, SRC=ipn:1.7, ACCEPTOR, BCB, PAYLOAD, DROP BLOCK, bad key
    BSLP_PolicyPredicate_t *predicate_7 = &policy->predicates[policy->predicate_count++];
    BSLP_PolicyPredicate_Init(predicate_7, BSL_POLICYLOCATION_CLIN, BSL_TestUtils_GetEidPatternFromText("ipn:*.1.7"),
                              BSL_TestUtils_GetEidPatternFromText("*:**"), BSL_TestUtils_GetEidPatternFromText("*:**"));
    BSLP_PolicyRule_t *rule_7 = &policy->rules[policy->rule_count++];
    BSLP_PolicyRule_Init(rule_7, "ACCEPT BCB OVER PAYLOAD AT CLIN FILTER(SRC=ipn:1.7)", predicate_7, 2,
                         BSL_SECROLE_ACCEPTOR, BSL_SECBLOCKTYPE_BCB, BSL_BLOCK_TYPE_PAYLOAD,
                         BSL_POLICYACTION_DROP_BLOCK);
    BSLP_PolicyRule_AddParam(rule_7, &param_test_bcb_key_bad);
    BSLP_PolicyRule_AddParam(rule_7, &param_iv);
    BSLP_PolicyRule_AddParam(rule_7, &param_wrapped_key);
    BSLP_PolicyRule_AddParam(rule_7, &param_auth_tag);
    BSLP_PolicyRule_AddParam(rule_7, &param_aes_variant);

    // CLIN, SRC=ipn:1.8, ACCEPTOR, BCB, PAYLOAD, NOTHING, bad key
    BSLP_PolicyPredicate_t *predicate_8 = &policy->predicates[policy->predicate_count++];
    BSLP_PolicyPredicate_Init(predicate_8, BSL_POLICYLOCATION_CLIN, BSL_TestUtils_GetEidPatternFromText("ipn:*.1.8"),
                              BSL_TestUtils_GetEidPatternFromText("*:**"), BSL_TestUtils_GetEidPatternFromText("*:**"));
    BSLP_PolicyRule_t *rule_8 = &policy->rules[policy->rule_count++];
    BSLP_PolicyRule_Init(rule_8, "ACCEPT BCB OVER PAYLOAD AT CLIN FILTER(SRC=ipn:1.8)", predicate_8, 2,
                         BSL_SECROLE_ACCEPTOR, BSL_SECBLOCKTYPE_BCB, BSL_BLOCK_TYPE_PAYLOAD, BSL_POLICYACTION_NOTHING);
    BSLP_PolicyRule_AddParam(rule_8, &param_test_bcb_key_bad);
    BSLP_PolicyRule_AddParam(rule_8, &param_iv);
    BSLP_PolicyRule_AddParam(rule_8, &param_wrapped_key);
    BSLP_PolicyRule_AddParam(rule_8, &param_auth_tag);
    BSLP_PolicyRule_AddParam(rule_8, &param_aes_variant);

    // test bib & bcb accpeting with good key, bad key (drop bundle), bad key (drop block), bad key (nothing)
    // CLIN, SRC=ipn:1.9, ACCEPTOR, BIB, PAYLOAD, DROP BLOCK, good key
    // CLIN, SRC=ipn:1.9, ACCEPTOR, BCB, PAYLOAD, DROP BLOCK, good key
    BSLP_PolicyPredicate_t *predicate_9a = &policy->predicates[policy->predicate_count++];
    BSLP_PolicyPredicate_Init(predicate_9a, BSL_POLICYLOCATION_CLIN, BSL_TestUtils_GetEidPatternFromText("ipn:*.1.9"),
                              BSL_TestUtils_GetEidPatternFromText("*:**"), BSL_TestUtils_GetEidPatternFromText("*:**"));
    BSLP_PolicyRule_t *rule_9a = &policy->rules[policy->rule_count++];
    BSLP_PolicyRule_Init(rule_9a, "ACCEPT BIB OVER PAYLOAD AT CLIN FILTER(SRC=ipn:1.9) WITH POLICY DROP BLOCK",
                         predicate_9a, 1, BSL_SECROLE_ACCEPTOR, BSL_SECBLOCKTYPE_BIB, BSL_BLOCK_TYPE_PAYLOAD,
                         BSL_POLICYACTION_DROP_BLOCK);
    BSLP_PolicyRule_AddParam(rule_9a, &param_sha_variant);
    BSLP_PolicyRule_AddParam(rule_9a, &param_scope_flag);
    BSLP_PolicyRule_AddParam(rule_9a, &param_test_bib_key_correct);

    BSLP_PolicyPredicate_t *predicate_9b = &policy->predicates[policy->predicate_count++];
    BSLP_PolicyPredicate_Init(predicate_9b, BSL_POLICYLOCATION_CLIN, BSL_TestUtils_GetEidPatternFromText("ipn:*.1.9"),
                              BSL_TestUtils_GetEidPatternFromText("*:**"), BSL_TestUtils_GetEidPatternFromText("*:**"));
    BSLP_PolicyRule_t *rule_9b = &policy->rules[policy->rule_count++];
    BSLP_PolicyRule_Init(rule_9b, "ACCEPT BCB OVER PAYLOAD AT CLIN FILTER(SRC=ipn:1.9) WITH POLICY DROP BLOCK",
                         predicate_9b, 2, BSL_SECROLE_ACCEPTOR, BSL_SECBLOCKTYPE_BCB, BSL_BLOCK_TYPE_PAYLOAD,
                         BSL_POLICYACTION_DROP_BLOCK);
    BSLP_PolicyRule_AddParam(rule_9b, &param_test_bcb_key_correct);
    BSLP_PolicyRule_AddParam(rule_9b, &param_iv);
    BSLP_PolicyRule_AddParam(rule_9b, &param_wrapped_key);
    BSLP_PolicyRule_AddParam(rule_9b, &param_auth_tag);
    BSLP_PolicyRule_AddParam(rule_9b, &param_aes_variant);

    // test bib sourcing with good key
    // CLOUT, DEST=ipn:1.1, SOURCE, BIB, PAYLOAD, DROP BLOCK, good key
    BSLP_PolicyPredicate_t *predicate_13 = &policy->predicates[policy->predicate_count++];
    BSLP_PolicyPredicate_Init(predicate_13, BSL_POLICYLOCATION_CLOUT, BSL_TestUtils_GetEidPatternFromText("*:**"),
                              BSL_TestUtils_GetEidPatternFromText("*:**"),
                              BSL_TestUtils_GetEidPatternFromText("ipn:*.1.1"));
    BSLP_PolicyRule_t *rule_13 = &policy->rules[policy->rule_count++];
    BSLP_PolicyRule_Init(rule_13, "SOURCE BIB OVER PAYLOAD AT CLOUT FILTER(DEST=ipn:1.1) WITH POLICY DROP BLOCK",
                         predicate_13, 1, BSL_SECROLE_SOURCE, BSL_SECBLOCKTYPE_BIB, BSL_BLOCK_TYPE_PAYLOAD,
                         BSL_POLICYACTION_DROP_BLOCK);
    BSLP_PolicyRule_AddParam(rule_13, &param_sha_variant);
    BSLP_PolicyRule_AddParam(rule_13, &param_scope_flag);
    BSLP_PolicyRule_AddParam(rule_13, &param_test_bib_key_correct);

    // test bcb sourcing with good key
    // CLOUT, DEST=ipn:1.5, SOURCE, BCB, PAYLOAD, DROP BLOCK, good key
    BSLP_PolicyPredicate_t *predicate_14 = &policy->predicates[policy->predicate_count++];
    BSLP_PolicyPredicate_Init(predicate_14, BSL_POLICYLOCATION_CLOUT, BSL_TestUtils_GetEidPatternFromText("*:**"),
                              BSL_TestUtils_GetEidPatternFromText("*:**"),
                              BSL_TestUtils_GetEidPatternFromText("ipn:*.1.5"));
    BSLP_PolicyRule_t *rule_14 = &policy->rules[policy->rule_count++];
    BSLP_PolicyRule_Init(rule_14, "SOURCE BCB OVER PAYLOAD AT CLOUT FILTER(DEST=ipn:1.5)", predicate_14, 2,
                         BSL_SECROLE_SOURCE, BSL_SECBLOCKTYPE_BCB, BSL_BLOCK_TYPE_PAYLOAD, BSL_POLICYACTION_DROP_BLOCK);
    BSLP_PolicyRule_AddParam(rule_14, &param_test_bcb_key_correct);
    BSLP_PolicyRule_AddParam(rule_14, &param_aes_variant);

    // test bib & bcb sourcing with good key
    // CLOUT, DEST=ipn:1.9, SOURCE, BIB, PAYLOAD, DROP BLOCK, good key
    // CLOUT, DEST=ipn:1.9, SOURCE, BCB, PAYLOAD, DROP BLOCK, good key
    BSLP_PolicyPredicate_t *predicate_15a = &policy->predicates[policy->predicate_count++];
    BSLP_PolicyPredicate_Init(predicate_15a, BSL_POLICYLOCATION_CLOUT, BSL_TestUtils_GetEidPatternFromText("*:**"),
                              BSL_TestUtils_GetEidPatternFromText("*:**"),
                              BSL_TestUtils_GetEidPatternFromText("ipn:*.1.9"));
    BSLP_PolicyRule_t *rule_15a = &policy->rules[policy->rule_count++];
    BSLP_PolicyRule_Init(rule_15a, "SOURCE BIB OVER PAYLOAD AT CLOUT FILTER(DEST=ipn:1.9) WITH POLICY DROP BLOCK",
                         predicate_15a, 1, BSL_SECROLE_SOURCE, BSL_SECBLOCKTYPE_BIB, BSL_BLOCK_TYPE_PAYLOAD,
                         BSL_POLICYACTION_DROP_BLOCK);
    BSLP_PolicyRule_AddParam(rule_15a, &param_sha_variant_384);
    BSLP_PolicyRule_AddParam(rule_15a, &param_scope_flag_7);
    BSLP_PolicyRule_AddParam(rule_15a, &param_test_bib_key_correct);

    BSLP_PolicyPredicate_t *predicate_15b = &policy->predicates[policy->predicate_count++];
    BSLP_PolicyPredicate_Init(predicate_15b, BSL_POLICYLOCATION_CLOUT, BSL_TestUtils_GetEidPatternFromText("*:**"),
                              BSL_TestUtils_GetEidPatternFromText("*:**"),
                              BSL_TestUtils_GetEidPatternFromText("ipn:*.1.9"));
    BSLP_PolicyRule_t *rule_15b = &policy->rules[policy->rule_count++];
    BSLP_PolicyRule_Init(rule_15b, "SOURCE BCB OVER PAYLOAD AT CLOUT FILTER(DEST=ipn:1.9)", predicate_15b, 2,
                         BSL_SECROLE_SOURCE, BSL_SECBLOCKTYPE_BCB, BSL_BLOCK_TYPE_PAYLOAD, BSL_POLICYACTION_DROP_BLOCK);
    BSLP_PolicyRule_AddParam(rule_15b, &param_test_bcb_2_key_correct);
    BSLP_PolicyRule_AddParam(rule_15b, &param_aes_variant_256);

    // test bib verif with good key, bad key (drop bundle), bad key (drop block), bad key (nothing)
    // APPIN, DEST=ipn:1.1, VERIF, BIB, PAYLOAD, DROP BLOCK, good key
    BSLP_PolicyPredicate_t *predicate_17 = &policy->predicates[policy->predicate_count++];
    BSLP_PolicyPredicate_Init(predicate_17, BSL_POLICYLOCATION_APPIN, BSL_TestUtils_GetEidPatternFromText("*:**"),
                              BSL_TestUtils_GetEidPatternFromText("*:**"),
                              BSL_TestUtils_GetEidPatternFromText("ipn:*.1.1"));
    BSLP_PolicyRule_t *rule_17 = &policy->rules[policy->rule_count++];
    BSLP_PolicyRule_Init(rule_17, "VERIFY BCB OVER PAYLOAD AT APPIN FILTER(DEST=ipn:1.1)", predicate_17, 1,
                         BSL_SECROLE_VERIFIER, BSL_SECBLOCKTYPE_BIB, BSL_BLOCK_TYPE_PAYLOAD,
                         BSL_POLICYACTION_DROP_BLOCK);
    BSLP_PolicyRule_AddParam(rule_17, &param_sha_variant);
    BSLP_PolicyRule_AddParam(rule_17, &param_scope_flag);
    BSLP_PolicyRule_AddParam(rule_17, &param_test_bib_key_correct);

    // APPIN, DEST=ipn:1.2, VERIF, BIB, PAYLOAD, DROP BUNDLE, bad key
    BSLP_PolicyPredicate_t *predicate_18 = &policy->predicates[policy->predicate_count++];
    BSLP_PolicyPredicate_Init(predicate_18, BSL_POLICYLOCATION_APPIN, BSL_TestUtils_GetEidPatternFromText("*:**"),
                              BSL_TestUtils_GetEidPatternFromText("*:**"),
                              BSL_TestUtils_GetEidPatternFromText("ipn:*.1.2"));
    BSLP_PolicyRule_t *rule_18 = &policy->rules[policy->rule_count++];
    BSLP_PolicyRule_Init(rule_18, "VERIFY BCB OVER PAYLOAD AT APPIN FILTER(DEST=ipn:1.2)", predicate_18, 1,
                         BSL_SECROLE_VERIFIER, BSL_SECBLOCKTYPE_BIB, BSL_BLOCK_TYPE_PAYLOAD,
                         BSL_POLICYACTION_DROP_BUNDLE);
    BSLP_PolicyRule_AddParam(rule_18, &param_sha_variant);
    BSLP_PolicyRule_AddParam(rule_18, &param_scope_flag);
    BSLP_PolicyRule_AddParam(rule_18, &param_test_bib_key_bad);

    // APPIN, DEST=ipn:1.3, VERIF, BIB, PAYLOAD, DROP BLOCK, bad key
    BSLP_PolicyPredicate_t *predicate_19 = &policy->predicates[policy->predicate_count++];
    BSLP_PolicyPredicate_Init(predicate_19, BSL_POLICYLOCATION_APPIN, BSL_TestUtils_GetEidPatternFromText("*:**"),
                              BSL_TestUtils_GetEidPatternFromText("*:**"),
                              BSL_TestUtils_GetEidPatternFromText("ipn:*.1.3"));
    BSLP_PolicyRule_t *rule_19 = &policy->rules[policy->rule_count++];
    BSLP_PolicyRule_Init(rule_19, "VERIFY BCB OVER PAYLOAD AT APPIN FILTER(DEST=ipn:1.3)", predicate_19, 1,
                         BSL_SECROLE_VERIFIER, BSL_SECBLOCKTYPE_BIB, BSL_BLOCK_TYPE_PAYLOAD,
                         BSL_POLICYACTION_DROP_BLOCK);
    BSLP_PolicyRule_AddParam(rule_19, &param_sha_variant);
    BSLP_PolicyRule_AddParam(rule_19, &param_scope_flag);
    BSLP_PolicyRule_AddParam(rule_19, &param_test_bib_key_bad);

    // APPIN, DEST=ipn:1.4, VERIF, BIB, PAYLOAD, NOTHING, bad key
    BSLP_PolicyPredicate_t *predicate_20 = &policy->predicates[policy->predicate_count++];
    BSLP_PolicyPredicate_Init(predicate_20, BSL_POLICYLOCATION_APPIN, BSL_TestUtils_GetEidPatternFromText("*:**"),
                              BSL_TestUtils_GetEidPatternFromText("*:**"),
                              BSL_TestUtils_GetEidPatternFromText("ipn:*.1.4"));
    BSLP_PolicyRule_t *rule_20 = &policy->rules[policy->rule_count++];
    BSLP_PolicyRule_Init(rule_20, "VERIFY BCB OVER PAYLOAD AT APPIN FILTER(DEST=ipn:1.4)", predicate_20, 1,
                         BSL_SECROLE_VERIFIER, BSL_SECBLOCKTYPE_BIB, BSL_BLOCK_TYPE_PAYLOAD, BSL_POLICYACTION_NOTHING);
    BSLP_PolicyRule_AddParam(rule_20, &param_sha_variant);
    BSLP_PolicyRule_AddParam(rule_20, &param_scope_flag);
    BSLP_PolicyRule_AddParam(rule_20, &param_test_bib_key_bad);

    // test bcb verif with good key, bad key (drop bundle), bad key (drop block), bad key (nothing)
    // APPIN, DEST=ipn:1.5, VERIF, BCB, PAYLOAD, DROP BLOCK, good key
    BSLP_PolicyPredicate_t *predicate_21 = &policy->predicates[policy->predicate_count++];
    BSLP_PolicyPredicate_Init(predicate_21, BSL_POLICYLOCATION_APPIN, BSL_TestUtils_GetEidPatternFromText("*:**"),
                              BSL_TestUtils_GetEidPatternFromText("*:**"),
                              BSL_TestUtils_GetEidPatternFromText("ipn:*.1.5"));
    BSLP_PolicyRule_t *rule_21 = &policy->rules[policy->rule_count++];
    BSLP_PolicyRule_Init(rule_21, "VERIFY BCB OVER PAYLOAD AT APPIN FILTER(DEST=ipn:1.5)", predicate_21, 2,
                         BSL_SECROLE_VERIFIER, BSL_SECBLOCKTYPE_BCB, BSL_BLOCK_TYPE_PAYLOAD,
                         BSL_POLICYACTION_DROP_BLOCK);
    BSLP_PolicyRule_AddParam(rule_21, &param_test_bcb_key_correct);
    BSLP_PolicyRule_AddParam(rule_21, &param_iv);
    BSLP_PolicyRule_AddParam(rule_21, &param_wrapped_key);
    BSLP_PolicyRule_AddParam(rule_21, &param_auth_tag);
    BSLP_PolicyRule_AddParam(rule_21, &param_aes_variant);

    // APPIN, DEST=ipn:1.6, VERIF, BCB, PAYLOAD, DROP BUNDLE, bad key
    BSLP_PolicyPredicate_t *predicate_22 = &policy->predicates[policy->predicate_count++];
    BSLP_PolicyPredicate_Init(predicate_22, BSL_POLICYLOCATION_APPIN, BSL_TestUtils_GetEidPatternFromText("*:**"),
                              BSL_TestUtils_GetEidPatternFromText("*:**"),
                              BSL_TestUtils_GetEidPatternFromText("ipn:*.1.6"));
    BSLP_PolicyRule_t *rule_22 = &policy->rules[policy->rule_count++];
    BSLP_PolicyRule_Init(rule_22, "VERIFY BCB OVER PAYLOAD AT APPIN FILTER(DEST=ipn:1.6)", predicate_22, 2,
                         BSL_SECROLE_VERIFIER, BSL_SECBLOCKTYPE_BCB, BSL_BLOCK_TYPE_PAYLOAD,
                         BSL_POLICYACTION_DROP_BUNDLE);
    BSLP_PolicyRule_AddParam(rule_22, &param_test_bcb_key_bad);
    BSLP_PolicyRule_AddParam(rule_22, &param_iv);
    BSLP_PolicyRule_AddParam(rule_22, &param_wrapped_key);
    BSLP_PolicyRule_AddParam(rule_22, &param_auth_tag);
    BSLP_PolicyRule_AddParam(rule_22, &param_aes_variant);

    // APPIN, DEST=ipn:1.7, VERIF, BCB, PAYLOAD, DROP BLOCK, bad key
    BSLP_PolicyPredicate_t *predicate_23 = &policy->predicates[policy->predicate_count++];
    BSLP_PolicyPredicate_Init(predicate_23, BSL_POLICYLOCATION_APPIN, BSL_TestUtils_GetEidPatternFromText("*:**"),
                              BSL_TestUtils_GetEidPatternFromText("*:**"),
                              BSL_TestUtils_GetEidPatternFromText("ipn:*.1.7"));
    BSLP_PolicyRule_t *rule_23 = &policy->rules[policy->rule_count++];
    BSLP_PolicyRule_Init(rule_23, "VERIFY BCB OVER PAYLOAD AT APPIN FILTER(DEST=ipn:1.7)", predicate_23, 2,
                         BSL_SECROLE_VERIFIER, BSL_SECBLOCKTYPE_BCB, BSL_BLOCK_TYPE_PAYLOAD,
                         BSL_POLICYACTION_DROP_BLOCK);
    BSLP_PolicyRule_AddParam(rule_23, &param_test_bcb_key_bad);
    BSLP_PolicyRule_AddParam(rule_23, &param_iv);
    BSLP_PolicyRule_AddParam(rule_23, &param_wrapped_key);
    BSLP_PolicyRule_AddParam(rule_23, &param_auth_tag);
    BSLP_PolicyRule_AddParam(rule_23, &param_aes_variant);

    // APPIN, DEST=ipn:1.8, VERIF, BCB, PAYLOAD, NOTHING, bad key
    BSLP_PolicyPredicate_t *predicate_24 = &policy->predicates[policy->predicate_count++];
    BSLP_PolicyPredicate_Init(predicate_24, BSL_POLICYLOCATION_APPIN, BSL_TestUtils_GetEidPatternFromText("*:**"),
                              BSL_TestUtils_GetEidPatternFromText("*:**"),
                              BSL_TestUtils_GetEidPatternFromText("ipn:*.1.8"));
    BSLP_PolicyRule_t *rule_24 = &policy->rules[policy->rule_count++];
    BSLP_PolicyRule_Init(rule_24, "VERIFY BCB OVER PAYLOAD AT APPIN FILTER(DEST=ipn:1.8)", predicate_24, 2,
                         BSL_SECROLE_VERIFIER, BSL_SECBLOCKTYPE_BCB, BSL_BLOCK_TYPE_PAYLOAD, BSL_POLICYACTION_NOTHING);
    BSLP_PolicyRule_AddParam(rule_24, &param_test_bcb_key_bad);
    BSLP_PolicyRule_AddParam(rule_24, &param_iv);
    BSLP_PolicyRule_AddParam(rule_24, &param_wrapped_key);
    BSLP_PolicyRule_AddParam(rule_24, &param_auth_tag);
    BSLP_PolicyRule_AddParam(rule_24, &param_aes_variant);

    // test bib & bcb verif with good key, bad key (drop bundle), bad key (drop block), bad key (nothing)
    // APPIN, DEST=ipn:1.9, VERIF, BIB, PAYLOAD, DROP BLOCK, good key
    // APPIN, DEST=ipn:1.9, VERIF, BCB, PAYLOAD, DROP BLOCK, good key
    BSLP_PolicyPredicate_t *predicate_25a = &policy->predicates[policy->predicate_count++];
    BSLP_PolicyPredicate_Init(predicate_25a, BSL_POLICYLOCATION_APPIN, BSL_TestUtils_GetEidPatternFromText("*:**"),
                              BSL_TestUtils_GetEidPatternFromText("*:**"),
                              BSL_TestUtils_GetEidPatternFromText("ipn:*.1.9"));
    BSLP_PolicyRule_t *rule_25a = &policy->rules[policy->rule_count++];
    BSLP_PolicyRule_Init(rule_25a, "VERIFY BCB OVER PAYLOAD AT APPIN FILTER(DEST=ipn:1.9)", predicate_25a, 1,
                         BSL_SECROLE_VERIFIER, BSL_SECBLOCKTYPE_BIB, BSL_BLOCK_TYPE_PAYLOAD,
                         BSL_POLICYACTION_DROP_BLOCK);
    BSLP_PolicyRule_AddParam(rule_25a, &param_sha_variant);
    BSLP_PolicyRule_AddParam(rule_25a, &param_scope_flag);
    BSLP_PolicyRule_AddParam(rule_25a, &param_test_bib_key_correct);

    BSLP_PolicyPredicate_t *predicate_25b = &policy->predicates[policy->predicate_count++];
    BSLP_PolicyPredicate_Init(predicate_25b, BSL_POLICYLOCATION_APPIN, BSL_TestUtils_GetEidPatternFromText("*:**"),
                              BSL_TestUtils_GetEidPatternFromText("*:**"),
                              BSL_TestUtils_GetEidPatternFromText("ipn:*.1.9"));
    BSLP_PolicyRule_t *rule_25b = &policy->rules[policy->rule_count++];
    BSLP_PolicyRule_Init(rule_25b, "VERIFY BCB OVER PAYLOAD AT APPIN FILTER(DEST=ipn:1.9)", predicate_25b, 2,
                         BSL_SECROLE_VERIFIER, BSL_SECBLOCKTYPE_BCB, BSL_BLOCK_TYPE_PAYLOAD,
                         BSL_POLICYACTION_DROP_BLOCK);
    BSLP_PolicyRule_AddParam(rule_25b, &param_test_bcb_key_correct);
    BSLP_PolicyRule_AddParam(rule_25b, &param_iv);
    BSLP_PolicyRule_AddParam(rule_25b, &param_wrapped_key);
    BSLP_PolicyRule_AddParam(rule_25b, &param_auth_tag);
    BSLP_PolicyRule_AddParam(rule_25b, &param_aes_variant);

    // BSL 6
    BSLP_PolicyPredicate_t *predicate_bsl_6 = &policy->predicates[policy->predicate_count++];
    BSLP_PolicyPredicate_Init(predicate_bsl_6, BSL_POLICYLOCATION_CLOUT, BSL_TestUtils_GetEidPatternFromText("*:**"),
                              BSL_TestUtils_GetEidPatternFromText("*:**"),
                              BSL_TestUtils_GetEidPatternFromText("ipn:*.0.6"));
    BSLP_PolicyRule_t *rule_bsl_6 = &policy->rules[policy->rule_count++];
    BSLP_PolicyRule_Init(rule_bsl_6, "SOURCE BIB OVER PAYLOAD AT CLOUT FILTER(DEST=ipn:0.6) WITH POLICY DROP BLOCK",
                         predicate_bsl_6, 1, BSL_SECROLE_SOURCE, BSL_SECBLOCKTYPE_BIB, BSL_BLOCK_TYPE_PAYLOAD,
                         BSL_POLICYACTION_DROP_BLOCK);
    BSLP_PolicyRule_AddParam(rule_bsl_6, &param_sha_variant);
    BSLP_PolicyRule_AddParam(rule_bsl_6, &param_scope_flag);
    BSLP_PolicyRule_AddParam(rule_bsl_6, &param_test_bib_key_correct);

    // BSL_32
    BSLP_PolicyPredicate_t *predicate_bsl_32a = &policy->predicates[policy->predicate_count++];
    BSLP_PolicyPredicate_Init(predicate_bsl_32a, BSL_POLICYLOCATION_CLOUT, BSL_TestUtils_GetEidPatternFromText("*:**"),
                              BSL_TestUtils_GetEidPatternFromText("*:**"),
                              BSL_TestUtils_GetEidPatternFromText("ipn:*.3.2"));
    BSLP_PolicyRule_t *rule_bsl_32a = &policy->rules[policy->rule_count++];
    BSLP_PolicyRule_Init(rule_bsl_32a, "SOURCE BCB OVER PAYLOAD AT CLOUT FILTER(DEST=ipn:3.2)", predicate_bsl_32a, 2,
                         BSL_SECROLE_SOURCE, BSL_SECBLOCKTYPE_BCB, BSL_BLOCK_TYPE_PAYLOAD, BSL_POLICYACTION_DROP_BLOCK);
    BSLP_PolicyRule_AddParam(rule_bsl_32a, &param_test_bcb_key_correct);
    BSLP_PolicyRule_AddParam(rule_bsl_32a, &param_aes_variant);

    BSLP_PolicyPredicate_t *predicate_bsl_32b = &policy->predicates[policy->predicate_count++];
    BSLP_PolicyPredicate_Init(predicate_bsl_32b, BSL_POLICYLOCATION_CLOUT, BSL_TestUtils_GetEidPatternFromText("*:**"),
                              BSL_TestUtils_GetEidPatternFromText("*:**"),
                              BSL_TestUtils_GetEidPatternFromText("ipn:*.3.2"));
    BSLP_PolicyRule_t *rule_bsl_32b = &policy->rules[policy->rule_count++];
    BSLP_PolicyRule_Init(rule_bsl_32b, "SOURCE BCB OVER BIB AT CLOUT FILTER(DEST=ipn:3.2)", predicate_bsl_32b, 2,
                         BSL_SECROLE_SOURCE, BSL_SECBLOCKTYPE_BCB, BSL_BLOCK_TYPE_BIB, BSL_POLICYACTION_DROP_BLOCK);
    BSLP_PolicyRule_AddParam(rule_bsl_32b, &param_test_bcb_key_correct);
    BSLP_PolicyRule_AddParam(rule_bsl_32b, &param_aes_variant);

    /// Register the Security Context
    BSL_TestUtils_SetupDefaultSecurityContext(&LocalTestCtx.bsl);
}

void tearDown(void)
{
    BSL_SecurityActionSet_Deinit(&action_set);
    mock_bpa_ctr_deinit(&LocalTestCtx.mock_bpa_ctr);
    BSL_CryptoDeinit();
    TEST_ASSERT_EQUAL(0, BSL_API_DeinitLib(&LocalTestCtx.bsl));
}

#define TEST_BOTH_BIB_BCB 99

// All DROP_BUNDLE failing pending #12,#29
TEST_CASE(BSL_POLICYLOCATION_CLIN, "ipn:1.1", NULL, NULL, BSL_SECROLE_ACCEPTOR, BSL_SECBLOCKTYPE_BIB, BSL_BLOCK_TYPE_PAYLOAD, BSL_POLICYACTION_DROP_BLOCK, true, 1, 1) // PASS
TEST_CASE(BSL_POLICYLOCATION_CLIN, "ipn:1.2", NULL, NULL, BSL_SECROLE_ACCEPTOR, BSL_SECBLOCKTYPE_BIB, BSL_BLOCK_TYPE_PAYLOAD, BSL_POLICYACTION_DROP_BUNDLE, false, 1, 1) // FAIL
TEST_CASE(BSL_POLICYLOCATION_CLIN, "ipn:1.3", NULL, NULL, BSL_SECROLE_ACCEPTOR, BSL_SECBLOCKTYPE_BIB, BSL_BLOCK_TYPE_PAYLOAD, BSL_POLICYACTION_DROP_BLOCK, false, 1, 1) // FAIL pending #13
TEST_CASE(BSL_POLICYLOCATION_CLIN, "ipn:1.4", NULL, NULL, BSL_SECROLE_ACCEPTOR, BSL_SECBLOCKTYPE_BIB, BSL_BLOCK_TYPE_PAYLOAD, BSL_POLICYACTION_NOTHING, false, 1, 1) // FAIL pending #13
TEST_CASE(BSL_POLICYLOCATION_CLIN, "ipn:1.5", NULL, NULL, BSL_SECROLE_ACCEPTOR, BSL_SECBLOCKTYPE_BCB, BSL_BLOCK_TYPE_PAYLOAD, BSL_POLICYACTION_DROP_BLOCK, true, 1, 1) // PASS
TEST_CASE(BSL_POLICYLOCATION_CLIN, "ipn:1.6", NULL, NULL, BSL_SECROLE_ACCEPTOR, BSL_SECBLOCKTYPE_BCB, BSL_BLOCK_TYPE_PAYLOAD, BSL_POLICYACTION_DROP_BUNDLE, false, 1, 1) // FAIL
TEST_CASE(BSL_POLICYLOCATION_CLIN, "ipn:1.7", NULL, NULL, BSL_SECROLE_ACCEPTOR, BSL_SECBLOCKTYPE_BCB, BSL_BLOCK_TYPE_PAYLOAD, BSL_POLICYACTION_DROP_BLOCK, false, 1, 1) // FAIL(??) pending #13 (??)
TEST_CASE(BSL_POLICYLOCATION_CLIN, "ipn:1.8", NULL, NULL, BSL_SECROLE_ACCEPTOR, BSL_SECBLOCKTYPE_BCB, BSL_BLOCK_TYPE_PAYLOAD, BSL_POLICYACTION_NOTHING, false, 1, 1) // FAIL(??) pending #13 (??)
//TEST_CASE(BSL_POLICYLOCATION_CLIN, "ipn:1.9", NULL, NULL, BSL_SECROLE_ACCEPTOR, 99, BSL_BLOCK_TYPE_PAYLOAD, BSL_POLICYACTION_NOTHING, false, 2, 2) // super fail
TEST_CASE(BSL_POLICYLOCATION_CLOUT, NULL, "ipn:1.1", NULL, BSL_SECROLE_SOURCE, BSL_SECBLOCKTYPE_BIB, BSL_BLOCK_TYPE_PAYLOAD, BSL_POLICYACTION_DROP_BLOCK, true, 1, 1) // PASS
TEST_CASE(BSL_POLICYLOCATION_CLOUT, NULL, "ipn:1.5", NULL, BSL_SECROLE_SOURCE, BSL_SECBLOCKTYPE_BCB, BSL_BLOCK_TYPE_PAYLOAD, BSL_POLICYACTION_DROP_BLOCK, true, 1, 1) // PASS
TEST_CASE(BSL_POLICYLOCATION_CLOUT, NULL, "ipn:1.9", NULL, BSL_SECROLE_SOURCE, 99, BSL_BLOCK_TYPE_PAYLOAD, BSL_POLICYACTION_DROP_BLOCK, true, 2, 2) // PASS
TEST_CASE(BSL_POLICYLOCATION_APPIN, NULL, "ipn:1.1", NULL, BSL_SECROLE_VERIFIER, BSL_SECBLOCKTYPE_BIB, BSL_BLOCK_TYPE_PAYLOAD, BSL_POLICYACTION_DROP_BLOCK, true, 1, 1) // PASS
TEST_CASE(BSL_POLICYLOCATION_APPIN, NULL, "ipn:1.2", NULL, BSL_SECROLE_VERIFIER, BSL_SECBLOCKTYPE_BIB, BSL_BLOCK_TYPE_PAYLOAD, BSL_POLICYACTION_DROP_BUNDLE, false, 1, 1) // FAIL
TEST_CASE(BSL_POLICYLOCATION_APPIN, NULL, "ipn:1.3", NULL, BSL_SECROLE_VERIFIER, BSL_SECBLOCKTYPE_BIB, BSL_BLOCK_TYPE_PAYLOAD, BSL_POLICYACTION_DROP_BLOCK, false, 1, 1) // PASS
TEST_CASE(BSL_POLICYLOCATION_APPIN, NULL, "ipn:1.4", NULL, BSL_SECROLE_VERIFIER, BSL_SECBLOCKTYPE_BIB, BSL_BLOCK_TYPE_PAYLOAD, BSL_POLICYACTION_NOTHING, false, 1, 1) // PASS
TEST_CASE(BSL_POLICYLOCATION_APPIN, NULL, "ipn:1.5", NULL, BSL_SECROLE_VERIFIER, BSL_SECBLOCKTYPE_BCB, BSL_BLOCK_TYPE_PAYLOAD, BSL_POLICYACTION_DROP_BLOCK, true, 1, 1) // FAIL pending #30
TEST_CASE(BSL_POLICYLOCATION_APPIN, NULL, "ipn:1.6", NULL, BSL_SECROLE_VERIFIER, BSL_SECBLOCKTYPE_BCB, BSL_BLOCK_TYPE_PAYLOAD, BSL_POLICYACTION_DROP_BUNDLE, false, 1, 1) // FAIL
TEST_CASE(BSL_POLICYLOCATION_APPIN, NULL, "ipn:1.7", NULL, BSL_SECROLE_VERIFIER, BSL_SECBLOCKTYPE_BCB, BSL_BLOCK_TYPE_PAYLOAD, BSL_POLICYACTION_DROP_BLOCK, false, 1, 1) // PASS
TEST_CASE(BSL_POLICYLOCATION_APPIN, NULL, "ipn:1.8", NULL, BSL_SECROLE_VERIFIER, BSL_SECBLOCKTYPE_BCB, BSL_BLOCK_TYPE_PAYLOAD, BSL_POLICYACTION_NOTHING, false, 1, 1) // PASS
//TEST_CASE(BSL_POLICYLOCATION_APPIN, NULL, "ipn:1.9", NULL, BSL_SECROLE_VERIFIER, 99, BSL_BLOCK_TYPE_PAYLOAD, BSL_POLICYACTION_DROP_BLOCK, true, 2, 2) // super fail
void test_comprehensive(BSL_PolicyLocation_e policy_loc, const char *src_eid, const char *dest_eid,
                        const char *secsrc_eid, BSL_SecRole_e sec_role, int sec_block_type, uint8_t target_block,
                        BSL_PolicyAction_e policy_act, bool good_key, int sec_blks_ct, int expected_act_ct)
{

    (void)target_block;

    BSL_PrimaryBlock_t        primary_block = { 0 };
    BSL_SecurityResponseSet_t response_set  = { 0 };

    int query_result = -1;
    int apply_result = -1;

    if (sec_block_type == BSL_SECBLOCKTYPE_BIB)
    {
        if (sec_role == BSL_SECROLE_SOURCE)
        {
            TEST_ASSERT_EQUAL(0, BSL_TestUtils_LoadBundleFromCBOR(&LocalTestCtx,
                                                                  RFC9173_TestVectors_AppendixA1.cbor_bundle_original));
        }
        else
        {
            TEST_ASSERT_EQUAL(
                0, BSL_TestUtils_LoadBundleFromCBOR(&LocalTestCtx, RFC9173_TestVectors_AppendixA1.cbor_bundle_bib));
        }
    }
    else if (sec_block_type == BSL_SECBLOCKTYPE_BCB)
    {
        if (sec_role == BSL_SECROLE_SOURCE)
        {
            TEST_ASSERT_EQUAL(0, BSL_TestUtils_LoadBundleFromCBOR(&LocalTestCtx,
                                                                  RFC9173_TestVectors_AppendixA2.cbor_bundle_original));
        }
        else
        {
            TEST_ASSERT_EQUAL(
                0, BSL_TestUtils_LoadBundleFromCBOR(&LocalTestCtx, RFC9173_TestVectors_AppendixA2.cbor_bundle_bcb));
        }
    }
    else if (sec_block_type == TEST_BOTH_BIB_BCB)
    {
        if (sec_role == BSL_SECROLE_SOURCE)
        {
            TEST_ASSERT_EQUAL(0, BSL_TestUtils_LoadBundleFromCBOR(&LocalTestCtx,
                                                                  RFC9173_TestVectors_AppendixA4.cbor_bundle_original));
        }
        else
        {
            TEST_ASSERT_EQUAL(
                0, BSL_TestUtils_LoadBundleFromCBOR(&LocalTestCtx, RFC9173_TestVectors_AppendixA4.cbor_bundle_final));
        }
    }

    // Modify EIDs to match policy rule filters
    int res = BSL_TestUtils_ModifyEIDs(&LocalTestCtx.mock_bpa_ctr.bundle_ref, src_eid, dest_eid, secsrc_eid);
    BSL_LOG_INFO("EID MODIFICATION RESULT: %d", res);

    switch (sec_role)
    {
        case BSL_SECROLE_ACCEPTOR:
        {
            BSL_BundleCtx_GetBundleMetadata(&LocalTestCtx.mock_bpa_ctr.bundle_ref, &primary_block);
            TEST_ASSERT_EQUAL(1 + sec_blks_ct, primary_block.block_count);

            query_result = BSL_API_QuerySecurity(&LocalTestCtx.bsl, &action_set, &LocalTestCtx.mock_bpa_ctr.bundle_ref,
                                                 policy_loc);
            TEST_ASSERT_EQUAL(0, query_result);
            TEST_ASSERT_EQUAL(expected_act_ct, action_set.sec_operations_count);

            apply_result = BSL_API_ApplySecurity(&LocalTestCtx.bsl, &response_set,
                                                 &LocalTestCtx.mock_bpa_ctr.bundle_ref, &action_set);
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
                    TEST_ASSERT_EQUAL(sec_blks_ct, primary_block.block_count);
                }
                else if (policy_act == BSL_POLICYACTION_NOTHING)
                {
                    TEST_ASSERT_EQUAL(1 + sec_blks_ct, primary_block.block_count);
                }
                else
                {
                    // TODO
                    BSL_LOG_INFO("TODO!");
                }
            }

            break;
        }
        case BSL_SECROLE_VERIFIER:
        {
            BSL_BundleCtx_GetBundleMetadata(&LocalTestCtx.mock_bpa_ctr.bundle_ref, &primary_block);
            TEST_ASSERT_EQUAL(1 + sec_blks_ct, primary_block.block_count);

            query_result = BSL_API_QuerySecurity(&LocalTestCtx.bsl, &action_set, &LocalTestCtx.mock_bpa_ctr.bundle_ref,
                                                 policy_loc);
            TEST_ASSERT_EQUAL(0, query_result);
            TEST_ASSERT_EQUAL(expected_act_ct, action_set.sec_operations_count);

            apply_result = BSL_API_ApplySecurity(&LocalTestCtx.bsl, &response_set,
                                                 &LocalTestCtx.mock_bpa_ctr.bundle_ref, &action_set);
            TEST_ASSERT_EQUAL(0, apply_result);
            TEST_ASSERT_EQUAL((good_key) ? 0 : expected_act_ct, response_set.failure_count);

            BSL_BundleCtx_GetBundleMetadata(&LocalTestCtx.mock_bpa_ctr.bundle_ref, &primary_block);
            if (good_key)
            {
                // verified sec blocks
                TEST_ASSERT_EQUAL(1 + sec_blks_ct, primary_block.block_count);
            }
            else
            {
                if (policy_act == BSL_POLICYACTION_DROP_BLOCK)
                {
                    BSL_CanonicalBlock_t res;
                    TEST_ASSERT_EQUAL(0,
                                      BSL_BundleCtx_GetBlockMetadata(&LocalTestCtx.mock_bpa_ctr.bundle_ref, 2, &res));

                    // dropped target
                    TEST_ASSERT_EQUAL(sec_blks_ct, primary_block.block_count);
                }
                else if (policy_act == BSL_POLICYACTION_NOTHING)
                {
                    TEST_ASSERT_EQUAL(1 + sec_blks_ct, primary_block.block_count);
                }
                else
                {
                    // TODO
                }
            }

            break;
        }
        case BSL_SECROLE_SOURCE:
        {
            BSL_BundleCtx_GetBundleMetadata(&LocalTestCtx.mock_bpa_ctr.bundle_ref, &primary_block);
            TEST_ASSERT_EQUAL(1, primary_block.block_count);

            query_result = BSL_API_QuerySecurity(&LocalTestCtx.bsl, &action_set, &LocalTestCtx.mock_bpa_ctr.bundle_ref,
                                                 policy_loc);
            TEST_ASSERT_EQUAL(0, query_result);
            TEST_ASSERT_EQUAL(expected_act_ct, action_set.sec_operations_count);

            apply_result = BSL_API_ApplySecurity(&LocalTestCtx.bsl, &response_set,
                                                 &LocalTestCtx.mock_bpa_ctr.bundle_ref, &action_set);
            TEST_ASSERT_EQUAL(0, apply_result);
            TEST_ASSERT_EQUAL(0, response_set.failure_count);

            BSL_BundleCtx_GetBundleMetadata(&LocalTestCtx.mock_bpa_ctr.bundle_ref, &primary_block);

            // sourced sec blocks
            TEST_ASSERT_EQUAL(1 + sec_blks_ct, primary_block.block_count);

            BSL_CanonicalBlock_t res;
            if (sec_block_type == TEST_BOTH_BIB_BCB)
            {
                TEST_ASSERT_EQUAL(0, BSL_BundleCtx_GetBlockMetadata(&LocalTestCtx.mock_bpa_ctr.bundle_ref, 2, &res));
                TEST_ASSERT_EQUAL(11, res.type_code);
                TEST_ASSERT_EQUAL(0, BSL_BundleCtx_GetBlockMetadata(&LocalTestCtx.mock_bpa_ctr.bundle_ref, 3, &res));
                TEST_ASSERT_EQUAL(12, res.type_code);
            }
            else
            {
                TEST_ASSERT_EQUAL(0, BSL_BundleCtx_GetBlockMetadata(&LocalTestCtx.mock_bpa_ctr.bundle_ref, 2, &res));
                TEST_ASSERT_EQUAL(sec_block_type, res.type_code);
            }
            break;
        }
    }
}

void ntest_BSL_6(void)
{
    BSL_PrimaryBlock_t        primary_block = { 0 };
    BSL_SecurityResponseSet_t response_set  = { 0 };
    BSL_CanonicalBlock_t      res_blk;
    int                       query_result = -1;
    int                       apply_result = -1;

    TEST_ASSERT_EQUAL(0,
                      BSL_TestUtils_LoadBundleFromCBOR(&LocalTestCtx, RFC9173_TestVectors_AppendixA1.cbor_bundle_bib));

    int res = BSL_TestUtils_ModifyEIDs(&LocalTestCtx.mock_bpa_ctr.bundle_ref, NULL, "ipn:0.6", NULL);
    BSL_LOG_INFO("EID MODIFICATION RESULT: %d", res);

    BSL_BundleCtx_GetBundleMetadata(&LocalTestCtx.mock_bpa_ctr.bundle_ref, &primary_block);
    TEST_ASSERT_EQUAL(2, primary_block.block_count);

    TEST_ASSERT_EQUAL(0, BSL_BundleCtx_GetBlockMetadata(&LocalTestCtx.mock_bpa_ctr.bundle_ref, 2, &res_blk));
    TEST_ASSERT_EQUAL(11, res_blk.type_code); // should be a bib already

    query_result = BSL_API_QuerySecurity(&LocalTestCtx.bsl, &action_set, &LocalTestCtx.mock_bpa_ctr.bundle_ref,
                                         BSL_POLICYLOCATION_CLOUT);
    TEST_ASSERT_EQUAL(0, query_result);
    TEST_ASSERT_EQUAL(1, action_set.sec_operations_count);

    apply_result =
        BSL_API_ApplySecurity(&LocalTestCtx.bsl, &response_set, &LocalTestCtx.mock_bpa_ctr.bundle_ref, &action_set);
    TEST_ASSERT_EQUAL(0, apply_result);
    TEST_ASSERT_EQUAL(1, response_set.failure_count); // bib already there!

    BSL_BundleCtx_GetBundleMetadata(&LocalTestCtx.mock_bpa_ctr.bundle_ref, &primary_block);
    TEST_ASSERT_EQUAL(2, primary_block.block_count);
}

void ntest_BSL_32(void)
{
    BSL_PrimaryBlock_t        primary_block = { 0 };
    BSL_SecurityResponseSet_t response_set  = { 0 };
    BSL_CanonicalBlock_t      res_blk;
    int                       query_result = -1;
    int                       apply_result = -1;

    TEST_ASSERT_EQUAL(0,
                      BSL_TestUtils_LoadBundleFromCBOR(&LocalTestCtx, RFC9173_TestVectors_AppendixA1.cbor_bundle_bib));

    int res = BSL_TestUtils_ModifyEIDs(&LocalTestCtx.mock_bpa_ctr.bundle_ref, NULL, "ipn:3.2", NULL);
    BSL_LOG_INFO("EID MODIFICATION RESULT: %d", res);

    BSL_BundleCtx_GetBundleMetadata(&LocalTestCtx.mock_bpa_ctr.bundle_ref, &primary_block);
    TEST_ASSERT_EQUAL(2, primary_block.block_count);

    TEST_ASSERT_EQUAL(0, BSL_BundleCtx_GetBlockMetadata(&LocalTestCtx.mock_bpa_ctr.bundle_ref, 2, &res_blk));
    TEST_ASSERT_EQUAL(11, res_blk.type_code); // should be a bib already

    query_result = BSL_API_QuerySecurity(&LocalTestCtx.bsl, &action_set, &LocalTestCtx.mock_bpa_ctr.bundle_ref,
                                         BSL_POLICYLOCATION_CLOUT);
    TEST_ASSERT_EQUAL(0, query_result);
    TEST_ASSERT_EQUAL(1, action_set.sec_operations_count);

    apply_result =
        BSL_API_ApplySecurity(&LocalTestCtx.bsl, &response_set, &LocalTestCtx.mock_bpa_ctr.bundle_ref, &action_set);
    TEST_ASSERT_EQUAL(0, apply_result);
    TEST_ASSERT_EQUAL(0, response_set.failure_count);

    BSL_BundleCtx_GetBundleMetadata(&LocalTestCtx.mock_bpa_ctr.bundle_ref, &primary_block);

    // sourced sec blocks
    TEST_ASSERT_EQUAL(3, primary_block.block_count);

    TEST_ASSERT_EQUAL(0, BSL_BundleCtx_GetBlockMetadata(&LocalTestCtx.mock_bpa_ctr.bundle_ref, 2, &res_blk));
    TEST_ASSERT_EQUAL(11, res_blk.type_code);
    TEST_ASSERT_EQUAL(0, BSL_BundleCtx_GetBlockMetadata(&LocalTestCtx.mock_bpa_ctr.bundle_ref, 3, &res_blk));
    TEST_ASSERT_EQUAL(12, res_blk.type_code);
}