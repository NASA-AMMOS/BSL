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
#include <unity.h>

#include <BPSecLib_Public.h>
#include <CryptoInterface.h>
#include <backend/SecurityActionSet.h>
#include <backend/SecurityResultSet.h>
#include <policy_provider/SamplePolicyProvider.h>
#include <security_context/rfc9173.h>
#include <mock_bpa/agent.h>
#include <mock_bpa/log.h>

#include "bsl_test_utils.h"

static int malloc_cnt  = 0;
static int realloc_cnt = 0;
static int calloc_cnt  = 0;
static int free_cnt    = 0;

static BSL_SecParam_t param_aes_variant_128;
static BSL_SecParam_t param_use_wrap_key;
static BSL_SecParam_t param_test_bcb_key_correct;

static BSL_TestContext_t       LocalTestCtx = { 0 };
static BSL_SecurityActionSet_t action_set   = { 0 };
static BSLP_PolicyProvider_t  *policy_provider;

static void *malloc_test(size_t size)
{
    malloc_cnt++;
    return malloc(size);
}

static void *realloc_test(void *ptr, size_t size)
{
    realloc_cnt++;
    return realloc(ptr, size);
}

static void *calloc_test(size_t nmemb, size_t size)
{
    calloc_cnt++;
    return calloc(nmemb, size);
}

static void free_test(void *ptr)
{
    free_cnt++;
    free(ptr);
}

void suiteSetUp(void)
{
    BSL_HostDescriptors_t       host_desc    = MockBPA_Agent_Descriptors(NULL);
    BSL_DynMemHostDescriptors_t dyn_mem_desc = {
        .malloc_cb  = malloc_test,
        .realloc_cb = realloc_test,
        .calloc_cb  = calloc_test,
        .free_cb    = free_test,
    };
    host_desc.dyn_mem_desc = dyn_mem_desc;

    TEST_ASSERT_EQUAL_INT(0, BSL_HostDescriptors_Set(host_desc));
    mock_bpa_LogOpen();
}

int suiteTearDown(int failures)
{
    mock_bpa_LogClose();
    BSL_HostDescriptors_Clear();
    return failures;
}

// manually call this to control dynamic mem callback tracking for test
void _setUp(void)
{
    setenv("BSL_TEST_LOCAL_IPN_EID", "ipn:2.1", 1);
    memset(&LocalTestCtx, 0, sizeof(LocalTestCtx));
    TEST_ASSERT_EQUAL(0, BSL_API_InitLib(&LocalTestCtx.bsl));
    mock_bpa_ctr_init(&LocalTestCtx.mock_bpa_ctr);
    memset(&action_set, 0, sizeof(action_set));

    BSL_CryptoInit();

    BSL_SecParam_Init(&param_aes_variant_128);
    BSL_SecParam_Init(&param_use_wrap_key);
    BSL_SecParam_Init(&param_test_bcb_key_correct);

    policy_provider = BSLP_PolicyProvider_Init(1);

    /// Register the policy provider with some rules
    BSL_PolicyDesc_t policy_desc = { 0 };
    policy_desc.user_data        = policy_provider;
    policy_desc.query_fn         = BSLP_QueryPolicy;
    policy_desc.deinit_fn        = BSLP_Deinit;
    policy_desc.finalize_fn      = BSLP_FinalizePolicy;
    TEST_ASSERT_EQUAL(0, BSL_API_RegisterPolicyProvider(&LocalTestCtx.bsl, BSL_SAMPLE_PP_ID, policy_desc));

    BSLP_PolicyProvider_t *policy = BSL_PolicyDict_get(LocalTestCtx.bsl.policy_reg, BSL_SAMPLE_PP_ID)->user_data;

    BSL_SecParam_InitInt64(&param_aes_variant_128, RFC9173_BCB_SECPARAM_AESVARIANT, RFC9173_BCB_AES_VARIANT_A128GCM);
    BSL_SecParam_InitInt64(&param_use_wrap_key, BSL_SECPARAM_USE_KEY_WRAP, 1);
    BSL_SecParam_InitTextstr(&param_test_bcb_key_correct, BSL_SECPARAM_TYPE_KEY_ID, RFC9173_EXAMPLE_A2_KEY);

    // BSL_32
    BSLP_PolicyPredicate_t predicate_bsl_32a;
    BSLP_PolicyPredicate_InitFrom(&predicate_bsl_32a, BSL_POLICYLOCATION_CLOUT, "*:**", "*:**", "ipn:*.3.2");
    BSLP_PolicyRule_t rule_bsl_32a;
    BSLP_PolicyRule_InitFrom(&rule_bsl_32a, "SOURCE BCB OVER PAYLOAD AT CLOUT FILTER(DEST=ipn:3.2)", 2,
                             BSL_SECROLE_SOURCE, BSL_SECBLOCKTYPE_BCB, BSL_BLOCK_TYPE_PAYLOAD,
                             BSL_POLICYACTION_DROP_BLOCK);
    BSLP_PolicyRule_CopyParam(&rule_bsl_32a, &param_test_bcb_key_correct);
    BSLP_PolicyRule_CopyParam(&rule_bsl_32a, &param_aes_variant_128);
    BSLP_PolicyRule_CopyParam(&rule_bsl_32a, &param_use_wrap_key);
    BSLP_PolicyProvider_AddRule(policy, &rule_bsl_32a, &predicate_bsl_32a);

    BSLP_PolicyPredicate_t predicate_bsl_32b;
    BSLP_PolicyPredicate_InitFrom(&predicate_bsl_32b, BSL_POLICYLOCATION_CLOUT, "*:**", "*:**", "ipn:*.3.2");
    BSLP_PolicyRule_t rule_bsl_32b;
    BSLP_PolicyRule_InitFrom(&rule_bsl_32b, "SOURCE BCB OVER BIB AT CLOUT FILTER(DEST=ipn:3.2)", 2, BSL_SECROLE_SOURCE,
                             BSL_SECBLOCKTYPE_BCB, BSL_BLOCK_TYPE_BIB, BSL_POLICYACTION_DROP_BLOCK);
    BSLP_PolicyRule_CopyParam(&rule_bsl_32b, &param_test_bcb_key_correct);
    BSLP_PolicyRule_CopyParam(&rule_bsl_32b, &param_aes_variant_128);
    BSLP_PolicyRule_CopyParam(&rule_bsl_32b, &param_use_wrap_key);
    BSLP_PolicyProvider_AddRule(policy, &rule_bsl_32b, &predicate_bsl_32b);

    /// Register the Security Context
    BSL_TestUtils_SetupDefaultSecurityContext(&LocalTestCtx.bsl);
}

// manually call this to control dynamic mem callback tracking for test
void _tearDown(void)
{
    BSL_SecurityActionSet_Deinit(&action_set);
    BSLP_PolicyProvider_Deinit(policy_provider);
    mock_bpa_ctr_deinit(&LocalTestCtx.mock_bpa_ctr);
    BSL_CryptoDeinit();
    TEST_ASSERT_EQUAL(0, BSL_API_DeinitLib(&LocalTestCtx.bsl));

    BSL_SecParam_Deinit(&param_aes_variant_128);
    BSL_SecParam_Deinit(&param_use_wrap_key);
    BSL_SecParam_Deinit(&param_test_bcb_key_correct);
}

// Test BSL 32 with user-defined dyn mem cbs
void test_dyn_mem_cbs_BSL_32(void)
{
    _setUp();

    BSL_PrimaryBlock_t        primary_block;
    BSL_SecurityResponseSet_t response_set = { 0 };
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
    TEST_ASSERT_EQUAL(2, BSL_SecurityActionSet_CountOperations(&action_set));

    apply_result =
        BSL_API_ApplySecurity(&LocalTestCtx.bsl, &response_set, &LocalTestCtx.mock_bpa_ctr.bundle_ref, &action_set);
    TEST_ASSERT_EQUAL(0, apply_result);

    for (size_t i = 0; i < BSL_SecurityActionSet_CountActions(&action_set); i++)
    {
        const BSL_SecurityAction_t *act = BSL_SecurityActionSet_GetActionAtIndex(&action_set, i);
        for (size_t j = 0; j < BSL_SecurityAction_CountSecOpers(act); j++)
        {
            TEST_ASSERT_EQUAL(BSL_SECOP_CONCLUSION_SUCCESS,
                              BSL_SecOper_GetConclusion(BSL_SecurityAction_GetSecOperAtIndex(act, j)));
        }
    }
    BSL_PrimaryBlock_deinit(&primary_block);

    BSL_BundleCtx_GetBundleMetadata(&LocalTestCtx.mock_bpa_ctr.bundle_ref, &primary_block);

    TEST_ASSERT_EQUAL(4, primary_block.block_count);
    TEST_ASSERT_EQUAL(0, BSL_BundleCtx_GetBlockMetadata(&LocalTestCtx.mock_bpa_ctr.bundle_ref, 2, &res_blk));
    TEST_ASSERT_EQUAL(11, res_blk.type_code);
    TEST_ASSERT_EQUAL(0, BSL_BundleCtx_GetBlockMetadata(&LocalTestCtx.mock_bpa_ctr.bundle_ref, 3, &res_blk));
    TEST_ASSERT_EQUAL(12, res_blk.type_code);
    TEST_ASSERT_EQUAL(0, BSL_BundleCtx_GetBlockMetadata(&LocalTestCtx.mock_bpa_ctr.bundle_ref, 4, &res_blk));
    TEST_ASSERT_EQUAL(12, res_blk.type_code);

    BSL_PrimaryBlock_deinit(&primary_block);

    _tearDown();

    TEST_ASSERT_NOT_EQUAL(0, malloc_cnt);
    TEST_ASSERT_NOT_EQUAL(0, realloc_cnt);
    TEST_ASSERT_NOT_EQUAL(0, calloc_cnt);
    TEST_ASSERT_NOT_EQUAL(0, free_cnt);
}
