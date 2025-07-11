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
 * Implementations for permutations of policy configurations.
 * @ingroup mock_bpa
 */

#include "bsl_mock_bpa_policy_config.h"

// Params related to BIB
static BSL_SecParam_t *param_integ_scope_flag;
static BSL_SecParam_t *param_sha_variant;

// Params related to BCB
static BSL_SecParam_t *param_aad_scope_flag;
static BSL_SecParam_t *param_init_vector;
static BSL_SecParam_t *param_aes_variant;

// Params agnostic to BIB vs BCB
static BSL_SecParam_t *param_test_key;

static BSL_HostEIDPattern_t mock_bpa_util_get_eid_pattern_from_text(const char *text)
{
    BSL_HostEIDPattern_t pat;
    BSL_HostEIDPattern_Init(&pat);
    assert(0 == BSL_HostEIDPattern_DecodeFromText(&pat, text));
    return pat;
}

void mock_bpa_verify_bib_at_cla_in_policy(BSLP_PolicyProvider_t *policy) {

    BSL_SecParam_InitInt64(param_integ_scope_flag, RFC9173_BIB_PARAMID_INTEG_SCOPE_FLAG, 0);
    BSL_SecParam_InitInt64(param_sha_variant, RFC9173_BIB_PARAMID_SHA_VARIANT, RFC9173_BIB_SHA_HMAC512);
    BSL_SecParam_InitInt64(param_test_key, BSL_SECPARAM_TYPE_INT_KEY_ID, 9001);
    // BSL_SecParam_InitInt64(param_test_key_bad, BSL_SECPARAM_TYPE_INT_KEY_ID, 9002);

    // Create a rule to verify BIB's at CLA Ingress
    BSLP_PolicyPredicate_t *predicate_all_cl_in = &policy->predicates[policy->predicate_count++];
    BSLP_PolicyPredicate_Init(predicate_all_cl_in, BSL_POLICYLOCATION_CLIN, mock_bpa_util_get_eid_pattern_from_text("*:**"),
                              mock_bpa_util_get_eid_pattern_from_text("*:**"), mock_bpa_util_get_eid_pattern_from_text("*:**"));
    BSLP_PolicyRule_t *rule_verify_bib_cl_in = &policy->rules[policy->rule_count++];
    BSLP_PolicyRule_Init(rule_verify_bib_cl_in, "Verify BIB on CL in to/from anywhere.", predicate_all_cl_in, 1,
                         BSL_SECROLE_ACCEPTOR, BSL_SECBLOCKTYPE_BIB, BSL_BLOCK_TYPE_PAYLOAD,
                         BSL_POLICYACTION_DROP_BLOCK);
    BSLP_PolicyRule_AddParam(rule_verify_bib_cl_in, param_sha_variant);
    BSLP_PolicyRule_AddParam(rule_verify_bib_cl_in, param_integ_scope_flag);
    BSLP_PolicyRule_AddParam(rule_verify_bib_cl_in, param_test_key);
    // BSLP_PolicyRule_AddParam(rule_verify_bib_cl_in, param_test_key_bad);
}

void mock_bpa_verify_bcb_at_cla_in_policy(BSLP_PolicyProvider_t *policy) {

    uint64_t iv;
    sscanf("5477656c7665313231323132", "%" SCNx64, &iv);



    BSL_SecParam_InitInt64(param_aad_scope_flag, RFC9173_BCB_AADSCOPEFLAGID_INC_PRIM_BLOCK, 0);
    BSL_SecParam_InitInt64(param_init_vector, BSL_SECPARAM_TYPE_IV, iv);
    BSL_SecParam_InitInt64(param_aes_variant, RFC9173_BCB_SECPARAM_AESVARIANT, RFC9173_BCB_AES_VARIANT_A256GCM);
    BSL_SecParam_InitInt64(param_test_key, BSL_SECPARAM_TYPE_INT_KEY_ID, 9001);

    // Create a rule to verify BCB's at CLA Ingress
    BSLP_PolicyPredicate_t *predicate_all_cl_in = &policy->predicates[policy->predicate_count++];
    BSLP_PolicyPredicate_Init(predicate_all_cl_in, BSL_POLICYLOCATION_CLIN, mock_bpa_util_get_eid_pattern_from_text("*:**"),
                              mock_bpa_util_get_eid_pattern_from_text("*:**"), mock_bpa_util_get_eid_pattern_from_text("*:**"));
    BSLP_PolicyRule_t *rule_verify_bcb_cl_in = &policy->rules[policy->rule_count++];
    BSLP_PolicyRule_Init(rule_verify_bcb_cl_in, "Verify BCB on CL in to/from anywhere.", predicate_all_cl_in, 1,
                         BSL_SECROLE_ACCEPTOR, BSL_SECBLOCKTYPE_BCB, BSL_BLOCK_TYPE_PAYLOAD,
                         BSL_POLICYACTION_DROP_BLOCK);
    BSLP_PolicyRule_AddParam(rule_verify_bcb_cl_in, param_aes_variant);
    BSLP_PolicyRule_AddParam(rule_verify_bcb_cl_in, param_aad_scope_flag);
    BSLP_PolicyRule_AddParam(rule_verify_bcb_cl_in, param_init_vector);
    BSLP_PolicyRule_AddParam(rule_verify_bcb_cl_in, param_test_key);
}

void mock_bpa_init_policy_config() {

    param_integ_scope_flag = calloc(BSL_SecParam_Sizeof(), 1);
    param_sha_variant = calloc(BSL_SecParam_Sizeof(), 1);
    param_aad_scope_flag = calloc(BSL_SecParam_Sizeof(), 1);
    param_init_vector = calloc(BSL_SecParam_Sizeof(), 1);
    param_aes_variant = calloc(BSL_SecParam_Sizeof(), 1);
    param_test_key = calloc(BSL_SecParam_Sizeof(), 1);
}

void mock_bpa_deinit_policy_config() {

    free(param_integ_scope_flag);
    free(param_sha_variant);
    free(param_aad_scope_flag);
    free(param_init_vector);
    free(param_aes_variant);
    free(param_test_key);
}

void mock_bpa_handle_policy_config(const bsl_mock_policy_configuration_t policy_bits, BSLP_PolicyProvider_t *policy) {

    mock_bpa_init_policy_config();

    BSL_LOG_DEBUG("\nInterpreted policy: 0x%X\n", policy_bits);

    BSL_SecBlockType_e sec_block_type = policy_bits & 0x01;
    BSL_SecRole_e sec_role = policy_bits & 0x02;
    BSL_BundleBlockTypeCode_e bundle_block_type = (policy_bits >> 2) & 0x03;

    // TODO: get all info on policy and refactor registration here

    if (policy_bits & 0x01) {
        mock_bpa_verify_bcb_at_cla_in_policy(policy);
    }
    else {
        mock_bpa_verify_bib_at_cla_in_policy(policy);
    }

}
