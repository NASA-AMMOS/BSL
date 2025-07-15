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

typedef struct mock_bpa_policy_params
{
    // Params related to BIB
    BSL_SecParam_t *param_integ_scope_flag;
    BSL_SecParam_t *param_sha_variant;

    // Params related to BCB
    BSL_SecParam_t *param_aad_scope_flag;
    BSL_SecParam_t *param_init_vector;
    BSL_SecParam_t *param_aes_variant;

    // Params agnostic to BIB vs BCB
    BSL_SecParam_t *param_test_key;
} mock_bpa_policy_params_t;

#define MOCK_BPA_MAX_POLICIES 100

typedef struct mock_bpa_policy_registry
{
    mock_bpa_policy_params_t mock_bpa_policy_registry[MOCK_BPA_MAX_POLICIES];
    uint32_t registry_count;
} mock_bpa_policy_registry_t;

static mock_bpa_policy_registry_t registry;

static BSL_HostEIDPattern_t mock_bpa_util_get_eid_pattern_from_text(const char *text)
{
    BSL_HostEIDPattern_t pat;
    BSL_HostEIDPattern_Init(&pat);
    assert(0 == BSL_HostEIDPattern_DecodeFromText(&pat, text));
    return pat;
}

static void mock_bpa_init_registry(void) {

    registry.mock_bpa_policy_registry[registry.registry_count].param_integ_scope_flag = calloc(BSL_SecParam_Sizeof(), 1);
    registry.mock_bpa_policy_registry[registry.registry_count].param_sha_variant = calloc(BSL_SecParam_Sizeof(), 1);
    registry.mock_bpa_policy_registry[registry.registry_count].param_aad_scope_flag = calloc(BSL_SecParam_Sizeof(), 1);
    registry.mock_bpa_policy_registry[registry.registry_count].param_init_vector = calloc(BSL_SecParam_Sizeof(), 1);
    registry.mock_bpa_policy_registry[registry.registry_count].param_aes_variant = calloc(BSL_SecParam_Sizeof(), 1);
    registry.mock_bpa_policy_registry[registry.registry_count].param_test_key = calloc(BSL_SecParam_Sizeof(), 1);

    BSL_LOG_DEBUG("Successfully Init policy number %d in registry\n", registry.registry_count);
}

void mock_bpa_handle_policy_config_from_json(const bsl_mock_policy_configuration_t policy_type, BSLP_PolicyProvider_t *policy) {
    mock_bpa_init_policy_config();

    uint32_t sec_block_type;
    uint32_t sec_role;
    uint32_t bundle_block_type;
    uint32_t policy_action_type;
    
    (void) policy;
    (void) policy_type;
    (void) sec_block_type;
    (void) sec_role;
    (void) bundle_block_type;
    (void) policy_action_type;

    json_t *root;
    json_error_t err;

    int cp=0;

    root = json_load_file("src/mock_bpa/iontest1policyrule.json", 0, &err);
    if (!root) {
        BSL_LOG_ERR("JSON error: line %d: %s\n", err.line, err.text);
        return;
    }
    BSL_LOG_DEBUG("checkpoint %d\n", cp++);

     /* ----- policyrule attr ----- */
    json_t *policyrule = json_object_get(root, "policyrule");
    if (!policyrule || !json_is_object(policyrule)) {
        BSL_LOG_ERR("Missing \"policyrule\" \n");
        goto cleanup;
    }
    BSL_LOG_DEBUG("checkpoint %d\n", cp++);

     /* ----- filter attr ----- */
    json_t *filter = json_object_get(policyrule, "filter");
    if (filter && json_is_object(filter)) {
        const char *rule_id = json_string_value(json_object_get(filter, "rule_id"));
        const char *role    = json_string_value(json_object_get(filter, "role"));
        const char *src     = json_string_value(json_object_get(filter, "src"));
        json_t     *tgt_val = json_object_get(filter, "tgt");

        BSL_LOG_DEBUG("filter:\n");
        BSL_LOG_DEBUG("  rule_id: %s\n", rule_id ? rule_id : "(null)");
        BSL_LOG_DEBUG("  role   : %s\n", role    ? role    : "(null)");
        BSL_LOG_DEBUG("  src    : %s\n", src     ? src     : "(null)");
        if (tgt_val && json_is_integer(tgt_val))
            BSL_LOG_DEBUG("  tgt    : %" JSON_INTEGER_FORMAT "\n", json_integer_value(tgt_val));
    }
    BSL_LOG_DEBUG("checkpoint %d\n", cp++);

    /* ----- spec attr ----- */
    json_t *spec = json_object_get(policyrule, "spec");
    if (spec && json_is_object(spec)) {
        const char *svc  = json_string_value(json_object_get(spec, "svc"));
        json_t     *id_v = json_object_get(spec, "sc_id");

        BSL_LOG_DEBUG("spec:\n");
        BSL_LOG_DEBUG("  svc  : %s\n", svc ? svc : "(null)");
        if (id_v && json_is_integer(id_v))
            BSL_LOG_DEBUG("  sc_id: %" JSON_INTEGER_FORMAT "\n", json_integer_value(id_v));

        json_t *sc_parms = json_object_get(spec, "sc_parms");
        if (sc_parms && json_is_array(sc_parms)) {
            size_t i, n = json_array_size(sc_parms);
            BSL_LOG_DEBUG("  sc_parms (%zu):\n", n);
            for (i = 0; i < n; ++i) {
                json_t *entry = json_array_get(sc_parms, i);
                if (!json_is_object(entry)) continue;
                const char *id    = json_string_value(json_object_get(entry, "id"));
                const char *value = json_string_value(json_object_get(entry, "value"));
                BSL_LOG_DEBUG("    - id: %s, value: %s\n",
                       id ? id : "(null)", value ? value : "(null)");
            }
        }
    }
    BSL_LOG_DEBUG("checkpoint %d\n", cp++);

    cleanup:
        json_decref(root);

}

static void mock_bpa_register_policy(const bsl_mock_policy_configuration_t policy_bits, BSLP_PolicyProvider_t *policy) {

    BSL_LOG_DEBUG("\nInterpreted policy: 0x%X\n", policy_bits);

    mock_bpa_init_registry();

    uint32_t sec_block_type = policy_bits & 0x01;
    uint32_t policy_loc = policy_bits & 0x02;
    uint32_t bundle_block_type = (policy_bits >> 2) & 0x03;
    uint32_t policy_action_type = (policy_bits >> 4) & 0x03;
    uint32_t sec_role = (policy_bits >> 6) & 0x03;

    uint64_t iv;
    sscanf("5477656c7665313231323132", "%" SCNx64, &iv);

    // Init params for BCB if equal to 1, otherwise BIB
    if (sec_block_type == 1) {
        BSL_SecParam_InitInt64(registry.mock_bpa_policy_registry[registry.registry_count].param_aad_scope_flag, RFC9173_BCB_AADSCOPEFLAGID_INC_PRIM_BLOCK, 0);
        BSL_SecParam_InitInt64(registry.mock_bpa_policy_registry[registry.registry_count].param_init_vector, BSL_SECPARAM_TYPE_IV, iv);
        BSL_SecParam_InitInt64(registry.mock_bpa_policy_registry[registry.registry_count].param_aes_variant, RFC9173_BCB_SECPARAM_AESVARIANT, RFC9173_BCB_AES_VARIANT_A256GCM);
        BSL_SecParam_InitInt64(registry.mock_bpa_policy_registry[registry.registry_count].param_test_key, BSL_SECPARAM_TYPE_INT_KEY_ID, 9001);
    }
    else {
        BSL_SecParam_InitInt64(registry.mock_bpa_policy_registry[registry.registry_count].param_integ_scope_flag, RFC9173_BIB_PARAMID_INTEG_SCOPE_FLAG, 0);
        BSL_SecParam_InitInt64(registry.mock_bpa_policy_registry[registry.registry_count].param_sha_variant, RFC9173_BIB_PARAMID_SHA_VARIANT, RFC9173_BIB_SHA_HMAC512);
        BSL_SecParam_InitInt64(registry.mock_bpa_policy_registry[registry.registry_count].param_test_key, BSL_SECPARAM_TYPE_INT_KEY_ID, 9001);
        // BSL_SecParam_InitInt64(registry.mock_bpa_policy_registry[registry.registry_count].param_test_key_bad, BSL_SECPARAM_TYPE_INT_KEY_ID, 9002);
    }

    BSL_SecBlockType_e sec_block_emum;
    if (sec_block_type == 1) {
        sec_block_emum = BSL_SECBLOCKTYPE_BCB;
    }
    else {
        sec_block_emum = BSL_SECBLOCKTYPE_BIB;
    }

    BSL_PolicyLocation_e policy_loc_enum;
    if (policy_loc == 1) {
        policy_loc_enum = BSL_POLICYLOCATION_CLIN;
    }
    else {
        policy_loc_enum = BSL_POLICYLOCATION_APPIN;
    }

    BSL_BundleBlockTypeCode_e bundle_block_enum;
    switch (bundle_block_type) {
        case 0: bundle_block_enum = BSL_BLOCK_TYPE_PRIMARY;
                break;
        case 1: bundle_block_enum = BSL_BLOCK_TYPE_PAYLOAD;
                break;
        case 2: bundle_block_enum = BSL_BLOCK_TYPE_BIB;
                break;
        case 3: bundle_block_enum = BSL_BLOCK_TYPE_BIB;
                break;
        default: break;
    }

    BSL_PolicyAction_e policy_action_enum;
    switch (policy_action_type) {
        case 0: policy_action_enum = BSL_POLICYACTION_NOTHING;
                break;
        case 1: policy_action_enum = BSL_POLICYACTION_DROP_BLOCK;
                break;
        case 2: policy_action_enum = BSL_POLICYACTION_DROP_BUNDLE;
                break;
        default: policy_action_enum = BSL_POLICYACTION_NOTHING;
                break;
    }

    BSL_SecRole_e sec_role_enum;
    switch (sec_role) {
        case 0: sec_role_enum = BSL_SECROLE_SOURCE;
                break;
        case 1: sec_role_enum = BSL_SECROLE_VERIFIER;
                break;
        case 2: sec_role_enum = BSL_SECROLE_ACCEPTOR;
                break;
        default: sec_role_enum = BSL_SECROLE_VERIFIER;
                break;
    }
        
    // Create a rule to verify security block at APP/CLA Ingress
    BSLP_PolicyPredicate_t *predicate_all_in = &policy->predicates[policy->predicate_count++];
    BSLP_PolicyPredicate_Init(predicate_all_in, policy_loc_enum, mock_bpa_util_get_eid_pattern_from_text("*:**"),
                              mock_bpa_util_get_eid_pattern_from_text("*:**"), mock_bpa_util_get_eid_pattern_from_text("*:**"));
    BSLP_PolicyRule_t *rule_all_in = &policy->rules[policy->rule_count++];
    BSLP_PolicyRule_Init(rule_all_in, "Verify BCB on CL in to/from anywhere.", predicate_all_in, 1,
                         sec_role_enum, sec_block_emum, bundle_block_enum,
                         policy_action_enum);

    if (sec_block_emum == BSL_SECBLOCKTYPE_BCB) {
        BSLP_PolicyRule_AddParam(rule_all_in, registry.mock_bpa_policy_registry[registry.registry_count].param_aes_variant);
        BSLP_PolicyRule_AddParam(rule_all_in, registry.mock_bpa_policy_registry[registry.registry_count].param_aad_scope_flag);
        BSLP_PolicyRule_AddParam(rule_all_in, registry.mock_bpa_policy_registry[registry.registry_count].param_init_vector);
        BSLP_PolicyRule_AddParam(rule_all_in, registry.mock_bpa_policy_registry[registry.registry_count].param_test_key);
    }
    else {
        BSLP_PolicyRule_AddParam(rule_all_in, registry.mock_bpa_policy_registry[registry.registry_count].param_sha_variant);
        BSLP_PolicyRule_AddParam(rule_all_in, registry.mock_bpa_policy_registry[registry.registry_count].param_integ_scope_flag);
        BSLP_PolicyRule_AddParam(rule_all_in, registry.mock_bpa_policy_registry[registry.registry_count].param_test_key);
        // BSLP_PolicyRule_AddParam(rule_all_in, registry.mock_bpa_policy_registry[registry.registry_count].param_test_key_bad);
    }

}

void mock_bpa_init_policy_config() {

    // placeholder for symmetry
    registry.registry_count = 0;
}

void mock_bpa_deinit_policy_config() {

    for(uint32_t i = 0; i < registry.registry_count; i++) {
        free(registry.mock_bpa_policy_registry[i].param_integ_scope_flag);
        free(registry.mock_bpa_policy_registry[i].param_sha_variant);
        free(registry.mock_bpa_policy_registry[i].param_aad_scope_flag);
        free(registry.mock_bpa_policy_registry[i].param_init_vector);
        free(registry.mock_bpa_policy_registry[i].param_aes_variant);
        free(registry.mock_bpa_policy_registry[i].param_test_key);

        BSL_LOG_DEBUG("Successfully De-init policy number %d in registry\n", i);
    }
}

void mock_bpa_handle_policy_config(char *policies, BSLP_PolicyProvider_t *policy) {

    char *pt;

    registry.registry_count = 0;

    // Split up and register each policy
    pt = strtok(policies,",");
    while (pt != NULL) {

        if (registry.registry_count < MOCK_BPA_MAX_POLICIES) {
            mock_bpa_register_policy(strtoul(pt, NULL, 0), policy);
            registry.registry_count++;
        }
        else {
            BSL_LOG_ERR("\nPOLICY COUNT EXCEEDED, NOT REGISTERING FURTHER\n");
        }
        pt = strtok(NULL, ",");
        
    }
    BSL_LOG_DEBUG("Successfully created policy registry of size: %d\n", registry.registry_count);
}
