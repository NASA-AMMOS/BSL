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

#include "policy_config.h"
#include "text_util.h"

static BSL_HostEIDPattern_t mock_bpa_util_get_eid_pattern_from_text(const char *text)
{
    BSL_HostEIDPattern_t pat;
    BSL_HostEIDPattern_Init(&pat);
    ASSERT_PROPERTY(0 == BSL_HostEIDPattern_DecodeFromText(&pat, text));
    return pat;
}

// TODO: JSON PARSING IN PROGRESS, THIS DOESN'T DO ANYTHING YET
void mock_bpa_handle_policy_config_from_json(const char *pp_cfg_file_path, BSLP_PolicyProvider_t *policy)
{

    uint32_t             sec_block_type;
    uint32_t             sec_ctx_id;
    BSL_SecRole_e        sec_role;
    uint32_t             bundle_block_type;
    uint32_t             policy_action_type;
    BSL_PolicyLocation_e policy_loc_enum;

    const char          *src_str     = "";
    const char          *dest_str    = "";
    const char          *sec_src_str = "";
    BSL_HostEIDPattern_t src_eid;
    BSL_HostEIDPattern_t dest_eid;
    BSL_HostEIDPattern_t sec_src_eid;

    (void)policy;
    (void)sec_block_type;
    (void)sec_ctx_id;
    (void)sec_role;
    (void)bundle_block_type;
    (void)policy_action_type;
    (void)policy_loc_enum;
    (void)src_str;
    (void)dest_str;
    (void)sec_src_str;
    (void)src_eid;
    (void)dest_eid;
    (void)sec_src_eid;

    json_t      *root;
    json_error_t err;

    root = json_load_file(pp_cfg_file_path, 0, &err);
    if (!root)
    {
        BSL_LOG_ERR("JSON error: line %d: %s\n", err.line, err.text);
        return;
    }

    // policyrule attr
    json_t *policyrule = json_object_get(root, "policyrule");
    if (!policyrule || !json_is_object(policyrule))
    {
        BSL_LOG_ERR("Missing \"policyrule\" \n");
        json_decref(root);
        return;
    }

    // filter attr
    json_t *filter = json_object_get(policyrule, "filter");
    BSL_LOG_DEBUG("filter:\n");
    if (filter && json_is_object(filter))
    {
        // Get rule_id
        json_t *rule_id = json_object_get(filter, "rule_id");
        if (!rule_id)
        {
            BSL_LOG_ERR("No rule ID \n");
            json_decref(root);
            return;
        }
        const char *rule_id_str = json_string_value(rule_id);
        BSL_LOG_DEBUG("     rule_id: %s\n", rule_id_str);

        // get sec role
        json_t *role = json_object_get(filter, "role");
        if (!role)
        {
            BSL_LOG_ERR("No sec role\n");
            json_decref(root);
            return;
        }
        const char *role_str = json_string_value(role);
        BSL_LOG_DEBUG("     role   : %s\n", role_str);

        // check for valid sec role
        if (!strcmp(role_str, "s"))
        {
            sec_role = BSL_SECROLE_SOURCE;
        }
        else if (!strcmp(role_str, "v"))
        {
            sec_role = BSL_SECROLE_VERIFIER;
        }
        else if (!strcmp(role_str, "a"))
        {
            sec_role = BSL_SECROLE_ACCEPTOR;
        }
        else
        {
            BSL_LOG_ERR("INVALID SEC ROLE %s\n", role_str);
            json_decref(root);
            return;
        }

        json_t *src = json_object_get(filter, "src");
        if (src)
        {
            src_str = json_string_value(src);
            BSL_LOG_DEBUG("     src    : %s\n", src_str);
            src_eid = mock_bpa_util_get_eid_pattern_from_text(src_str);
        }

        json_t *dest = json_object_get(filter, "dest");
        if (dest)
        {
            dest_str = json_string_value(dest);
            BSL_LOG_DEBUG("     dest    : %s\n", dest_str);
            dest_eid = mock_bpa_util_get_eid_pattern_from_text(dest_str);
        }

        json_t *sec_src = json_object_get(filter, "sec_src");
        if (sec_src)
        {
            sec_src_str = json_string_value(sec_src);
            BSL_LOG_DEBUG("     sec_src    : %s\n", sec_src_str);
            sec_src_eid = mock_bpa_util_get_eid_pattern_from_text(sec_src_str);
        }

        // must have at least 1 EID for valid filter (for ION)
        // do we care about this for BSL? TODO
        if (!dest && !src && !sec_src)
        {
            BSL_LOG_ERR("No EIDs set, INVALID RULE\n");
            json_decref(root);
            return;
        }

        // check tgt (target block type)
        json_t *tgt = json_object_get(filter, "tgt");
        if (!tgt)
        {
            BSL_LOG_ERR("No tgt\n");
            json_decref(root);
            return;
        }
        const long tgt_l = json_integer_value(tgt);
        BSL_LOG_DEBUG("     tgt    : %" JSON_INTEGER_FORMAT "\n", tgt_l);

        bundle_block_type = tgt_l;

        // check loc (sec location )
        json_t *loc = json_object_get(filter, "loc");
        if (!loc)
        {
            BSL_LOG_ERR("No loc\n");
            json_decref(root);
            return;
        }
        const char *loc_str = json_string_value(loc);
        BSL_LOG_DEBUG("     loc    : %s\n", loc_str);

        if (strcmp(loc_str, "appin"))
        {
            policy_loc_enum = BSL_POLICYLOCATION_APPIN;
        }
        else if (strcmp(loc_str, "appout"))
        {
            policy_loc_enum = BSL_POLICYLOCATION_APPOUT;
        }
        else if (strcmp(loc_str, "clin"))
        {
            policy_loc_enum = BSL_POLICYLOCATION_CLIN;
        }
        else if (strcmp(loc_str, "clout"))
        {
            policy_loc_enum = BSL_POLICYLOCATION_CLOUT;
        }
        else
        {
            BSL_LOG_ERR("INVALID POLICY LOCATION %s\n", loc_str);
            json_decref(root);
            return;
        }

        json_t *sc_id   = json_object_get(filter, "sc_id");
        long    sc_id_l = json_integer_value(sc_id);
        BSL_LOG_DEBUG("     scid    : %" JSON_INTEGER_FORMAT "\n", sc_id_l);

        sec_ctx_id = sc_id_l;
    }

    // es_ref
    json_t *es_ref = json_object_get(policyrule, "es_ref");
    if (!es_ref || !json_is_string(es_ref))
    {
        BSL_LOG_DEBUG("NO ES REF");
    }

    // spec attr
    json_t *spec = json_object_get(policyrule, "spec");
    if (spec && json_is_object(spec))
    {

        json_t     *svc   = json_object_get(spec, "svc");
        const char *svc_c = json_string_value(svc);

        // check sec ctx id
        json_t *sc_id   = json_object_get(spec, "sc_id");
        long    sc_id_l = json_integer_value(sc_id);

        BSL_LOG_DEBUG("spec:\n");
        BSL_LOG_DEBUG("     svc: %s\n", svc_c ? svc_c : "(null)");
        BSL_LOG_DEBUG("     sc_id: %" JSON_INTEGER_FORMAT "\n", sc_id_l ? sc_id_l : -1);

        json_t *sc_parms = json_object_get(spec, "sc_parms");
        if (sc_parms && json_is_array(sc_parms))
        {
            size_t i, n = json_array_size(sc_parms);
            BSL_LOG_DEBUG("     sc_parms (%zu):\n", n);
            for (i = 0; i < n; ++i)
            {
                json_t *entry = json_array_get(sc_parms, i);
                if (!json_is_object(entry))
                    continue;

                json_t *id = json_object_get(entry, "id");
                if (!id)
                    continue;
                const char *id_str = json_string_value(id);

                json_t *value = json_object_get(entry, "value");
                if (!value)
                    continue;
                const char *value_str = json_string_value(value);

                BSL_LOG_DEBUG("         - id: %s, value: %s\n", id_str, value_str);

                // different valid param IDs for different contexts
                switch (sc_id_l)
                {
                    case 1:
                        if (!strcmp(id_str, "key_name"))
                        {}
                        else if (!strcmp(id_str, "sha_variant"))
                        {}
                        else if (!strcmp(id_str, "scope_flags"))
                        {}
                        else
                        {
                            BSL_LOG_ERR("INVALID KEY FOR SC ID %d\n", sc_id_l);
                            json_decref(root);
                            return;
                        }
                        break;
                    case 2:
                        if (!strcmp(id_str, "key_name"))
                        {}
                        else if (!strcmp(id_str, "iv"))
                        {}
                        else if (!strcmp(id_str, "aes_variant"))
                        {}
                        else if (!strcmp(id_str, "aad_scope"))
                        {}
                        else
                        {
                            BSL_LOG_ERR("INVALID KEY FOR SC ID %d\n", sc_id_l);
                            json_decref(root);
                            return;
                        }
                        break;
                    default:
                        BSL_LOG_ERR("INVALID SC ID\n");
                        json_decref(root);
                        return;
                }
            }
        }
    }

    // event set
    json_t *event_set = json_object_get(root, "event_set");
    if (event_set && json_is_object(event_set))
    {
        // es_ref
        json_t *es_ref_es = json_object_get(policyrule, "es_ref");
        if (!es_ref_es || !json_is_string(es_ref_es))
        {
            BSL_LOG_DEBUG("NO ES REF");
        }

        json_t *events = json_object_get(event_set, "events");
        if (events && json_is_array(events))
        {
            size_t i, n = json_array_size(events);
            BSL_LOG_DEBUG("num events (%zu):\n", n);
            for (i = 0; i < n; ++i)
            {
                json_t *entry = json_array_get(events, i);
                if (!json_is_object(entry))
                    continue;

                json_t *event_id = json_object_get(entry, "event_id");
                if (!event_id)
                    continue;
                const char *event_id_str = json_string_value(event_id);

                BSL_LOG_DEBUG("EVENT ID FOUND: %s", event_id_str);

                json_t *actions = json_object_get(entry, "actions");
                if (actions && json_is_array(actions))
                {
                    size_t j, m = json_array_size(actions);
                    BSL_LOG_DEBUG("num actions in %s (%zu):\n", event_id_str, m);
                    for (j = 0; j < m; ++j)
                    {
                        json_t *act = json_array_get(actions, j);
                        if (!json_is_string(act))
                            continue;

                        const char *act_str = json_string_value(act);
                        BSL_LOG_DEBUG("Action of %s: %s", event_id_str, act_str);
                    }
                }
            }
        }
    }

    json_decref(root);
}

int bsl_mock_bpa_rfc9173_bcb_cek(unsigned char *buf, int len)
{
    if (len == 12) // IV
    {
        uint8_t iv[] = { 0x54, 0x77, 0x65, 0x6c, 0x76, 0x65, 0x31, 0x32, 0x31, 0x32, 0x31, 0x32 };
        memcpy(buf, iv, 12);
    }
    else // A3 KEY
    {
        uint8_t rfc9173A3_key[] = { 0x71, 0x77, 0x65, 0x72, 0x74, 0x79, 0x75, 0x69,
                                    0x6f, 0x70, 0x61, 0x73, 0x64, 0x66, 0x67, 0x68 };
        memcpy(buf, rfc9173A3_key, len);
    }
    return 1;
}

static void mock_bpa_register_policy(const bsl_mock_policy_configuration_t policy_bits, BSLP_PolicyProvider_t *policy,
                                     mock_bpa_policy_params_t *params)
{

    BSL_LOG_DEBUG("\nInterpreted policy: 0x%X\n", policy_bits);

    uint32_t sec_block_type     = policy_bits & 0x01;
    uint32_t policy_loc         = (policy_bits >> 1) & 0x01;
    uint32_t bundle_block_type  = (policy_bits >> 2) & 0x03;
    uint32_t policy_action_type = (policy_bits >> 4) & 0x03;
    uint32_t sec_role           = (policy_bits >> 6) & 0x03;
    uint32_t use_wrapped_key    = (policy_bits >> 8) & 0x01;
    uint32_t policy_ignore      = (policy_bits >> 9) & 0x01;

    uint64_t sec_context;

    // Init params for BCB if equal to 1, otherwise BIB
    if (sec_block_type == 1)
    {
        BSL_SecParam_InitInt64(params->param_aad_scope_flag, RFC9173_BCB_SECPARAM_AADSCOPE,
                               RFC9173_BCB_AADSCOPEFLAGID_INC_NONE);
        BSL_SecParam_InitInt64(params->param_aes_variant, RFC9173_BCB_SECPARAM_AESVARIANT,
                               RFC9173_BCB_AES_VARIANT_A128GCM);
        if (use_wrapped_key)
        {
            BSL_SecParam_InitStr(params->param_test_key, BSL_SECPARAM_TYPE_KEY_ID, "9103");
            BSL_SecParam_InitInt64(params->param_use_wrapped_key, BSL_SECPARAM_TYPE_INT_USE_WRAPPED_KEY, 1);
        }
        else
        {
            BSL_SecParam_InitStr(params->param_test_key, BSL_SECPARAM_TYPE_KEY_ID, "9102");
            BSL_SecParam_InitInt64(params->param_use_wrapped_key, BSL_SECPARAM_TYPE_INT_USE_WRAPPED_KEY, 0);
        }
    }
    else
    {
        BSL_SecParam_InitInt64(params->param_integ_scope_flag, RFC9173_BIB_PARAMID_INTEG_SCOPE_FLAG, 0);
        BSL_SecParam_InitInt64(params->param_sha_variant, RFC9173_BIB_PARAMID_SHA_VARIANT, RFC9173_BIB_SHA_HMAC512);
        BSL_SecParam_InitStr(params->param_test_key, BSL_SECPARAM_TYPE_KEY_ID, "9100");
    }

    BSL_SecBlockType_e sec_block_emum;
    if (sec_block_type == 1)
    {
        sec_block_emum = BSL_SECBLOCKTYPE_BCB;
        sec_context    = 2;
        BSL_LOG_DEBUG("\nPolicy: 0x%X - BSL Security Block Type: BCB", policy_bits);
    }
    else
    {
        sec_block_emum = BSL_SECBLOCKTYPE_BIB;
        sec_context    = 1;
        BSL_LOG_DEBUG("\nPolicy: 0x%X - BSL Security Block Type: BIB", policy_bits);
    }

    BSL_PolicyLocation_e policy_loc_enum;
    if (policy_loc == 1)
    {
        policy_loc_enum = BSL_POLICYLOCATION_CLIN;
        BSL_LOG_DEBUG("\nPolicy: 0x%X - Policy Location: CLIN", policy_bits);
    }
    else
    {
        policy_loc_enum = BSL_POLICYLOCATION_CLOUT;
        BSL_LOG_DEBUG("\nPolicy: 0x%X - Policy Location: CLOUT", policy_bits);
    }

    BSL_BundleBlockTypeCode_e bundle_block_enum;
    switch (bundle_block_type)
    {
        case 0:
            bundle_block_enum = BSL_BLOCK_TYPE_PRIMARY;
            BSL_LOG_DEBUG("\nPolicy: 0x%X - Bundle Block Type: PRIMARY", policy_bits);
            break;
        case 1:
            bundle_block_enum = BSL_BLOCK_TYPE_PAYLOAD;
            BSL_LOG_DEBUG("\nPolicy: 0x%X - Bundle Block Type: PAYLOAD", policy_bits);
            break;
        case 2:
            bundle_block_enum = 192;
            BSL_LOG_DEBUG("\nPolicy: 0x%X - Bundle Block Type: PRIVATE (192)", policy_bits);
            break;
        case 3:
            bundle_block_enum = BSL_BLOCK_TYPE_BUNDLE_AGE;
            BSL_LOG_DEBUG("\nPolicy: 0x%X - Bundle Block Type: BUNDLE AGE", policy_bits);
            break;
        default:
            return;
    }

    BSL_PolicyAction_e policy_action_enum;
    switch (policy_action_type)
    {
        case 0:
            policy_action_enum = BSL_POLICYACTION_NOTHING;
            BSL_LOG_DEBUG("\nPolicy: 0x%X - Policy Acion: DO NOTHING", policy_bits);
            break;
        case 1:
            policy_action_enum = BSL_POLICYACTION_DROP_BLOCK;
            BSL_LOG_DEBUG("\nPolicy: 0x%X - Policy Acion: DROP BLOCK", policy_bits);
            break;
        case 2:
            policy_action_enum = BSL_POLICYACTION_DROP_BUNDLE;
            BSL_LOG_DEBUG("\nPolicy: 0x%X - Policy Acion: DROP BUNDLE", policy_bits);
            break;
        default:
            policy_action_enum = BSL_POLICYACTION_NOTHING;
            BSL_LOG_DEBUG("\nPolicy: 0x%X - Policy Acion: DO NOTHING", policy_bits);
            break;
    }

    BSL_SecRole_e sec_role_enum;
    switch (sec_role)
    {
        case 0:
            sec_role_enum = BSL_SECROLE_SOURCE;
            BSL_LOG_DEBUG("\nPolicy: 0x%X - Security Role: SOURCE", policy_bits);
            break;
        case 1:
            sec_role_enum = BSL_SECROLE_VERIFIER;
            BSL_LOG_DEBUG("\nPolicy: 0x%X - Security Role: VERIFIER", policy_bits);
            break;
        case 2:
            sec_role_enum = BSL_SECROLE_ACCEPTOR;
            BSL_LOG_DEBUG("\nPolicy: 0x%X - Security Role: ACCEPTOR", policy_bits);
            break;
        default:
            sec_role_enum = BSL_SECROLE_VERIFIER;
            BSL_LOG_DEBUG("\nPolicy: 0x%X - Security Role: VERIFIER", policy_bits);
            break;
    }

    BSL_HostEIDPattern_t eid_src_pat;
    if (policy_ignore)
    {
        BSL_LOG_INFO("Creating src eid pattern to match none - bundle should be ignored!");
        eid_src_pat = mock_bpa_util_get_eid_pattern_from_text("");
    }
    else
    {
        eid_src_pat = mock_bpa_util_get_eid_pattern_from_text("*:**");
    }

    // Create a rule to verify security block at APP/CLA Ingress
    char policybits_str[100];
    sprintf(policybits_str, "Policy: %x", policy_bits);
    BSLP_PolicyPredicate_t *predicate_all_in = &policy->predicates[policy->predicate_count++];
    BSLP_PolicyPredicate_Init(predicate_all_in, policy_loc_enum, eid_src_pat,
                              mock_bpa_util_get_eid_pattern_from_text("*:**"),
                              mock_bpa_util_get_eid_pattern_from_text("*:**"));
    BSLP_PolicyRule_t *rule_all_in = &policy->rules[policy->rule_count++];
    BSLP_PolicyRule_Init(rule_all_in, policybits_str, predicate_all_in, sec_context, sec_role_enum, sec_block_emum,
                         bundle_block_enum, policy_action_enum);

    if (sec_block_emum == BSL_SECBLOCKTYPE_BCB)
    {
        BSLP_PolicyRule_AddParam(rule_all_in, params->param_aes_variant);
        BSLP_PolicyRule_AddParam(rule_all_in, params->param_use_wrapped_key);
        if (sec_role != BSL_SECROLE_SOURCE)
        {
            BSLP_PolicyRule_AddParam(rule_all_in, params->param_aad_scope_flag);
            BSL_Crypto_SetRngGenerator(bsl_mock_bpa_rfc9173_bcb_cek);
        }
    }
    else
    {
        BSLP_PolicyRule_AddParam(rule_all_in, params->param_sha_variant);
        BSLP_PolicyRule_AddParam(rule_all_in, params->param_integ_scope_flag);
    }
    BSLP_PolicyRule_AddParam(rule_all_in, params->param_test_key);
}

void mock_bpa_handle_policy_config(char *policies, BSLP_PolicyProvider_t *policy, mock_bpa_policy_registry_t *reg)
{

    char *pt;

    // Split up and register each policy
    pt = strtok(policies, ",");
    while (pt != NULL)
    {

        mock_bpa_policy_params_t *params = mock_bpa_policy_registry_get(reg);

        if (params != NULL)
        {
            mock_bpa_register_policy(strtoul(pt, NULL, 0), policy, params);
        }
        else
        {
            BSL_LOG_ERR("\nPOLICY COUNT EXCEEDED, NOT REGISTERING FURTHER\n");
        }
        pt = strtok(NULL, ",");
    }

    BSL_LOG_DEBUG("Successfully created policy registry of size: %d\n", mock_bpa_policy_registry_size(reg));
}

int mock_bpa_key_registry_init(const char *pp_cfg_file_path)
{

    int          retval = 0;
    json_t      *root;
    json_error_t err;

    BSL_LOG_INFO("Reading keys from %s", pp_cfg_file_path);
    root = json_load_file(pp_cfg_file_path, 0, &err);
    if (!root)
    {
        BSL_LOG_ERR("JSON error: line %d: %s\n", err.line, err.text);
        json_decref(root);
        return 1;
    }

    json_t *keys = json_object_get(root, "keys");
    if (!keys || !json_is_array(keys))
    {
        BSL_LOG_ERR("Missing \"keys\" \n");
        json_decref(root);
        return 1;
    }

    size_t n = json_array_size(keys);
    printf("Found %zu key objects\n\n", n);

    for (size_t i = 0; !retval && (i < n); ++i)
    {
        json_t *key_obj = json_array_get(keys, i);
        if (!json_is_object(key_obj))
        {
            continue;
        }

        json_t *kty = json_object_get(key_obj, "kty");
        if (!kty)
        {
            BSL_LOG_ERR("Missing \"kty\" \n");
            continue;
        }

        if (0 != strcmp("oct", json_string_value(kty)))
        {
            BSL_LOG_ERR("Not a symmetric key set\n");
            continue;
        }

        json_t *kid = json_object_get(key_obj, "kid");
        if (!kid)
        {
            BSL_LOG_ERR("Missing \"kid\" \n");
            continue;
        }
        const char *kid_str = json_string_value(kid);
        BSL_LOG_DEBUG("kid: %s\n", kid_str);

        json_t *k = json_object_get(key_obj, "k");
        if (!k)
        {
            BSL_LOG_ERR("Missing \"kid\" \n");
            continue;
        }
        const char *k_str = json_string_value(k);
        BSL_LOG_DEBUG("k: %s\n", k_str);

        m_string_t k_text;
        m_string_init_set_cstr(k_text, k_str);
        m_bstring_t k_data;
        m_bstring_init(k_data);

        retval = mock_bpa_base64_decode(k_data, k_text);

        if (!retval)
        {
            const size_t   k_len = m_bstring_size(k_data);
            const uint8_t *k_ptr = m_bstring_view(k_data, 0, k_len);

            retval = BSL_Crypto_AddRegistryKey(kid_str, k_ptr, k_len);
        }
        m_bstring_clear(k_data);
        m_string_clear(k_text);
    }

    json_decref(root);

    return retval;
}
