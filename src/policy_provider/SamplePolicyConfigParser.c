#include "SamplePolicyConfigParser.h"

int BSLP_InitParams_Init(BSLP_InitParams_t *params)
{
    params->param_integ_scope_flag = BSL_calloc(1, BSL_SecParam_Sizeof());
    if (NULL == params->param_integ_scope_flag)
    {
        return BSL_ERR_INSUFFICIENT_SPACE;
    }

    params->param_sha_variant = BSL_calloc(1, BSL_SecParam_Sizeof());
    if (NULL == params->param_sha_variant)
    {
        return BSL_ERR_INSUFFICIENT_SPACE;
    }

    params->param_aad_scope_flag = BSL_calloc(1, BSL_SecParam_Sizeof());
    if (NULL == params->param_aad_scope_flag)
    {
        return BSL_ERR_INSUFFICIENT_SPACE;
    }

    params->param_init_vector = BSL_calloc(1, BSL_SecParam_Sizeof());
    if (NULL == params->param_init_vector)
    {
        return BSL_ERR_INSUFFICIENT_SPACE;
    }

    params->param_aes_variant = BSL_calloc(1, BSL_SecParam_Sizeof());
    if (NULL == params->param_aes_variant)
    {
        return BSL_ERR_INSUFFICIENT_SPACE;
    }

    params->param_test_key = BSL_calloc(1, BSL_SecParam_Sizeof());
    if (NULL == params->param_test_key)
    {
        return BSL_ERR_INSUFFICIENT_SPACE;
    }

    params->param_use_wrapped_key = BSL_calloc(1, BSL_SecParam_Sizeof());
    if (NULL == params->param_use_wrapped_key)
    {
        return BSL_ERR_INSUFFICIENT_SPACE;
    }

    return BSL_SUCCESS;
}

void BSLP_InitParams_Deinit(BSLP_InitParams_t *params)
{
    BSL_SecParam_Deinit(params->param_integ_scope_flag);
    BSL_free(params->param_integ_scope_flag);
    BSL_SecParam_Deinit(params->param_sha_variant);
    BSL_free(params->param_sha_variant);
    BSL_SecParam_Deinit(params->param_aad_scope_flag);
    BSL_free(params->param_aad_scope_flag);
    BSL_SecParam_Deinit(params->param_init_vector);
    BSL_free(params->param_init_vector);
    BSL_SecParam_Deinit(params->param_aes_variant);
    BSL_free(params->param_aes_variant);
    BSL_SecParam_Deinit(params->param_test_key);
    BSL_free(params->param_test_key);
    BSL_SecParam_Deinit(params->param_use_wrapped_key);
    BSL_free(params->param_use_wrapped_key);
}

/**
 * @todo Handle ION events as policy actions - dependent on other BSL issues/ future changes
 */
int BSLP_RegisterPolicyFromJSON(const char *policy_cfg_path, BSLP_PolicyProvider_t *policy)
{
    CHK_ARG_NONNULL(policy_cfg_path);
    CHK_ARG_NONNULL(policy);

    BSL_SecBlockType_e   sec_block_type;
    int64_t              sec_ctx_id;
    BSL_SecRole_e        sec_role;
    uint64_t             target_block_type;
    BSL_PolicyLocation_e policy_loc_enum;
    BSL_PolicyAction_e   policy_action_enum;

    const char *src_str;
    const char *dest_str;
    const char *sec_src_str;

    const char *rule_id_str;

    json_t      *root;
    json_error_t err;

    root = json_load_file(policy_cfg_path, 0, &err);
    if (!root)
    {
        BSL_LOG_ERR("JSON error: line %d: %s", err.line, err.text);
        return BSL_ERR_POLICY_CONFIG;
    }

    // policyrule_set attr
    json_t *policyrule_set = json_object_get(root, "policyrule_set");
    if (!policyrule_set || !json_is_array(policyrule_set))
    {
        BSL_LOG_ERR("Missing policyrule set ");
        json_decref(root);
        return BSL_ERR_POLICY_CONFIG;
    }

    size_t policy_rule_idx, policy_rule_ct = json_array_size(policyrule_set);
    BSL_LOG_DEBUG(" got (%zu) policyrules:", policy_rule_ct);
    for (policy_rule_idx = 0; policy_rule_idx < policy_rule_ct; ++policy_rule_idx)
    {
        json_t *policy_rule_elm = json_array_get(policyrule_set, policy_rule_idx);
        if (!json_is_object(policy_rule_elm))
        {
            BSL_LOG_ERR("Policy rule not JSON object");
            continue;
        }

        // policyrule attr
        json_t *policyrule = json_object_get(policy_rule_elm, "policyrule");
        if (!policyrule || !json_is_object(policyrule))
        {
            BSL_LOG_ERR("Missing policyrule");
            continue;
        }

        BSLP_InitParams_t params;
        int               params_init_retval = BSLP_InitParams_Init(&params);
        if (BSL_SUCCESS != params_init_retval)
        {
            BSL_LOG_ERR("JSON Policy Parse: Error allocating params");
            return params_init_retval;
        }

        // filter attr
        json_t *filter = json_object_get(policyrule, "filter");
        if (filter && json_is_object(filter))
        {
            BSL_LOG_DEBUG("filter:");

            // Get rule_id
            json_t *rule_id = json_object_get(filter, "rule_id");
            if (!rule_id)
            {
                BSL_LOG_ERR("No rule ID ");
                continue;
            }
            rule_id_str = json_string_value(rule_id);
            BSL_LOG_DEBUG("     rule_id: %s", rule_id_str);

            // get sec role
            json_t *role = json_object_get(filter, "role");
            if (!role)
            {
                BSL_LOG_ERR("No sec role");
                continue;
            }
            const char *role_str = json_string_value(role);
            BSL_LOG_DEBUG("     role   : %s", role_str);

            // check for valid sec role
            if (0 == strcmp(role_str, "s"))
            {
                sec_role = BSL_SECROLE_SOURCE;
            }
            else if (0 == strcmp(role_str, "v"))
            {
                sec_role = BSL_SECROLE_VERIFIER;
            }
            else if (0 == strcmp(role_str, "a"))
            {
                sec_role = BSL_SECROLE_ACCEPTOR;
            }
            else
            {
                BSL_LOG_ERR("INVALID SEC ROLE %s", role_str);
                continue;
            }

            json_t *src = json_object_get(filter, "src");
            if (src)
            {
                src_str = json_string_value(src);
                BSL_LOG_DEBUG("     src    : %s", src_str);
            }
            else
            {
                src_str = "*:**";
            }

            json_t *dest = json_object_get(filter, "dest");
            if (dest)
            {
                dest_str = json_string_value(dest);
                BSL_LOG_DEBUG("     dest    : %s", dest_str);
            }
            else
            {
                dest_str = "*:**";
            }

            json_t *sec_src = json_object_get(filter, "sec_src");
            if (sec_src)
            {
                sec_src_str = json_string_value(sec_src);
                BSL_LOG_DEBUG("     sec_src    : %s", sec_src_str);
            }
            else
            {
                sec_src_str = "*:**";
            }

            // check tgt (target block type)
            json_t *tgt = json_object_get(filter, "tgt");
            if (!tgt)
            {
                BSL_LOG_ERR("No tgt");
                continue;
            }
            const json_int_t tgt_l = json_integer_value(tgt);
            BSL_LOG_DEBUG("     tgt    : %" JSON_INTEGER_FORMAT, tgt_l);
            if (tgt_l < 0)
            {
                BSL_LOG_ERR("Invalid tgt");
                continue;
            }
            target_block_type = (uint64_t)tgt_l;

            // check loc (sec location )
            json_t *loc = json_object_get(filter, "loc");
            if (!loc)
            {
                BSL_LOG_ERR("No loc");
                continue;
            }
            const char *loc_str = json_string_value(loc);
            BSL_LOG_DEBUG("     loc    : %s", loc_str);

            if (0 == strcmp(loc_str, "appin"))
            {
                policy_loc_enum = BSL_POLICYLOCATION_APPIN;
            }
            else if (0 == strcmp(loc_str, "appout"))
            {
                policy_loc_enum = BSL_POLICYLOCATION_APPOUT;
            }
            else if (0 == strcmp(loc_str, "clin"))
            {
                policy_loc_enum = BSL_POLICYLOCATION_CLIN;
            }
            else if (0 == strcmp(loc_str, "clout"))
            {
                policy_loc_enum = BSL_POLICYLOCATION_CLOUT;
            }
            else
            {
                BSL_LOG_ERR("INVALID POLICY LOCATION %s", loc_str);
                continue;
            }

            json_t *sc_id = json_object_get(filter, "sc_id");
            if (!sc_id || !json_is_integer(sc_id))
            {
                BSL_LOG_DEBUG("NO SEC CTX ID");
                continue;
            }
            const json_int_t sc_id_l = json_integer_value(sc_id);
            BSL_LOG_DEBUG("     scid    : %" JSON_INTEGER_FORMAT, sc_id_l);

            sec_ctx_id     = (int64_t)sc_id_l;
            sec_block_type = (sec_ctx_id == 1) ? BSL_SECBLOCKTYPE_BIB : BSL_SECBLOCKTYPE_BCB;
        }
        else
        {
            BSL_LOG_DEBUG("NO FILTER");
            continue;
        }

        // es_ref
        json_t *es_ref = json_object_get(policyrule, "es_ref");
        if (!es_ref || !json_is_string(es_ref))
        {
            BSL_LOG_DEBUG("NO ES REF");
        }

        // policy_action_on_fail
        json_t *policy_action_on_fail = json_object_get(policyrule, "policy_action_on_fail");
        if (!policy_action_on_fail || !json_is_string(policy_action_on_fail))
        {
            BSL_LOG_ERR("NO POLICY ACTION");
            continue;
        }

        const char *policy_act_str = json_string_value(policy_action_on_fail);
        if (0 == strcmp(policy_act_str, "delete_bundle"))
        {
            policy_action_enum = BSL_POLICYACTION_DROP_BUNDLE;
        }
        else if (0 == strcmp(policy_act_str, "drop_block"))
        {
            policy_action_enum = BSL_POLICYACTION_DROP_BLOCK;
        }
        else if (0 == strcmp(policy_act_str, "nothing"))
        {
            policy_action_enum = BSL_POLICYACTION_NOTHING;
        }
        else
        {
            BSL_LOG_ERR("INVALID POLICY ACTION ENUM %s", policy_act_str);
            continue;
        }

        uint64_t params_got = 0x0;

        // spec attr
        json_t *spec = json_object_get(policyrule, "spec");
        if (spec && json_is_object(spec))
        {
            // check sec ctx id
            json_t          *sc_id   = json_object_get(spec, "sc_id");
            const json_int_t sc_id_l = json_integer_value(sc_id);

            BSL_LOG_DEBUG("spec:");
            BSL_LOG_DEBUG("     sc_id: %" JSON_INTEGER_FORMAT, sc_id_l);

            json_t *sc_parms = json_object_get(spec, "sc_parms");
            if (sc_parms && json_is_array(sc_parms))
            {
                size_t i, n = json_array_size(sc_parms);
                BSL_LOG_DEBUG("     sc_parms (%zu):", n);
                for (i = 0; i < n; ++i)
                {
                    json_t *entry = json_array_get(sc_parms, i);
                    if (!json_is_object(entry))
                    {
                        continue;
                    }

                    json_t *id = json_object_get(entry, "id");
                    if (!id || !json_is_string(id))
                    {
                        continue;
                    }
                    const char *id_str = json_string_value(id);

                    json_t *value = json_object_get(entry, "value");
                    if (!value || !json_is_string(value))
                    {
                        continue;
                    }
                    const char *value_str = json_string_value(value);

                    BSL_LOG_DEBUG("         - id: %s, value: %s", id_str, value_str);

                    // different valid param IDs for different contexts
                    switch (sc_id_l)
                    {
                        case 1:
                        {
                            if (0 == strcmp(id_str, "key_name"))
                            {
                                BSL_SecParam_InitTextstr(params.param_test_key, BSL_SECPARAM_TYPE_KEY_ID, value_str);
                                params_got |= 0x1;
                            }
                            else if (0 == strcmp(id_str, "sha_variant"))
                            {
                                uint64_t sha_var;
                                if (0 == strcmp(value_str, "5"))
                                {
                                    sha_var = RFC9173_BIB_SHA_HMAC256;
                                }
                                else if (0 == strcmp(value_str, "6"))
                                {
                                    sha_var = RFC9173_BIB_SHA_HMAC384;
                                }
                                else
                                {
                                    sha_var = RFC9173_BIB_SHA_HMAC512;
                                }

                                BSL_SecParam_InitUint64(params.param_sha_variant, RFC9173_BIB_PARAMID_SHA_VARIANT,
                                                        sha_var);
                                params_got |= 0x2;
                            }
                            else if (0 == strcmp(id_str, "scope_flags"))
                            {
                                uint64_t flag = strtol(value_str, NULL, 10); // FIXME
                                BSL_SecParam_InitUint64(params.param_integ_scope_flag,
                                                        RFC9173_BIB_PARAMID_INTEG_SCOPE_FLAG, flag);
                                params_got |= 0x4;
                            }
                            else if (0 == strcmp(id_str, "key_wrap"))
                            {
                                uint64_t keywrap;
                                if (0 == strcmp(value_str, "0"))
                                {
                                    keywrap = 0;
                                }
                                else
                                {
                                    keywrap = 1;
                                }

                                BSL_SecParam_InitUint64(params.param_use_wrapped_key, BSL_SECPARAM_USE_KEY_WRAP,
                                                        keywrap);
                                params_got |= 0x8;
                            }
                            else
                            {
                                BSL_LOG_ERR("INVALID PARAM KEY %s FOR SC ID %" JSON_INTEGER_FORMAT, id_str, sc_id_l);
                                continue;
                            }
                            break;
                        }
                        case 2:
                        {
                            if (0 == strcmp(id_str, "key_name"))
                            {
                                BSL_SecParam_InitTextstr(params.param_test_key, BSL_SECPARAM_TYPE_KEY_ID, value_str);
                                params_got |= 0x1;
                            }
                            else if (0 == strcmp(id_str, "iv"))
                            {
                                // TODO covert value_str to bstring
                                // BSL_SecParam_InitBytestr(params.param_init_vector, RFC9173_BCB_SECPARAM_IV, );
                                params_got |= 0x2;
                            }
                            else if (0 == strcmp(id_str, "aes_variant"))
                            {
                                uint64_t aes_var = strtol(value_str, NULL, 10);
                                BSL_SecParam_InitUint64(params.param_aes_variant, RFC9173_BCB_SECPARAM_AESVARIANT,
                                                        aes_var);
                                params_got |= 0x4;
                            }
                            else if (0 == strcmp(id_str, "aad_scope"))
                            {
                                uint64_t flag = strtol(value_str, NULL, 10); // FIXME
                                BSL_SecParam_InitUint64(params.param_aad_scope_flag, RFC9173_BCB_SECPARAM_AADSCOPE,
                                                        flag);
                                params_got |= 0x8;
                            }
                            else if (0 == strcmp(id_str, "key_wrap"))
                            {
                                uint64_t keywrap;
                                if (0 == strcmp(value_str, "0"))
                                {
                                    keywrap = 0;
                                }
                                else
                                {
                                    keywrap = 1;
                                }

                                BSL_SecParam_InitUint64(params.param_use_wrapped_key, BSL_SECPARAM_USE_KEY_WRAP,
                                                        keywrap);
                                params_got |= 0x10;
                            }
                            else
                            {
                                BSL_LOG_ERR("INVALID PARAM KEY %s FOR SC ID %" JSON_INTEGER_FORMAT, id_str, sc_id_l);
                                continue;
                            }
                            break;
                        }
                        default:
                        {
                            BSL_LOG_ERR("INVALID SC ID");
                            continue;
                        }
                    }
                }
            }
        }

        // event set
        // TODO currently not utilized
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
                BSL_LOG_DEBUG("num events (%zu):", n);
                for (i = 0; i < n; ++i)
                {
                    json_t *entry = json_array_get(events, i);
                    if (!json_is_object(entry))
                    {
                        continue;
                    }

                    json_t *event_id = json_object_get(entry, "event_id");
                    if (!event_id)
                    {
                        continue;
                    }
                    const char *event_id_str = json_string_value(event_id);
                    BSL_LOG_DEBUG("EVENT ID FOUND: %s", event_id_str);

                    json_t *actions = json_object_get(entry, "actions");
                    if (actions && json_is_array(actions))
                    {
                        size_t j, m = json_array_size(actions);
                        BSL_LOG_DEBUG("num actions in %s (%zu):", event_id_str, m);
                        for (j = 0; j < m; ++j)
                        {
                            json_t *act = json_array_get(actions, j);
                            if (!json_is_string(act))
                            {
                                continue;
                            }

                            const char *act_str = json_string_value(act);
                            BSL_LOG_DEBUG("Action of %s: %s", event_id_str, act_str);
                        }
                    }
                }
            }
        }

        BSLP_PolicyPredicate_t predicate;
        BSLP_PolicyPredicate_InitFrom(&predicate, policy_loc_enum, src_str, sec_src_str, dest_str);

        BSLP_PolicyRule_t rule;
        BSLP_PolicyRule_InitFrom(&rule, rule_id_str, sec_ctx_id, sec_role, sec_block_type, target_block_type,
                                 policy_action_enum);

        // TODO validate params_got
        (void)params_got;

        if (sec_ctx_id == 2) // BCB
        {
            BSLP_PolicyRule_CopyParam(&rule, params.param_aes_variant);
            if (sec_role == BSL_SECROLE_SOURCE)
            {
                BSLP_PolicyRule_CopyParam(&rule, params.param_aad_scope_flag);
            }
        }
        else
        {
            BSLP_PolicyRule_CopyParam(&rule, params.param_sha_variant);
            BSLP_PolicyRule_CopyParam(&rule, params.param_integ_scope_flag);
        }
        BSLP_PolicyRule_CopyParam(&rule, params.param_test_key);
        BSLP_PolicyRule_CopyParam(&rule, params.param_use_wrapped_key);

        BSLP_PolicyProvider_AddRule(policy, &rule, &predicate);

        BSLP_InitParams_Deinit(&params);
    }

    json_decref(root);

    return BSL_SUCCESS;
}

static void BSLP_RegisterPolicyFromBitstring(const BSLP_BitstringPolicyConfiguration_t policy_bits,
                                             BSLP_PolicyProvider_t *policy, BSLP_InitParams_t *params)
{
    BSL_LOG_DEBUG("Interpreting policy: 0x%X", policy_bits);

    uint32_t sec_block_type     = policy_bits & 0x01;
    uint32_t policy_loc         = (policy_bits >> 1) & 0x01;
    uint32_t bundle_block_type  = (policy_bits >> 2) & 0x03;
    uint32_t policy_action_type = (policy_bits >> 4) & 0x03;
    uint32_t sec_role           = (policy_bits >> 6) & 0x03;
    uint32_t use_wrapped_key    = (policy_bits >> 8) & 0x01;
    uint32_t policy_ignore      = (policy_bits >> 9) & 0x01;

    int64_t sec_context;

    // Init params for BCB if equal to 1, otherwise BIB
    if (sec_block_type == 1)
    {
        BSL_SecParam_InitUint64(params->param_aad_scope_flag, RFC9173_BCB_SECPARAM_AADSCOPE,
                                RFC9173_BCB_AADSCOPEFLAGID_INC_NONE);
        BSL_SecParam_InitUint64(params->param_aes_variant, RFC9173_BCB_SECPARAM_AESVARIANT,
                                RFC9173_BCB_AES_VARIANT_A128GCM);
        if (use_wrapped_key)
        {
            BSL_SecParam_InitTextstr(params->param_test_key, BSL_SECPARAM_TYPE_KEY_ID, "9103");
            BSL_SecParam_InitUint64(params->param_use_wrapped_key, BSL_SECPARAM_USE_KEY_WRAP, 1);
        }
        else
        {
            BSL_SecParam_InitTextstr(params->param_test_key, BSL_SECPARAM_TYPE_KEY_ID, "9102");
            BSL_SecParam_InitUint64(params->param_use_wrapped_key, BSL_SECPARAM_USE_KEY_WRAP, 0);
        }
    }
    else
    {
        BSL_SecParam_InitUint64(params->param_integ_scope_flag, RFC9173_BIB_PARAMID_INTEG_SCOPE_FLAG, 0);
        BSL_SecParam_InitUint64(params->param_sha_variant, RFC9173_BIB_PARAMID_SHA_VARIANT, RFC9173_BIB_SHA_HMAC512);
        BSL_SecParam_InitTextstr(params->param_test_key, BSL_SECPARAM_TYPE_KEY_ID, "9100");
        BSL_SecParam_InitUint64(params->param_use_wrapped_key, BSL_SECPARAM_USE_KEY_WRAP, 0);
    }

    BSL_SecBlockType_e sec_block_enum;
    if (sec_block_type == 1)
    {
        sec_block_enum = BSL_SECBLOCKTYPE_BCB;
        sec_context    = 2;
        BSL_LOG_DEBUG("Policy: 0x%X - BSL Security Block Type: BCB", policy_bits);
    }
    else
    {
        sec_block_enum = BSL_SECBLOCKTYPE_BIB;
        sec_context    = 1;
        BSL_LOG_DEBUG("Policy: 0x%X - BSL Security Block Type: BIB", policy_bits);
    }

    BSL_PolicyLocation_e policy_loc_enum;
    if (policy_loc == 1)
    {
        policy_loc_enum = BSL_POLICYLOCATION_CLIN;
        BSL_LOG_DEBUG("Policy: 0x%X - Policy Location: CLIN", policy_bits);
    }
    else
    {
        policy_loc_enum = BSL_POLICYLOCATION_CLOUT;
        BSL_LOG_DEBUG("Policy: 0x%X - Policy Location: CLOUT", policy_bits);
    }

    BSL_BundleBlockTypeCode_e bundle_block_enum;
    switch (bundle_block_type)
    {
        case 0:
            bundle_block_enum = BSL_BLOCK_TYPE_PRIMARY;
            BSL_LOG_DEBUG("Policy: 0x%X - Bundle Block Type: PRIMARY", policy_bits);
            break;
        case 1:
            bundle_block_enum = BSL_BLOCK_TYPE_PAYLOAD;
            BSL_LOG_DEBUG("Policy: 0x%X - Bundle Block Type: PAYLOAD", policy_bits);
            break;
        case 2:
            bundle_block_enum = 192;
            BSL_LOG_DEBUG("Policy: 0x%X - Bundle Block Type: PRIVATE (192)", policy_bits);
            break;
        case 3:
            bundle_block_enum = BSL_BLOCK_TYPE_BUNDLE_AGE;
            BSL_LOG_DEBUG("Policy: 0x%X - Bundle Block Type: BUNDLE AGE", policy_bits);
            break;
        default:
            return;
    }

    BSL_PolicyAction_e policy_action_enum;
    switch (policy_action_type)
    {
        case 0:
            policy_action_enum = BSL_POLICYACTION_NOTHING;
            BSL_LOG_DEBUG("Policy: 0x%X - Policy Acion: DO NOTHING", policy_bits);
            break;
        case 1:
            policy_action_enum = BSL_POLICYACTION_DROP_BLOCK;
            BSL_LOG_DEBUG("Policy: 0x%X - Policy Acion: DROP BLOCK", policy_bits);
            break;
        case 2:
            policy_action_enum = BSL_POLICYACTION_DROP_BUNDLE;
            BSL_LOG_DEBUG("Policy: 0x%X - Policy Acion: DROP BUNDLE", policy_bits);
            break;
        default:
            policy_action_enum = BSL_POLICYACTION_NOTHING;
            BSL_LOG_DEBUG("Policy: 0x%X - Policy Acion: DO NOTHING", policy_bits);
            break;
    }

    BSL_SecRole_e sec_role_enum;
    switch (sec_role)
    {
        case 0:
            sec_role_enum = BSL_SECROLE_SOURCE;
            BSL_LOG_DEBUG("Policy: 0x%X - Security Role: SOURCE", policy_bits);
            break;
        case 1:
            sec_role_enum = BSL_SECROLE_VERIFIER;
            BSL_LOG_DEBUG("Policy: 0x%X - Security Role: VERIFIER", policy_bits);
            break;
        case 2:
            sec_role_enum = BSL_SECROLE_ACCEPTOR;
            BSL_LOG_DEBUG("Policy: 0x%X - Security Role: ACCEPTOR", policy_bits);
            break;
        default:
            sec_role_enum = BSL_SECROLE_VERIFIER;
            BSL_LOG_DEBUG("Policy: 0x%X - Security Role: VERIFIER", policy_bits);
            break;
    }

    const char *eid_src_pat_str;
    if (policy_ignore)
    {
        BSL_LOG_INFO("Creating src eid pattern to match none - bundle should be ignored!");
        eid_src_pat_str = "";
    }
    else
    {
        eid_src_pat_str = "*:**";
    }

    // Create a rule to verify security block at APP/CLA Ingress
    char policybits_str[100];
    snprintf(policybits_str, 100, "Policy: %x", policy_bits);

    BSLP_PolicyPredicate_t predicate_all_in;
    BSLP_PolicyPredicate_InitFrom(&predicate_all_in, policy_loc_enum, eid_src_pat_str, "*:**", "*:**");

    BSLP_PolicyRule_t rule_all_in;
    BSLP_PolicyRule_InitFrom(&rule_all_in, policybits_str, sec_context, sec_role_enum, sec_block_enum,
                             bundle_block_enum, policy_action_enum);

    if (sec_block_enum == BSL_SECBLOCKTYPE_BCB)
    {
        BSLP_PolicyRule_CopyParam(&rule_all_in, params->param_aes_variant);
        if (sec_role_enum == BSL_SECROLE_SOURCE)
        {
            BSLP_PolicyRule_CopyParam(&rule_all_in, params->param_aad_scope_flag);
        }
    }
    else
    {
        BSLP_PolicyRule_CopyParam(&rule_all_in, params->param_sha_variant);
        BSLP_PolicyRule_CopyParam(&rule_all_in, params->param_integ_scope_flag);
    }
    BSLP_PolicyRule_CopyParam(&rule_all_in, params->param_use_wrapped_key);
    BSLP_PolicyRule_CopyParam(&rule_all_in, params->param_test_key);

    BSLP_PolicyProvider_AddRule(policy, &rule_all_in, &predicate_all_in);
}

int BSLP_RegisterPolicyFromBitstringList(const char *policies, BSLP_PolicyProvider_t *policy)
{
    CHK_ARG_NONNULL(policies);
    CHK_ARG_NONNULL(policy);

    // Split up and register each policy
    const char *curs = policies;
    char       *pend;
    while (true)
    {
        BSLP_InitParams_t params;
        int               params_init_retval = BSLP_InitParams_Init(&params);
        if (BSL_SUCCESS != params_init_retval)
        {
            BSL_LOG_ERR("JSON Policy Parse: Error allocating params");
            return params_init_retval;
        }

        uint32_t val = strtoul(curs, &pend, 0);
        if (pend == curs)
        {
            BSL_LOG_ERR("Failed to decode policy integer at: %s", curs);
        }
        curs = pend;
        BSLP_RegisterPolicyFromBitstring(val, policy, &params);
        BSLP_InitParams_Deinit(&params);

        if (*curs == '\0')
        {
            break;
        }
        else if (*curs != ',')
        {
            BSL_LOG_ERR("Failed to decode policy list (expecting comma) at: %s", curs);
        }
        curs += 1;
    }

    return BSL_SUCCESS;
}
