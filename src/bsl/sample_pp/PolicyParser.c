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
#include "PolicyParser.h"
#include "bsl/front/TextUtil.h"
#include "bsl/default_sc/DefaultSecContext.h"
#include "bsl/cose_sc/CoseContext.h"
#include <strings.h>
#include <errno.h>

/** Read a text value as long integer.
 * The entire text must be consumed to be valid.
 *
 * @param[out] as_int The output value.
 * @param[in] ptr The text pointer.
 * @param len The text length (excluding null terminator).
 */
static int BSLP_GetTextAsInt(int64_t *as_int, const char *ptr, size_t len)
{
    char *endp;
    *as_int = strtoll(ptr, &endp, 0);
    if (endp != ptr + len)
    {
        BSL_LOG_ERR("Invalid text-as-integer: %s", ptr);
        return BSL_ERR_POLICY_CONFIG;
    }
    if (((*as_int == LLONG_MIN) || (*as_int == LLONG_MAX)) && (errno == ERANGE))
    {
        BSL_LOG_ERR("Overflow in text-as-integer: %s", ptr);
        return BSL_ERR_POLICY_CONFIG;
    }
    return BSL_SUCCESS;
}

/** Read a JSON value as long integer, either directly or from text.
 * @param[in] value The value to interpret.
 * @param[out] as_int The output value.
 */
static int BSLP_GetNumberInt(const json_t *value, int64_t *as_int)
{
    if (json_is_integer(value))
    {
        *as_int = json_integer_value(value);
    }
    else if (json_is_string(value))
    {
        if (BSLP_GetTextAsInt(as_int, json_string_value(value), json_string_length(value)))
        {
            return BSL_ERR_POLICY_CONFIG;
        }
    }
    else
    {
        BSL_LOG_ERR("Invalid option value type, expected int or text");
        return BSL_ERR_POLICY_CONFIG;
    }
    return BSL_SUCCESS;
}

/** Read a JSON value as hexadecimal bytes from text.
 * @param[in] value The value to interpret.
 * @param[out] as_bytes The output value.
 */
static int BSLP_GetBytesHex(const json_t *value, BSL_Data_t *as_bytes)
{
    const char *val_ptr = json_string_value(value);
    size_t      val_len = json_string_length(value);
    if (strncasecmp(val_ptr, "0x", 2) == 0)
    {
        val_ptr += 2;
        val_len -= 2;
    }
    return BSL_TextUtil_Base16_Decode(as_bytes, val_ptr, val_len);
}

/** Read a JSON value as a boolean, either directly or from text.
 * @param[in] value The value to interpret.
 * @param[out] as_bool The output value.
 */
static int BSLP_GetBoolean(const json_t *value, bool *as_bool)
{
    if (json_is_boolean(value))
    {
        *as_bool = json_is_true(value);
    }
    if (json_is_integer(value))
    {
        *as_bool = (json_integer_value(value) != 0);
        return BSL_SUCCESS;
    }
    else if (json_is_string(value))
    {
        *as_bool = !!strcmp(json_string_value(value), "0");
        return BSL_SUCCESS;
    }
    else
    {
        BSL_LOG_ERR("Invalid option value type, expected boolean or zero");
        return BSL_ERR_POLICY_CONFIG;
    }
}

/// Type for individual option handling according to each SC
typedef int (*BSLP_OptionHandler_f)(BSLB_IdValPairPtrMap_t options, const char *id_str, json_t *value);

/** Handle options for Security context ID 1.
 * Matches ::BSLP_OptionHandler_f signature.
 */
static int BSLP_PolicyOptions_SC1(BSLB_IdValPairPtrMap_t options, const char *id_str, json_t *value) // NOSONAR
{
    if (0 == strcmp(id_str, "key_name"))
    {
        BSL_IdValPair_t *opt = BSLB_IdValPairPtrMap_add(options, BSLX_BIB_OPT_KEY_ID);
        BSL_IdValPair_SetTextstr(opt, BSLX_BIB_OPT_KEY_ID, json_string_value(value));
    }
    else if (0 == strcmp(id_str, "sha_variant"))
    {
        int64_t as_int;
        if (BSLP_GetNumberInt(value, &as_int))
        {
            return BSL_ERR_POLICY_CONFIG;
        }

        BSL_IdValPair_t *opt = BSLB_IdValPairPtrMap_add(options, BSLX_BIB_OPT_SHA_VARIANT);
        BSL_IdValPair_SetInt64(opt, BSLX_BIB_OPT_SHA_VARIANT, as_int);
    }
    else if (0 == strcmp(id_str, "scope_flags"))
    {
        int64_t as_int;
        if (BSLP_GetNumberInt(value, &as_int))
        {
            return BSL_ERR_POLICY_CONFIG;
        }

        BSL_IdValPair_t *opt = BSLB_IdValPairPtrMap_add(options, BSLX_BIB_OPT_SCOPE);
        BSL_IdValPair_SetInt64(opt, BSLX_BIB_OPT_SCOPE, as_int);
    }
    else if (0 == strcmp(id_str, "key_wrap"))
    {
        bool as_bool;
        if (BSLP_GetBoolean(value, &as_bool))
        {
            return BSL_ERR_POLICY_CONFIG;
        }

        BSL_IdValPair_t *opt = BSLB_IdValPairPtrMap_add(options, BSLX_BIB_OPT_USE_KEY_WRAP);
        BSL_IdValPair_SetInt64(opt, BSLX_BIB_OPT_USE_KEY_WRAP, (int64_t)as_bool);
    }
    else
    {
        BSL_LOG_ERR("INVALID PARAM KEY %s FOR SC ID 1", id_str);
        return BSL_ERR_POLICY_CONFIG;
    }
    return BSL_SUCCESS;
}

/** Handle options for Security context ID 2.
 * Matches ::BSLP_OptionHandler_f signature.
 */
static int BSLP_PolicyOptions_SC2(BSLB_IdValPairPtrMap_t options, const char *id_str, json_t *value) // NOSONAR
{
    if (0 == strcmp(id_str, "key_name"))
    {
        BSL_IdValPair_t *opt = BSLB_IdValPairPtrMap_add(options, BSLX_BCB_OPT_KEY_ID);
        BSL_IdValPair_SetTextstr(opt, BSLX_BCB_OPT_KEY_ID, json_string_value(value));
    }
    else if (0 == strcmp(id_str, "aes_variant"))
    {
        int64_t as_int;
        if (BSLP_GetNumberInt(value, &as_int))
        {
            return BSL_ERR_POLICY_CONFIG;
        }

        BSL_IdValPair_t *opt = BSLB_IdValPairPtrMap_add(options, BSLX_BCB_OPT_AES_VARIANT);
        BSL_IdValPair_SetInt64(opt, BSLX_BCB_OPT_AES_VARIANT, as_int);
    }
    else if (0 == strcmp(id_str, "aad_scope"))
    {
        int64_t as_int;
        if (BSLP_GetNumberInt(value, &as_int))
        {
            return BSL_ERR_POLICY_CONFIG;
        }

        BSL_IdValPair_t *opt = BSLB_IdValPairPtrMap_add(options, BSLX_BCB_OPT_SCOPE);
        BSL_IdValPair_SetInt64(opt, BSLX_BCB_OPT_SCOPE, as_int);
    }
    else if (0 == strcmp(id_str, "key_wrap"))
    {
        bool as_bool;
        if (BSLP_GetBoolean(value, &as_bool))
        {
            return BSL_ERR_POLICY_CONFIG;
        }

        BSL_IdValPair_t *opt = BSLB_IdValPairPtrMap_add(options, BSLX_BCB_OPT_USE_KEY_WRAP);
        BSL_IdValPair_SetInt64(opt, BSLX_BCB_OPT_USE_KEY_WRAP, (int64_t)as_bool);
    }
    else
    {
        BSL_LOG_ERR("INVALID PARAM KEY %s FOR SC ID 2", id_str);
        return BSL_ERR_POLICY_CONFIG;
    }
    return BSL_SUCCESS;
}

/** Handle options for Security context ID 3.
 * Matches ::BSLP_OptionHandler_f signature.
 */
static int BSLP_PolicyOptions_SC3(BSLB_IdValPairPtrMap_t options, const char *id_str, json_t *value) // NOSONAR
{
    if (0 == strcmp(id_str, "key_id"))
    {
        const char *val_str = json_string_value(value);
        if (!val_str)
        {
            return BSL_ERR_POLICY_CONFIG;
        }
        BSL_Data_t as_bytes = BSL_DATA_INIT_VIEW_CSTR(val_str);

        BSL_IdValPair_t *opt = BSLB_IdValPairPtrMap_add(options, BSLX_COSESC_OPTION_KEY_ID);
        BSL_IdValPair_SetBytestr(opt, BSLX_COSESC_OPTION_KEY_ID, as_bytes);
    }
    else if (0 == strcasecmp(id_str, "target_alg"))
    {
        int64_t as_int;
        if (BSLP_GetNumberInt(value, &as_int))
        {
            return BSL_ERR_POLICY_CONFIG;
        }

        BSL_IdValPair_t *opt = BSLB_IdValPairPtrMap_add(options, BSLX_COSESC_OPTION_TGT_ALG);
        BSL_IdValPair_SetInt64(opt, BSLX_COSESC_OPTION_TGT_ALG, as_int);
    }
    else if (0 == strcasecmp(id_str, "aad_scope"))
    {
        void *val_it = json_object_iter(value);
        if (!val_it)
        {
            BSL_LOG_ERR("AAD Scope is not an object");
            return BSL_ERR_POLICY_CONFIG;
        }

        BSLX_CoseSc_AadScope_t scope;
        BSLX_CoseSc_AadScope_init(scope);
        while (val_it)
        {
            int64_t blk_num;
            if (BSLP_GetTextAsInt(&blk_num, json_object_iter_key(val_it), json_object_iter_key_len(val_it)))
            {
                BSL_LOG_ERR("AAD Scope invalid map key");
                BSLX_CoseSc_AadScope_clear(scope);
                return BSL_ERR_POLICY_CONFIG;
            }
            int64_t aad_flags;
            if (BSLP_GetNumberInt(json_object_iter_value(val_it), &aad_flags))
            {
                BSL_LOG_ERR("AAD Scope invalid map value");
                BSLX_CoseSc_AadScope_clear(scope);
                return BSL_ERR_POLICY_CONFIG;
            }

            BSL_LOG_DEBUG("AAD Scope for block %" PRId64 " has flags 0x%" PRIx64, blk_num, aad_flags);
            BSLX_CoseSc_AadScope_set_at(scope, blk_num, aad_flags);

            val_it = json_object_iter_next(value, val_it);
        }

        BSL_Data_t enc_scope;
        BSL_Data_Init(&enc_scope);
        int res = BSL_CBOR_Encode_Twopass(&enc_scope, (BSL_CBOR_Encode_f)&BSLX_CoseSc_AadScope_Encode, &scope);
        BSLX_CoseSc_AadScope_clear(scope);
        if (BSL_SUCCESS != res)
        {
            BSL_LOG_ERR("Failed to encode AAD Scope");
            BSL_Data_Deinit(&enc_scope);
            return BSL_ERR_POLICY_CONFIG;
        }

        BSL_IdValPair_t *opt = BSLB_IdValPairPtrMap_add(options, BSLX_COSESC_OPTION_AAD_SCOPE);
        BSL_IdValPair_SetRaw(opt, BSLX_COSESC_OPTION_AAD_SCOPE, enc_scope.ptr, enc_scope.len);
        BSL_Data_Deinit(&enc_scope);
    }
    else if (0 == strcasecmp(id_str, "iv_base"))
    {
        BSL_Data_t as_bytes;
        BSL_Data_Init(&as_bytes);
        if (BSLP_GetBytesHex(value, &as_bytes))
        {
            return BSL_ERR_POLICY_CONFIG;
        }

        BSL_IdValPair_t *opt = BSLB_IdValPairPtrMap_add(options, BSLX_COSESC_OPTION_IV_BASE);
        BSL_IdValPair_SetBytestr(opt, BSLX_COSESC_OPTION_IV_BASE, as_bytes);
        BSL_Data_Deinit(&as_bytes);
    }
    else if (0 == strcasecmp(id_str, "iv_counter_offset"))
    {
        int64_t as_int;
        if (BSLP_GetNumberInt(value, &as_int))
        {
            return BSL_ERR_POLICY_CONFIG;
        }

        BSL_IdValPair_t *opt = BSLB_IdValPairPtrMap_add(options, BSLX_COSESC_OPTION_IV_COUNTER_OFFSET);
        BSL_IdValPair_SetInt64(opt, BSLX_COSESC_OPTION_IV_COUNTER_OFFSET, as_int);
    }
    else if (0 == strcasecmp(id_str, "salt_length"))
    {
        int64_t as_int;
        if (BSLP_GetNumberInt(value, &as_int))
        {
            return BSL_ERR_POLICY_CONFIG;
        }

        BSL_IdValPair_t *opt = BSLB_IdValPairPtrMap_add(options, BSLX_COSESC_OPTION_SALT_LENGTH);
        BSL_IdValPair_SetInt64(opt, BSLX_COSESC_OPTION_SALT_LENGTH, as_int);
    }
    else if (0 == strcasecmp(id_str, "salt_base"))
    {
        BSL_Data_t as_bytes;
        BSL_Data_Init(&as_bytes);
        if (BSLP_GetBytesHex(value, &as_bytes))
        {
            return BSL_ERR_POLICY_CONFIG;
        }

        BSL_IdValPair_t *opt = BSLB_IdValPairPtrMap_add(options, BSLX_COSESC_OPTION_SALT_BASE);
        BSL_IdValPair_SetBytestr(opt, BSLX_COSESC_OPTION_SALT_BASE, as_bytes);
        BSL_Data_Deinit(&as_bytes);
    }
    else if (0 == strcasecmp(id_str, "salt_counter_offset"))
    {
        int64_t as_int;
        if (BSLP_GetNumberInt(value, &as_int))
        {
            return BSL_ERR_POLICY_CONFIG;
        }

        BSL_IdValPair_t *opt = BSLB_IdValPairPtrMap_add(options, BSLX_COSESC_OPTION_SALT_COUNTER_OFFSET);
        BSL_IdValPair_SetInt64(opt, BSLX_COSESC_OPTION_SALT_COUNTER_OFFSET, as_int);
    }
    else
    {
        BSL_LOG_ERR("INVALID PARAM KEY %s FOR SC ID 3", id_str);
        return BSL_ERR_POLICY_CONFIG;
    }
    return BSL_SUCCESS;
}

static int BSLP_PolicyParser_ReadOneRule(BSLP_PolicyProvider_t *policy, const json_t *policy_rule_elm)
{
    const char          *src_str;
    const char          *dest_str;
    const char          *sec_src_str;
    const char          *rule_id_str;
    BSL_SecBlockType_e   sec_block_type;
    int64_t              sec_ctx_id;
    BSL_SecRole_e        sec_role;
    uint64_t             target_block_type;
    BSL_PolicyLocation_e policy_loc_enum;
    BSL_PolicyAction_e   policy_action_enum;

    if (!json_is_object(policy_rule_elm))
    {
        BSL_LOG_ERR("Policy rule not JSON object");
        return BSL_ERR_POLICY_CONFIG;
    }

    // policyrule attr
    const json_t *policyrule = json_object_get(policy_rule_elm, "policyrule");
    if (!policyrule || !json_is_object(policyrule))
    {
        BSL_LOG_ERR("Missing policyrule");
        return BSL_ERR_POLICY_CONFIG;
    }

    // filter attr
    const json_t *filter = json_object_get(policyrule, "filter");
    if (!filter || !json_is_object(filter))
    {
        BSL_LOG_ERR("Invalid filter attribute");
        return BSL_ERR_POLICY_CONFIG;
    }
    else
    {
        BSL_LOG_DEBUG("filter:");

        // Get rule_id
        const json_t *rule_id = json_object_get(filter, "rule_id");
        if (!rule_id)
        {
            BSL_LOG_ERR("No rule ID ");
            return BSL_ERR_POLICY_CONFIG;
        }
        rule_id_str = json_string_value(rule_id);
        BSL_LOG_DEBUG("     rule_id: %s", rule_id_str);

        // get sec role
        const json_t *role = json_object_get(filter, "role");
        if (!role)
        {
            BSL_LOG_ERR("No sec role");
            return BSL_ERR_POLICY_CONFIG;
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
            return BSL_ERR_POLICY_CONFIG;
        }

        const json_t *src = json_object_get(filter, "src");
        if (src)
        {
            src_str = json_string_value(src);
            BSL_LOG_DEBUG("     src    : %s", src_str);
        }
        else
        {
            src_str = "*:**";
        }

        const json_t *dest = json_object_get(filter, "dest");
        if (dest)
        {
            dest_str = json_string_value(dest);
            BSL_LOG_DEBUG("     dest    : %s", dest_str);
        }
        else
        {
            dest_str = "*:**";
        }

        const json_t *sec_src = json_object_get(filter, "sec_src");
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
        const json_t *tgt = json_object_get(filter, "tgt");
        if (!tgt)
        {
            BSL_LOG_ERR("No tgt");
            return BSL_ERR_POLICY_CONFIG;
        }
        const json_int_t tgt_l = json_integer_value(tgt);
        BSL_LOG_DEBUG("     tgt    : %" JSON_INTEGER_FORMAT, tgt_l);
        if (tgt_l < 0)
        {
            BSL_LOG_ERR("Invalid tgt");
            return BSL_ERR_POLICY_CONFIG;
        }
        target_block_type = (uint64_t)tgt_l;

        // check loc (sec location )
        const json_t *loc = json_object_get(filter, "loc");
        if (!loc)
        {
            BSL_LOG_ERR("No loc");
            return BSL_ERR_POLICY_CONFIG;
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
            return BSL_ERR_POLICY_CONFIG;
        }

        const json_t *sc_id = json_object_get(filter, "sc_id");
        if (!sc_id || !json_is_integer(sc_id))
        {
            BSL_LOG_DEBUG("NO SEC CTX ID");
            return BSL_ERR_POLICY_CONFIG;
        }
        const json_int_t sc_id_l = json_integer_value(sc_id);
        BSL_LOG_DEBUG("     sc_id    : %" JSON_INTEGER_FORMAT, sc_id_l);
    }

    // es_ref
    const json_t *es_ref = json_object_get(policyrule, "es_ref");
    if (!es_ref || !json_is_string(es_ref))
    {
        BSL_LOG_INFO("NO ES REF");
    }

    // policy_action_on_fail
    const json_t *policy_action_on_fail = json_object_get(policyrule, "policy_action_on_fail");
    if (!policy_action_on_fail || !json_is_string(policy_action_on_fail))
    {
        BSL_LOG_ERR("NO POLICY ACTION");
        return BSL_ERR_POLICY_CONFIG;
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
        return BSL_ERR_POLICY_CONFIG;
    }

    BSLB_IdValPairPtrMap_t options;
    BSLB_IdValPairPtrMap_init(options);

    // spec attr
    const json_t *spec = json_object_get(policyrule, "spec");
    if (!spec && !json_is_object(spec))
    {
        BSL_LOG_ERR("Invalid spec attribute");
        BSLB_IdValPairPtrMap_clear(options);
        return BSL_ERR_POLICY_CONFIG;
    }
    else
    {
        BSL_LOG_DEBUG("spec:");

        const json_t *svc     = json_object_get(spec, "svc");
        const char   *svc_str = json_string_value(svc);
        BSL_LOG_DEBUG("     svc: %s", svc_str);
        if ((strcmp(svc_str, "bib") == 0) || (strcmp(svc_str, "bib-integrity") == 0))
        {
            sec_block_type = BSL_SECBLOCKTYPE_BIB;
        }
        else if ((strcmp(svc_str, "bcb") == 0) || (strcmp(svc_str, "bcb-confidentiality") == 0))
        {
            sec_block_type = BSL_SECBLOCKTYPE_BCB;
        }
        else
        {
            BSL_LOG_ERR("Invalid svc parameter: %s", svc_str);
            BSLB_IdValPairPtrMap_clear(options);
            return BSL_ERR_POLICY_CONFIG;
        }

        // check sec ctx id
        const json_t    *sc_id   = json_object_get(spec, "sc_id");
        const json_int_t sc_id_l = json_integer_value(sc_id);
        BSL_LOG_DEBUG("     sc_id: %" JSON_INTEGER_FORMAT, sc_id_l);
        sec_ctx_id = (int64_t)sc_id_l;

        // different valid param IDs for different contexts
        BSLP_OptionHandler_f handler = NULL;
        switch (sc_id_l)
        {
            case RFC9173_CONTEXTID_BIB_HMAC_SHA2:
                handler = &BSLP_PolicyOptions_SC1;
                break;
            case RFC9173_CONTEXTID_BCB_AES_GCM:
                handler = &BSLP_PolicyOptions_SC2;
                break;
            case BSLX_COSESC_CTX_ID:
                handler = &BSLP_PolicyOptions_SC3;
                break;
            default:
                BSL_LOG_CRIT("Unhandled context ID %" PRId64, sc_id_l);
                BSLB_IdValPairPtrMap_clear(options);
                return BSL_ERR_POLICY_CONFIG;
        }

        json_t *sc_parms = json_object_get(spec, "sc_parms");
        if (sc_parms && json_is_object(sc_parms))
        {
            for (void *val_it = json_object_iter(sc_parms); val_it; val_it = json_object_iter_next(sc_parms, val_it))
            {
                const char *id_str = json_object_iter_key(val_it);
                json_t     *value  = json_object_iter_value(val_it);

                int res = handler(options, id_str, value);
                if (BSL_SUCCESS != res)
                {
                    BSL_LOG_ERR("Failed to handle SC option: %s", id_str);
                    BSLB_IdValPairPtrMap_clear(options);
                    return res;
                }
            }
        }
        else if (sc_parms && json_is_array(sc_parms))
        {
            // legacy array form
            const size_t n = json_array_size(sc_parms);
            BSL_LOG_DEBUG("     sc_parms (%zu):", n);
            for (size_t i = 0; i < n; ++i)
            {
                const json_t *entry = json_array_get(sc_parms, i);
                if (!json_is_object(entry))
                {
                    BSL_LOG_ERR("Invalid sc_params item");
                    BSLB_IdValPairPtrMap_clear(options);
                    return BSL_ERR_POLICY_CONFIG;
                }

                const json_t *id = json_object_get(entry, "id");
                if (!id || !json_is_string(id))
                {
                    BSL_LOG_ERR("Missing sc_params item id");
                    BSLB_IdValPairPtrMap_clear(options);
                    return BSL_ERR_POLICY_CONFIG;
                }
                const char *id_str = json_string_value(id);

                json_t *value = json_object_get(entry, "value");
                if (!value)
                {
                    BSL_LOG_ERR("Missing sc_params item value");
                    BSLB_IdValPairPtrMap_clear(options);
                    return BSL_ERR_POLICY_CONFIG;
                }
                const char *value_str = json_string_value(value);
                BSL_LOG_DEBUG("         - id: %s, value: %s", id_str, value_str);

                int res = handler(options, id_str, value);
                if (BSL_SUCCESS != res)
                {
                    BSL_LOG_ERR("Failed to handle SC option: %s", id_str);
                    BSLB_IdValPairPtrMap_clear(options);
                    return res;
                }
            }
        }
        else
        {
            BSL_LOG_ERR("No valid sc_parms present");
            BSLB_IdValPairPtrMap_clear(options);
            return BSL_ERR_POLICY_CONFIG;
        }
    }

    BSLP_PolicyPredicate_t predicate;
    BSLP_PolicyPredicate_InitFrom(&predicate, policy_loc_enum, src_str, sec_src_str, dest_str);

    BSLP_PolicyRule_t rule;
    BSLP_PolicyRule_InitFrom(&rule, rule_id_str, sec_ctx_id, sec_role, sec_block_type, target_block_type,
                             policy_action_enum);

    // move options into rule
    BSLB_IdValPairPtrMap_it_t opt_it;
    for (BSLB_IdValPairPtrMap_it(opt_it, options); !BSLB_IdValPairPtrMap_end_p(opt_it);
         BSLB_IdValPairPtrMap_next(opt_it))
    {
        BSL_IdValPair_Set(BSLP_PolicyRule_AddOption(&rule),
                          BSLB_IdValPairPtr_ref(*BSLB_IdValPairPtrMap_ref(opt_it)->value_ptr));
    }

    BSLP_PolicyProvider_AddRule(policy, &rule, &predicate);
    BSLB_IdValPairPtrMap_clear(options);
    return BSL_SUCCESS;
}

int BSLP_PolicyParser_FromJSON(const char *policy_cfg_path, BSLP_PolicyProvider_t *policy)
{
    CHK_ARG_NONNULL(policy_cfg_path);
    CHK_ARG_NONNULL(policy);

    json_t      *root;
    json_error_t err;

    root = json_load_file(policy_cfg_path, 0, &err);
    if (!root)
    {
        BSL_LOG_ERR("JSON error: line %d: %s", err.line, err.text);
        return BSL_ERR_POLICY_CONFIG;
    }

    // policyrule_set attr
    const json_t *policyrule_set = json_object_get(root, "policyrule_set");
    if (!policyrule_set || !json_is_array(policyrule_set))
    {
        BSL_LOG_ERR("Missing policyrule set ");
        json_decref(root);
        return BSL_ERR_POLICY_CONFIG;
    }

    const size_t policy_rule_ct = json_array_size(policyrule_set);
    BSL_LOG_DEBUG(" got (%zu) policyrules:", policy_rule_ct);
    size_t failures = 0;
    for (size_t policy_rule_idx = 0; policy_rule_idx < policy_rule_ct; ++policy_rule_idx)
    {
        const json_t *policy_rule_elm = json_array_get(policyrule_set, policy_rule_idx);

        int res = BSLP_PolicyParser_ReadOneRule(policy, policy_rule_elm);
        if (BSL_SUCCESS != res)
        {
            ++failures;
        }
    }

    // event set (currently parsed, but not utilized/initialized meaningfully)
    const json_t *event_set = json_object_get(root, "event_set");
    if (event_set && json_is_object(event_set))
    {
        // es_ref
        const json_t *es_ref_es = json_object_get(event_set, "es_ref");
        if (!es_ref_es || !json_is_string(es_ref_es))
        {
            BSL_LOG_DEBUG("NO ES REF");
        }

        const json_t *events = json_object_get(event_set, "events");
        if (events && json_is_array(events))
        {
            size_t n = json_array_size(events);
            BSL_LOG_DEBUG("num events (%zu):", n);
            for (size_t i = 0; i < n; ++i)
            {
                const json_t *entry = json_array_get(events, i);
                if (!json_is_object(entry))
                {
                    return BSL_ERR_POLICY_CONFIG;
                }

                const json_t *event_id = json_object_get(entry, "event_id");
                if (!event_id)
                {
                    return BSL_ERR_POLICY_CONFIG;
                }
                const char *event_id_str = json_string_value(event_id);
                BSL_LOG_DEBUG("EVENT ID FOUND: %s", event_id_str);

                const json_t *actions = json_object_get(entry, "actions");
                if (actions && json_is_array(actions))
                {
                    const size_t m = json_array_size(actions);
                    BSL_LOG_DEBUG("num actions in %s (%zu):", event_id_str, m);
                    for (size_t j = 0; j < m; ++j)
                    {
                        const json_t *act = json_array_get(actions, j);
                        if (!json_is_string(act))
                        {
                            return BSL_ERR_POLICY_CONFIG;
                        }

                        const char *act_str = json_string_value(act);
                        BSL_LOG_DEBUG("Action of %s: %s", event_id_str, act_str);
                    }
                }
            }
        }
    }

    json_decref(root);
    if (failures)
    {
        BSL_LOG_ERR("Policy contains %zu invalid rules", failures);
        return BSL_ERR_POLICY_CONFIG;
    }

    return BSL_SUCCESS;
}

static void BSLP_RegisterPolicyFromBitstring(const BSLP_PolicyParser_BitstringConfig_t policy_bits,
                                             BSLP_PolicyProvider_t *policy, BSLB_IdValPairPtrMap_t options)
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

    if (sec_block_type == 1)
    {
        {
            BSL_IdValPair_t *opt = BSLB_IdValPairPtrMap_add(options, BSLX_BCB_OPT_SCOPE);
            BSL_IdValPair_SetInt64(opt, BSLX_BCB_OPT_SCOPE, RFC9173_BCB_AADSCOPEFLAGID_INC_NONE);
        }
        {
            BSL_IdValPair_t *opt = BSLB_IdValPairPtrMap_add(options, BSLX_BCB_OPT_AES_VARIANT);
            BSL_IdValPair_SetInt64(opt, BSLX_BCB_OPT_AES_VARIANT, RFC9173_BCB_AES_VARIANT_A128GCM);
        }
        if (use_wrapped_key)
        {
            {
                BSL_IdValPair_t *opt = BSLB_IdValPairPtrMap_add(options, BSLX_BCB_OPT_KEY_ID);
                BSL_IdValPair_SetTextstr(opt, BSLX_BCB_OPT_KEY_ID, "9103");
            }
            {
                BSL_IdValPair_t *opt = BSLB_IdValPairPtrMap_add(options, BSLX_BCB_OPT_USE_KEY_WRAP);
                BSL_IdValPair_SetInt64(opt, BSLX_BCB_OPT_USE_KEY_WRAP, 1);
            }
        }
        else
        {
            {
                BSL_IdValPair_t *opt = BSLB_IdValPairPtrMap_add(options, BSLX_BCB_OPT_KEY_ID);
                BSL_IdValPair_SetTextstr(opt, BSLX_BCB_OPT_KEY_ID, "9102");
            }
            {
                BSL_IdValPair_t *opt = BSLB_IdValPairPtrMap_add(options, BSLX_BCB_OPT_USE_KEY_WRAP);
                BSL_IdValPair_SetInt64(opt, BSLX_BCB_OPT_USE_KEY_WRAP, 0);
            }
        }
    }
    else
    {
        {
            BSL_IdValPair_t *opt = BSLB_IdValPairPtrMap_add(options, BSLX_BIB_OPT_SCOPE);
            BSL_IdValPair_SetInt64(opt, BSLX_BIB_OPT_SCOPE, 0);
        }
        {
            BSL_IdValPair_t *opt = BSLB_IdValPairPtrMap_add(options, BSLX_BIB_OPT_SHA_VARIANT);
            BSL_IdValPair_SetInt64(opt, BSLX_BIB_OPT_SHA_VARIANT, RFC9173_BIB_SHA_HMAC512);
        }
        {
            BSL_IdValPair_t *opt = BSLB_IdValPairPtrMap_add(options, BSLX_BIB_OPT_KEY_ID);
            BSL_IdValPair_SetTextstr(opt, BSLX_BIB_OPT_KEY_ID, "9100");
        }
        {
            BSL_IdValPair_t *opt = BSLB_IdValPairPtrMap_add(options, BSLX_BIB_OPT_USE_KEY_WRAP);
            BSL_IdValPair_SetInt64(opt, BSLX_BIB_OPT_USE_KEY_WRAP, 0);
        }
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

    // move options into rule
    BSLB_IdValPairPtrMap_it_t opt_it;
    for (BSLB_IdValPairPtrMap_it(opt_it, options); !BSLB_IdValPairPtrMap_end_p(opt_it);
         BSLB_IdValPairPtrMap_next(opt_it))
    {
        BSL_IdValPair_Set(BSLP_PolicyRule_AddOption(&rule_all_in),
                          BSLB_IdValPairPtr_ref(*BSLB_IdValPairPtrMap_ref(opt_it)->value_ptr));
    }

    BSLP_PolicyProvider_AddRule(policy, &rule_all_in, &predicate_all_in);
}

int BSLP_PolicyParser_FromBitstringList(const char *policies, BSLP_PolicyProvider_t *policy)
{
    CHK_ARG_NONNULL(policies);
    CHK_ARG_NONNULL(policy);

    // Split up and register each policy
    const char *curs = policies;
    char       *pend;
    while (true)
    {
        BSLB_IdValPairPtrMap_t options;
        BSLB_IdValPairPtrMap_init(options);

        unsigned long val = strtoul(curs, &pend, 0);
        if ((pend == curs) || (val > INT_MAX))
        {
            BSL_LOG_ERR("Failed to decode policy integer at: %s", curs);
        }
        curs = pend;
        BSLP_RegisterPolicyFromBitstring((int)val, policy, options);
        BSLB_IdValPairPtrMap_clear(options);

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
