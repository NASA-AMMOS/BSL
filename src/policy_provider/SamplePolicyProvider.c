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

/**
 * @file
 * @brief Local implementation of locally-defined data structures.
 * @ingroup example_pp
 */
#include <stddef.h>
#include <stdlib.h>

#include <BPSecLib_Private.h>
#include <sys/types.h>

#include "SamplePolicyProvider.h"

static bool BSLP_PolicyProvider_IsConsistent(const BSLP_PolicyProvider_t *self)
{
    assert(self != NULL);
    assert(strlen(self->name) < sizeof(self->name)); // TODO - Safer strlen since no strnlen
    assert(self->rule_count < (sizeof(self->rules) / sizeof(BSLP_PolicyRule_t)));
    return true;
}

static bool BSLP_PolicyPredicate_IsConsistent(const BSLP_PolicyPredicate_t *self)
{
    assert(self != NULL);
    assert(self->location > 0);
    assert(self->dst_eid_pattern.handle != NULL);
    assert(self->src_eid_pattern.handle != NULL);
    assert(self->secsrc_eid_pattern.handle != NULL);
    return true;
}

static bool BSLP_PolicyRule_IsConsistent(const BSLP_PolicyRule_t *self)
{
    assert(self != NULL);
    assert(strlen(self->description) < sizeof(self->description));
    assert(self->params != NULL);
    assert(BSL_SECROLE_ISVALID(self->role));
    assert(self->sec_block_type > 0);
    assert(self->context_id > 0);
    // NOLINTBEGIN
    assert(BSLP_PolicyPredicate_IsConsistent(self->predicate));
    // NOLINTEND
    return true;
}

static uint64_t get_target_block_id(const BSL_BundleRef_t *bundle, uint64_t target_block_type)
{
    uint64_t target_block_num = 0;
    for (uint64_t block_index = 1; block_index < 100; block_index++)
    {
        BSL_CanonicalBlock_t test_block = { 0 };
        if (BSL_SUCCESS == BSL_BundleCtx_GetBlockMetadata(bundle, block_index, &test_block))
        {
            if (test_block.type_code == target_block_type)
            {
                target_block_num = block_index;
                break;
            }
        }
    }
    // Returns zero if target block type not found.
    return target_block_num;
}

/**
 * Note that criticality is HIGH
 */
int BSLP_QueryPolicy(const void *user_data, BSL_SecurityActionSet_t *output_action_set, const BSL_BundleRef_t *bundle,
                     BSL_PolicyLocation_e location)
{
    // This is an output struct. The caller only provides the allocation for it (which must be zero)
    const BSLP_PolicyProvider_t *self = user_data;
    assert(BSLP_PolicyProvider_IsConsistent(self));

    BSL_PrimaryBlock_t primary_block = { 0 };
    if (BSL_SUCCESS != BSL_BundleCtx_GetBundleMetadata(bundle, &primary_block))
    {
        BSL_LOG_ERR("Failed to retrieve primary block");
        return BSL_ERR_HOST_CALLBACK_FAILED;
    }

    BSL_SecurityActionSet_Init(output_action_set);

    BSL_SecurityAction_t *action = BSL_CALLOC(BSL_SecurityAction_Sizeof(), 1);
    BSLP_SecOperPtrList_t secops;
    BSLP_SecOperPtrList_init(secops);

    const size_t capacity = sizeof(self->rules) / sizeof(BSLP_PolicyRule_t);
    for (size_t index = 0; index < self->rule_count && index < capacity; index++)
    {
        const BSLP_PolicyRule_t *rule = &self->rules[index];
        CHK_PROPERTY(BSLP_PolicyRule_IsConsistent(rule));
        BSL_LOG_DEBUG("Evaluating against rule `%s`", rule->description);

        if (!BSLP_PolicyPredicate_IsMatch(rule->predicate, location, primary_block.field_src_node_id,
                                          primary_block.field_dest_eid))
        {
            BSL_LOG_DEBUG("Rule `%s` not a match", rule->description);
            continue;
        }

        uint64_t target_block_num = get_target_block_id(bundle, rule->target_block_type);
        if (target_block_num == 0 && rule->target_block_type != BSL_BLOCK_TYPE_PRIMARY)
        {
            BSL_LOG_WARNING("Cannot find target block type = %lu", rule->target_block_type);
            continue;
        }

        BSL_SecOper_t *sec_oper = BSL_CALLOC(BSL_SecOper_Sizeof(), 1);
        BSL_SecOper_Init(sec_oper);
        if (BSLP_PolicyRule_EvaluateAsSecOper(rule, sec_oper, bundle, location) < 0)
        {
            BSL_SecurityAction_IncrError(action);
        }
        else
        {
            size_t i;
            for (i = 0; i < BSLP_SecOperPtrList_size(secops); i++)
            {
                BSL_SecOper_t **comp = BSLP_SecOperPtrList_get(secops, i);
                BSL_LOG_DEBUG("NEW SECOP (tgt=%d)(bib?=%d)(secblk=%d)", BSL_SecOper_GetTargetBlockNum(sec_oper),
                             BSL_SecOper_IsBIB(sec_oper), BSL_SecOper_GetSecurityBlockNum(sec_oper));
                BSL_LOG_DEBUG("comp SECOP (tgt=%d)(bib?=%d)(secblk=%d)", BSL_SecOper_GetTargetBlockNum(*comp),
                             BSL_SecOper_IsBIB(*comp), BSL_SecOper_GetSecurityBlockNum(*comp));
                if (BSL_SecOper_GetTargetBlockNum(*comp) == BSL_SecOper_GetTargetBlockNum(sec_oper))
                {
                    // Both BIBs or BCBs
                    if (!(BSL_SecOper_IsBIB(sec_oper) ^ BSL_SecOper_IsBIB(*comp)))
                    {
                        BSL_SecOper_SetConclusion(sec_oper, BSL_SECOP_CONCLUSION_INVALID);
                    }
                    // SOURCE BIB or ACCEPT BCB should come first
                    // true if ACC BIB or SRC BCB
                    if (BSL_SecOper_IsBIB(sec_oper) ^ BSL_SecOper_IsRoleSource(sec_oper))
                    {
                        BSL_LOG_DEBUG("NEW OP AFTER COMP");
                        BSLP_SecOperPtrList_push_at(secops, i + 1, sec_oper);
                    }
                    else
                    {
                        BSL_LOG_DEBUG("NEW OP BEFORE COMP");
                        BSLP_SecOperPtrList_push_at(secops, i, sec_oper);
                    }
                    break;
                }

                // security operation in list targets security operation
                if (BSL_SecOper_GetTargetBlockNum(*comp) == BSL_SecOper_GetSecurityBlockNum(sec_oper))
                {
                    BSLP_SecOperPtrList_push_at(secops, i, sec_oper);
                    break;
                }

                // new security operation targets security operation in list
                if (BSL_SecOper_GetTargetBlockNum(sec_oper) == BSL_SecOper_GetSecurityBlockNum(*comp))
                {
                    BSLP_SecOperPtrList_push_at(secops, i + 1, sec_oper);
                    break;
                }

                // same security block number, order by target
                if (BSL_SecOper_GetSecurityBlockNum(sec_oper) == BSL_SecOper_GetSecurityBlockNum(*comp))
                {
                    if (BSL_SecOper_GetTargetBlockNum(*comp) - BSL_SecOper_GetTargetBlockNum(sec_oper))
                    {
                        BSLP_SecOperPtrList_push_at(secops, i, sec_oper);
                    }
                    else
                    {
                        BSLP_SecOperPtrList_push_at(secops, i + 1, sec_oper);
                    }
                    break;
                }
            }

            if (i >= BSLP_SecOperPtrList_size(secops))
            {
                BSL_LOG_INFO("append to end");
                BSLP_SecOperPtrList_push_back(secops, sec_oper);
            }
        }
        BSL_LOG_INFO("Created sec operation for rule `%s`", rule->description);
    }

    for (size_t i = 0; i < BSLP_SecOperPtrList_size(secops); i++)
    {
        BSL_SecOper_t **secop = BSLP_SecOperPtrList_get(secops, i);
        BSL_SecurityAction_AppendSecOper(action, *secop);
        BSL_FREE(*secop);
    }
    BSLP_SecOperPtrList_clear(secops);

    BSL_SecurityActionSet_AppendAction(output_action_set, action);
    BSL_SecurityAction_Deinit(action);
    BSL_FREE(action);

    CHK_POSTCONDITION(BSL_SecurityActionSet_IsConsistent(output_action_set));
    return (int)BSL_SecurityActionSet_CountErrors(output_action_set);
}

int BSLP_FinalizePolicy(const void *user_data, const BSL_SecurityActionSet_t *output_action_set,
                        const BSL_BundleRef_t *bundle, const BSL_SecurityResponseSet_t *response_output)
{
    (void)user_data;
    (void)output_action_set;
    (void)response_output;
    (void)bundle;
    return 0;
}

void BSLP_PolicyPredicate_Deinit(BSLP_PolicyPredicate_t *self)
{
    BSL_HostEIDPattern_Deinit(&self->dst_eid_pattern);
    BSL_HostEIDPattern_Deinit(&self->secsrc_eid_pattern);
    BSL_HostEIDPattern_Deinit(&self->src_eid_pattern);
    memset(self, 0, sizeof(*self));
}

void BSLP_Deinit(void *user_data)
{
    BSLP_PolicyProvider_t *self = user_data;
    assert(BSLP_PolicyProvider_IsConsistent(self));
    for (size_t index = 0; index < self->rule_count; index++)
    {
        BSL_LOG_INFO("Sample Policy Provider deinit rule index %lu", index);
        BSLP_PolicyRule_Deinit(&self->rules[index]);
    }

    for (size_t index = 0; index < self->predicate_count; index++)
    {
        BSLP_PolicyPredicate_Deinit(&self->predicates[index]);
    }
    memset(self, 0, sizeof(*self));
}

void BSLP_PolicyPredicate_Init(BSLP_PolicyPredicate_t *self, BSL_PolicyLocation_e location,
                               BSL_HostEIDPattern_t src_eid_pattern, BSL_HostEIDPattern_t secsrc_eid_pattern,
                               BSL_HostEIDPattern_t dst_eid_pattern)
{
    // todo - eid patterns should be pointers since they are non-trivial copyable.
    assert(self != NULL);
    memset(self, 0, sizeof(*self));

    self->location           = location;
    self->src_eid_pattern    = src_eid_pattern;
    self->secsrc_eid_pattern = secsrc_eid_pattern;
    self->dst_eid_pattern    = dst_eid_pattern;

    assert(BSLP_PolicyPredicate_IsConsistent(self));
}

bool BSLP_PolicyPredicate_IsMatch(const BSLP_PolicyPredicate_t *self, BSL_PolicyLocation_e location,
                                  BSL_HostEID_t src_eid, BSL_HostEID_t dst_eid)
{
    assert(BSLP_PolicyPredicate_IsConsistent(self));

    bool is_location_match    = location == self->location;
    bool is_src_pattern_match = BSL_HostEIDPattern_IsMatch(&self->src_eid_pattern, &src_eid);
    bool is_dst_pattern_match = BSL_HostEIDPattern_IsMatch(&self->dst_eid_pattern, &dst_eid);

    BSL_LOG_DEBUG("Match: location=%d, src_pattern=%d, dst_pattern=%d", is_location_match, is_src_pattern_match,
                  is_dst_pattern_match);

    return is_location_match && is_src_pattern_match && is_dst_pattern_match;
}

/*
Example Rules:
 - Template: "If Bundle src/dst match PREDICATE, then (ADD|REMOVE|VALIDATE) SEC_BLOCK_TYPE using PARAM-KEY-VALUES"
 - "At ingress from the convergence layer, Bundles matching *.* must have a single BIB covering the primary and payload
block using key 9" Step 1: Match the Bundle struct with all Rule structs to find a Rule that matches. If no match,
reject
   - Things to match on:
     - Bitmask/something for HAS_BIB_ON_PRIMARY, HAS_BIB_ON_PAYLOAD, submasks for BIB_COVERS_PRIMARY, BIB_COVERS_TARGET
 Step 2: Populate security parameters unique to bundle and src/dst pair.
*/
int BSLP_PolicyRule_Init(BSLP_PolicyRule_t *self, const char *desc, BSLP_PolicyPredicate_t *predicate,
                         uint64_t context_id, BSL_SecRole_e role, BSL_SecBlockType_e sec_block_type,
                         BSL_BundleBlockTypeCode_e target_block_type, BSL_PolicyAction_e failure_action_code)
{
    assert(self != NULL);
    memset(self, 0, sizeof(*self));
    strncpy(self->description, desc, sizeof(self->description) - 1);
    self->sec_block_type    = sec_block_type;
    self->target_block_type = target_block_type;
    self->predicate         = predicate;
    self->context_id        = context_id;
    // TODO(bvb) assert Role in expected range
    self->failure_action_code = failure_action_code;
    self->role                = role;
    self->params              = BSL_CALLOC(BSL_SecParam_Sizeof() * BSL_PP_POLICYRULE_PARAM_MAX_COUNT, 1);
    self->nparams             = 0;
    assert(BSLP_PolicyRule_IsConsistent(self));
    return BSL_SUCCESS;
}

void BSLP_PolicyRule_Deinit(BSLP_PolicyRule_t *self)
{
    assert(BSLP_PolicyRule_IsConsistent(self));
    BSL_LOG_INFO("BSLP_PolicyRule_Deinit: %s, nparams=%lu", self->description, self->nparams);
    BSL_FREE(self->params);
    memset(self, 0, sizeof(*self));
}

void BSLP_PolicyRule_AddParam(BSLP_PolicyRule_t *self, const BSL_SecParam_t *param)
{
    assert(BSL_SecParam_IsConsistent(param));
    assert(BSLP_PolicyRule_IsConsistent(self));

    // TODO(bvb) - BOUNDS CHECKING
    assert(self->nparams < BSL_PP_POLICYRULE_PARAM_MAX_COUNT);

    size_t offset = self->nparams * BSL_SecParam_Sizeof();
    memcpy(&((uint8_t *)self->params)[offset], param, BSL_SecParam_Sizeof());
    self->nparams++;

    assert(BSLP_PolicyRule_IsConsistent(self));
}

int BSLP_PolicyRule_EvaluateAsSecOper(const BSLP_PolicyRule_t *self, BSL_SecOper_t *sec_oper,
                                      const BSL_BundleRef_t *bundle, BSL_PolicyLocation_e location)
{
    CHK_ARG_NONNULL(sec_oper);
    CHK_ARG_NONNULL(bundle);
    CHK_PRECONDITION(BSLP_PolicyRule_IsConsistent(self));

    {
        // Confirm that the rule matches the bundle.
        BSL_PrimaryBlock_t primary_block = { 0 };
        BSL_BundleCtx_GetBundleMetadata(bundle, &primary_block);
        CHK_PRECONDITION(BSLP_PolicyPredicate_IsMatch(self->predicate, location, primary_block.field_src_node_id,
                                                      primary_block.field_dest_eid));
    }

    // The rule gives us the target block TYPE, now we have to find the ID of the block with that type.
    uint64_t target_block_num = get_target_block_id(bundle, self->target_block_type);
    if (target_block_num == 0 && self->target_block_type != BSL_BLOCK_TYPE_PRIMARY)
    {
        BSL_LOG_WARNING("Cannot find target block type = %lu", self->target_block_type);
        return BSL_ERR_SECURITY_CONTEXT_FAILED;
    }

    // It's found, so populate the security operation from the rule and bundle.
    BSL_SecOper_Populate(sec_oper, self->context_id, target_block_num, 0, self->sec_block_type, self->role,
                         self->failure_action_code);

    // Next, append all the parameters from the matched rule.
    for (size_t index = 0; index < self->nparams; index++)
    {
        // We need to do this weird offsetting bc it does not know the size of SecParam_t
        size_t   offset = BSL_SecParam_Sizeof() * index;
        uint8_t *ptr    = &((uint8_t *)(self->params))[offset];
        BSL_SecOper_AppendParam(sec_oper, (BSL_SecParam_t *)ptr);
    }
    BSL_LOG_INFO("Created sec operation for rule `%s`", self->description);

    return BSL_SUCCESS;
}
