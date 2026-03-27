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

/**
 * @file
 * @brief Local implementation of locally-defined data structures.
 * @ingroup example_pp
 */
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <m-array.h>

#include <BPSecLib_Private.h>
#include "SamplePolicyProvider.h"

/** @struct BSLP_SecOperPtrList_t
 * Defines a basic list of ::BSL_SecOper_t pointers.
 */
/// @cond Doxygen_Suppress
// NOLINTBEGIN
// GCOV_EXCL_START
M_ARRAY_DEF(BSLP_SecOperPtrList, BSL_SecOper_t *, M_PTR_OPLIST)
// GCOV_EXCL_STOP
// NOLINTEND
/// @endcond

static bool BSLP_PolicyPredicate_IsConsistent(const BSLP_PolicyPredicate_t *self)
{
    ASSERT_ARG_NONNULL(self);
    ASSERT_ARG_EXPR(self->location >= BSL_POLICYLOCATION_APPIN && self->location <= BSL_POLICYLOCATION_CLOUT);
    ASSERT_ARG_NONNULL(self->dst_eid_pattern.handle);
    ASSERT_ARG_NONNULL(self->src_eid_pattern.handle);
    ASSERT_ARG_NONNULL(self->secsrc_eid_pattern.handle);
    return true;
}

static bool BSLP_PolicyRule_IsConsistent(const BSLP_PolicyRule_t *self)
{
    ASSERT_ARG_NONNULL(self);
    ASSERT_ARG_NONNULL(self->params);
    ASSERT_ARG_EXPR(BSL_SECROLE_ISVALID(self->role));
    ASSERT_ARG_EXPR(self->sec_block_type > 0);
    ASSERT_ARG_EXPR(self->context_id != 0);
    return true;
}

static uint64_t BSLP_PolicyProvider_HandleFailures(BSL_BundleRef_t *bundle, const BSL_SecOper_t *sec_oper)
{
    CHK_ARG_NONNULL(bundle);
    CHK_ARG_NONNULL(sec_oper);

    uint64_t           error_ret          = BSL_SUCCESS;
    uint64_t           block_num          = BSL_SecOper_GetTargetBlockNum(sec_oper);
    BSL_PolicyAction_e fail_policy_action = BSL_SecOper_GetPolicyAction(sec_oper);

    // Handle failure with specify rule policy code
    switch (fail_policy_action)
    {
        case BSL_POLICYACTION_NOTHING:
        {
            BSL_LOG_WARNING("Instructed to do nothing for failed security operation");
            break;
        }
        case BSL_POLICYACTION_DROP_BLOCK:
        {
            // Drop the failed target block, but otherwise continue
            BSL_LOG_WARNING("***** Dropping block over which security operation failed *******");
            error_ret = BSL_BundleCtx_RemoveBlock(bundle, block_num);
            break;
        }
        case BSL_POLICYACTION_DROP_BUNDLE:
        {
            BSL_LOG_WARNING("Deleting bundle due to block target num %" PRIu64 " security failure", block_num);
            // Drop the bundle
            BSL_LOG_WARNING("***** Delete bundle due to failed security operation *******");
            error_ret = BSL_BundleCtx_DeleteBundle(bundle, BSL_SecOper_GetReasonCode(sec_oper));
            break;
        }
        case BSL_POLICYACTION_UNDEFINED:
        default:
        {
            BSL_LOG_ERR("Unhandled policy action: %" PRIu64, fail_policy_action);
            return BSL_ERR_POLICY_FAILED;
        }
    }

    return error_ret;
}

static uint64_t get_target_block_id(const BSL_BundleRef_t *bundle, uint64_t target_block_type)
{
    uint64_t target_block_num = 0;

    BSL_PrimaryBlock_t res_prim_blk;
    if (BSL_BundleCtx_GetBundleMetadata(bundle, &res_prim_blk) != BSL_SUCCESS)
    {
        BSL_LOG_ERR("Failed to get bundle metadata");
        return target_block_num;
    }

    for (uint64_t ix = 0; ix < res_prim_blk.block_count; ix++)
    {
        BSL_CanonicalBlock_t test_block = { 0 };
        if (BSL_SUCCESS == BSL_BundleCtx_GetBlockMetadata(bundle, res_prim_blk.block_numbers[ix], &test_block))
        {
            if (test_block.type_code == target_block_type)
            {
                target_block_num = res_prim_blk.block_numbers[ix];
                break;
            }
        }
    }
    BSL_PrimaryBlock_deinit(&res_prim_blk);

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

    BSL_PrimaryBlock_t primary_block = { 0 };
    if (BSL_SUCCESS != BSL_BundleCtx_GetBundleMetadata(bundle, &primary_block))
    {
        BSL_LOG_ERR("Failed to retrieve primary block");
        return BSL_ERR_HOST_CALLBACK_FAILED;
    }

    BSL_SecurityAction_t *action = BSL_calloc(1, BSL_SecurityAction_Sizeof());
    BSL_SecurityAction_Init(action);

    BSLP_SecOperPtrList_t secops;
    BSLP_SecOperPtrList_init(secops);

    pthread_mutex_lock((pthread_mutex_t *) &self->mutex);
    BSLP_PolicyRuleList_it_t rule_it;
    size_t rule_pred_index = 0;
    for (BSLP_PolicyRuleList_it(rule_it, self->rules); !BSLP_PolicyRuleList_end_p(rule_it); BSLP_PolicyRuleList_next(rule_it), rule_pred_index++)
    {
        const BSLP_PolicyRule_t *rule = BSLP_PolicyRuleList_cref(rule_it);
        const BSLP_PolicyPredicate_t *predicate = BSLP_PolicyPredicateList_cget(self->predicates, rule_pred_index);
        if (!BSLP_PolicyRule_IsConsistent(rule))
        {
            BSL_LOG_ERR("Rule `%s` is not consistent", string_get_cstr(rule->description));
            continue;
        }
        BSL_LOG_DEBUG("Evaluating against rule `%s`", string_get_cstr(rule->description));

        if (!BSLP_PolicyPredicate_IsMatch(predicate, location, primary_block.field_src_node_id,
                                          primary_block.field_dest_eid))
        {
            BSL_LOG_DEBUG("Rule `%s` not a match", string_get_cstr(rule->description));
            continue;
        }

        uint64_t target_block_num = get_target_block_id(bundle, rule->target_block_type);
        if ((target_block_num == 0) && (rule->target_block_type != BSL_BLOCK_TYPE_PRIMARY))
        {
            BSL_LOG_WARNING("Cannot find target block type = %" PRIu64, rule->target_block_type);
            continue;
        }

        BSL_SecOper_t *sec_oper = BSL_calloc(1, BSL_SecOper_Sizeof());
        BSL_SecOper_Init(sec_oper);
        if (BSLP_PolicyRule_EvaluateAsSecOper(rule, predicate, sec_oper, bundle, location) < 0)
        {
            BSL_LOG_WARNING("SecOp evaluate failed");
            BSL_SecurityAction_IncrError(action);
            BSL_SecOper_Deinit(sec_oper);
            BSL_free(sec_oper);
            continue;
        }

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
        BSL_LOG_INFO("Created sec operation for rule `%s`", string_get_cstr(rule->description));
    }
    pthread_mutex_unlock((pthread_mutex_t *) &self->mutex);

    BSL_PrimaryBlock_deinit(&primary_block);

    // TODO replace a lot of copying with moving
    for (size_t i = 0; i < BSLP_SecOperPtrList_size(secops); i++)
    {
        BSL_SecOper_t **secop = BSLP_SecOperPtrList_get(secops, i);
        BSL_SecurityAction_AppendSecOper(action, *secop);
        BSL_free(*secop);
    }
    BSLP_SecOperPtrList_clear(secops);

    BSL_SecurityActionSet_AppendAction(output_action_set, action);
    BSL_SecurityAction_Deinit(action);
    BSL_free(action);

    CHK_POSTCONDITION(BSL_SecurityActionSet_IsConsistent(output_action_set));
    return (int)BSL_SecurityActionSet_CountErrors(output_action_set);
}

int BSLP_FinalizePolicy(const void *user_data _U_, const BSL_SecurityActionSet_t *output_action_set _U_,
                        const BSL_BundleRef_t *bundle, const BSL_SecurityResponseSet_t *response_output _U_)
{
    int                          error_ret = BSL_SUCCESS;
    const BSLP_PolicyProvider_t *self      = user_data;

    for (size_t i = 0; i < BSL_SecurityActionSet_CountActions(output_action_set); i++)
    {
        const BSL_SecurityAction_t *action = BSL_SecurityActionSet_GetActionAtIndex(output_action_set, i);

        pthread_mutex_lock((pthread_mutex_t *) &self->mutex);
        uint64_t pp_id = self->pp_id;
        pthread_mutex_unlock((pthread_mutex_t *) &self->mutex);
        
        if (BSL_SecurityAction_GetPPID(action) != pp_id)
        {
            continue;
        }

        for (size_t j = 0; j < BSL_SecurityAction_CountSecOpers(action); j++)
        {
            const BSL_SecOper_t          *secop      = BSL_SecurityAction_GetSecOperAtIndex(action, j);
            BSL_SecOper_ConclusionState_e conclusion = BSL_SecOper_GetConclusion(secop);

            switch (conclusion)
            {
                case BSL_SECOP_CONCLUSION_PENDING:
                {
                    BSL_LOG_INFO("PP FINALIZE: Sec Oper from action %" PRIu64 " at index %" PRIu64 ": STILL PENDING", i,
                                 j);
                    break;
                }
                case BSL_SECOP_CONCLUSION_SUCCESS:
                {
                    BSL_LOG_INFO("PP FINALIZE: Sec Oper from action %" PRIu64 " at index %" PRIu64 ": SUCCESS", i, j);
                    break;
                }
                case BSL_SECOP_CONCLUSION_INVALID:
                {
                    BSL_LOG_INFO("PP FINALIZE: Sec Oper from action %" PRIu64 " at index %" PRIu64 ": INVALID", i, j);
                    break;
                }
                case BSL_SECOP_CONCLUSION_FAILURE:
                {
                    BSL_LOG_INFO("PP FINALIZE: Sec Oper from action %" PRIu64 " at index %" PRIu64 ": FAIL", i, j);
                    break;
                }
            }

            if (conclusion != BSL_SECOP_CONCLUSION_SUCCESS)
            {
                error_ret = BSLP_PolicyProvider_HandleFailures((BSL_BundleRef_t *)bundle, secop);
            }
        }
    }

    return error_ret;
}

// is this needed w/ shared mem model?
void BSLP_Deinit(void *user_data)
{
    (void) user_data;
}

BSLP_PolicyProvider_t *BSLP_PolicyProvider_Init(uint64_t pp_id)
{
    BSLP_PolicyProvider_t *pp = BSL_malloc(sizeof(BSLP_PolicyProvider_t));
    ASSERT_ARG_NONNULL(pp);
    
    ASSERT_ARG_EXPR(pp_id > 0);
    pp->pp_id = pp_id;

    BSLP_PolicyRuleList_init(pp->rules);
    BSLP_PolicyPredicateList_init(pp->predicates);
    pthread_mutex_init(&pp->mutex, NULL);

    return pp;
}

int BSLP_PolicyProvider_AddRule(BSLP_PolicyProvider_t *self, BSLP_PolicyRule_t *rule, BSLP_PolicyPredicate_t *predicate)
{
    if (!BSLP_PolicyRule_IsConsistent(rule) || !BSLP_PolicyPredicate_IsConsistent(predicate))
    {
        return BSL_ERR_ARG_INVALID;
    }

    pthread_mutex_lock(&self->mutex);
    BSLP_PolicyRuleList_push_move(self->rules, rule);
    BSLP_PolicyPredicateList_push_back(self->predicates, *predicate);
    pthread_mutex_unlock(&self->mutex);

    return BSL_SUCCESS;
}

void BSLP_PolicyProvider_Deinit(BSLP_PolicyProvider_t *self)
{
    pthread_mutex_lock(&self->mutex);
    BSLP_PolicyRuleList_clear(self->rules);
    BSLP_PolicyPredicateList_clear(self->predicates);
    pthread_mutex_unlock(&self->mutex);

    pthread_mutex_destroy(&self->mutex);
    BSL_free(self);
}

void BSLP_PolicyPredicate_Init(BSLP_PolicyPredicate_t *self)
{
    self->location = 0;
    BSL_HostEIDPattern_Init(&self->src_eid_pattern);
    BSL_HostEIDPattern_Init(&self->secsrc_eid_pattern);
    BSL_HostEIDPattern_Init(&self->dst_eid_pattern);
}

void BSLP_PolicyPredicate_ShallowCopy(BSLP_PolicyPredicate_t *self, const BSLP_PolicyPredicate_t *src)
{
    // todo - eid patterns should be pointers since they are non-trivial copyable.
    self->location = src->location;
    self->src_eid_pattern.handle = src->src_eid_pattern.handle;
    self->secsrc_eid_pattern.handle = src->secsrc_eid_pattern.handle;
    self->dst_eid_pattern.handle = src->dst_eid_pattern.handle;
}

int BSLP_PolicyPredicate_InitFrom(BSLP_PolicyPredicate_t *self, BSL_PolicyLocation_e location, const char *src_eid_pattern, const char *secsrc_eid_pattern, const char *dst_eid_pattern)
{    
    BSLP_PolicyPredicate_Init(self);
    self->location = location;

    if (BSL_HostEIDPattern_DecodeFromText(&self->src_eid_pattern, src_eid_pattern) ||
        BSL_HostEIDPattern_DecodeFromText(&self->secsrc_eid_pattern, secsrc_eid_pattern) ||
        BSL_HostEIDPattern_DecodeFromText(&self->dst_eid_pattern, dst_eid_pattern))
    {
        return BSL_ERR_HOST_CALLBACK_FAILED;
    }

    if (!BSLP_PolicyPredicate_IsConsistent(self))
    {
        return BSL_ERR_PROPERTY_CHECK_FAILED;
    }

    return BSL_SUCCESS;
}

void BSLP_PolicyPredicate_Deinit(BSLP_PolicyPredicate_t *self)
{
    BSL_LOG_INFO(" AM I BEING CALLED?");
    BSL_HostEIDPattern_Deinit(&self->dst_eid_pattern);
    BSL_HostEIDPattern_Deinit(&self->secsrc_eid_pattern);
    BSL_HostEIDPattern_Deinit(&self->src_eid_pattern);
    memset(self, 0, sizeof(BSLP_PolicyPredicate_t));
}

bool BSLP_PolicyPredicate_IsMatch(const BSLP_PolicyPredicate_t *self, BSL_PolicyLocation_e location,
                                  BSL_HostEID_t src_eid, BSL_HostEID_t dst_eid)
{
    ASSERT_ARG_EXPR(BSLP_PolicyPredicate_IsConsistent(self));

    bool is_location_match    = location == self->location;
    bool is_src_pattern_match = BSL_HostEIDPattern_IsMatch(&self->src_eid_pattern, &src_eid);
    bool is_dst_pattern_match = BSL_HostEIDPattern_IsMatch(&self->dst_eid_pattern, &dst_eid);

    BSL_LOG_DEBUG("Match: location=%d, src_pattern=%d, dst_pattern=%d", is_location_match, is_src_pattern_match,
                  is_dst_pattern_match);

    return is_location_match && is_src_pattern_match && is_dst_pattern_match;
}

int BSLP_PolicyRule_InitFrom(BSLP_PolicyRule_t *self, const char *desc, int64_t context_id, BSL_SecRole_e role, BSL_SecBlockType_e sec_block_type, BSL_BundleBlockTypeCode_e target_block_type, BSL_PolicyAction_e failure_action_code)
{
    BSLP_PolicyRule_Init(self);
    string_set_str(self->description, desc);

    self->sec_block_type = sec_block_type;
    self->target_block_type = target_block_type;
    self->context_id = context_id;
    self->failure_action_code = failure_action_code;
    self->role = role;

    if (!BSLP_PolicyRule_IsConsistent(self))
    {
        return BSL_ERR_PROPERTY_CHECK_FAILED;
    }

    return BSL_SUCCESS;
}

void BSLP_PolicyRule_Init(BSLP_PolicyRule_t *self)
{
    memset(self, 0, sizeof(BSLP_PolicyRule_t));
    string_init(self->description);
    BSLB_SecParamList_init(self->params);
}

void BSLP_PolicyRule_InitSet(BSLP_PolicyRule_t *self, const BSLP_PolicyRule_t *src)
{
    string_init_set(self->description, src->description);
    BSLB_SecParamList_init_set(self->params, src->params);

    self->role = src->role;
    self->target_block_type = src->target_block_type;
    self->sec_block_type = src->sec_block_type;
    self->context_id = src->context_id;
    self->failure_action_code = src->failure_action_code;
}

void BSLP_PolicyRule_Deinit(BSLP_PolicyRule_t *self)
{
    BSL_LOG_INFO("BSLP_PolicyRule_Deinit: %s, nparams=%zu", string_get_cstr(self->description), BSLB_SecParamList_size(self->params));

    string_clear(self->description);
    BSLB_SecParamList_clear(self->params);
}

void BSLP_PolicyRule_CopyParam(BSLP_PolicyRule_t *self, const BSL_SecParam_t *param)
{
    ASSERT_ARG_EXPR(BSL_SecParam_IsConsistent(param));
    ASSERT_ARG_EXPR(BSLP_PolicyRule_IsConsistent(self));

    BSLB_SecParamList_push_back(self->params, *param);

    ASSERT_POSTCONDITION(BSLP_PolicyRule_IsConsistent(self));
}

void BSLP_PolicyRule_MoveParam(BSLP_PolicyRule_t *self, BSL_SecParam_t *param)
{
    ASSERT_ARG_EXPR(BSL_SecParam_IsConsistent(param));
    ASSERT_ARG_EXPR(BSLP_PolicyRule_IsConsistent(self));

    BSLB_SecParamList_push_move(self->params, param);

    ASSERT_POSTCONDITION(BSLP_PolicyRule_IsConsistent(self));
}

int BSLP_PolicyRule_EvaluateAsSecOper(const BSLP_PolicyRule_t *self, const BSLP_PolicyPredicate_t *predicate, BSL_SecOper_t *sec_oper, const BSL_BundleRef_t *bundle, BSL_PolicyLocation_e location)
{
    CHK_ARG_NONNULL(sec_oper);
    CHK_ARG_NONNULL(bundle);
    CHK_PRECONDITION(BSLP_PolicyRule_IsConsistent(self));

    {
        // Confirm that the rule matches the bundle.
        BSL_PrimaryBlock_t primary_block = { 0 };
        BSL_BundleCtx_GetBundleMetadata(bundle, &primary_block);
        CHK_PRECONDITION(BSLP_PolicyPredicate_IsMatch(predicate, location, primary_block.field_src_node_id,
                                                      primary_block.field_dest_eid));
        BSL_PrimaryBlock_deinit(&primary_block);
    }

    // The rule gives us the target block TYPE, now we have to find the ID of the block with that type.
    uint64_t target_block_num = get_target_block_id(bundle, self->target_block_type);
    if (target_block_num == 0 && self->target_block_type != BSL_BLOCK_TYPE_PRIMARY)
    {
        BSL_LOG_WARNING("Cannot find target block type = %" PRIu64, self->target_block_type);
        return BSL_ERR_SECURITY_CONTEXT_FAILED;
    }

    // It's found, so populate the security operation from the rule and bundle.
    BSL_SecOper_Populate(sec_oper, self->context_id, target_block_num, 0, self->sec_block_type, self->role,
                         self->failure_action_code);

    // Next, append all the parameters from the matched rule.
    BSLB_SecParamList_it_t pit;
    for (BSLB_SecParamList_it(pit, self->params); !BSLB_SecParamList_end_p(pit); BSLB_SecParamList_next(pit))
    {
        const BSL_SecParam_t *param = BSLB_SecParamList_cref(pit);
        BSL_SecOper_AppendParam(sec_oper, param);
    }
    BSL_LOG_INFO("Created sec operation for rule `%s`", string_get_cstr(self->description));

    return BSL_SUCCESS;
}
