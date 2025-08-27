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
/** @file PublicInterfaceImpl.c
 * @ingroup backend_dyn
 * Implementation of the dynamic backend Public API.
 *
 * @todo MAJOR Complete implementation for ApplySecurity so it can drop blocks or bundles as-needed.
 */
#include <inttypes.h>

#include <BPSecLib_Private.h>
#include <BPSecLib_Public.h>

#include "PublicInterfaceImpl.h"
#include "SecurityActionSet.h"
#include "SecurityResultSet.h"

size_t BSL_LibCtx_Sizeof(void)
{
    return sizeof(BSL_LibCtx_t);
}

int BSL_API_InitLib(BSL_LibCtx_t *lib)
{
    CHK_ARG_NONNULL(lib);

    memset(&lib->tlm_counters, 0, sizeof(BSL_TlmCounters_t));

    BSL_SecCtxDict_init(lib->sc_reg);
    BSL_PolicyDict_init(lib->policy_reg);
    return BSL_SUCCESS;
}

int BSL_API_DeinitLib(BSL_LibCtx_t *lib)
{
    CHK_ARG_NONNULL(lib);

    BSL_PolicyDict_it_t policy_reg_it;
    for (BSL_PolicyDict_it(policy_reg_it, lib->policy_reg); !BSL_PolicyDict_end_p(policy_reg_it);
         BSL_PolicyDict_next(policy_reg_it))
    {
        const BSL_PolicyDesc_t *policy = BSL_PolicyDict_cref(policy_reg_it)->value_ptr;
        if (policy->deinit_fn != NULL)
        {
            // Call the policy deinit function
            (policy->deinit_fn)(policy->user_data);
        }
        else
        {
            BSL_LOG_WARNING("Policy Provider offered no deinit function");
        }
    }

    BSL_PolicyDict_clear(lib->policy_reg);
    BSL_SecCtxDict_clear(lib->sc_reg);
    return BSL_SUCCESS;
}

int BSL_LibCtx_GetTlmCounters(const BSL_LibCtx_t *lib, BSL_TlmCounters_t *tlm)
{
    CHK_ARG_NONNULL(lib);
    CHK_ARG_NONNULL(tlm);

    BSL_TlmCounters_t copy_tlm = lib->tlm_counters;
    *tlm = copy_tlm;

    return BSL_SUCCESS;
}

void BSL_PrimaryBlock_deinit(BSL_PrimaryBlock_t *obj)
{
    ASSERT_ARG_NONNULL(obj);

    BSL_FREE(obj->block_numbers);
    obj->block_numbers = NULL;

    BSL_Data_Deinit(&obj->encoded);
}

int BSL_API_RegisterSecurityContext(BSL_LibCtx_t *lib, uint64_t sec_ctx_id, BSL_SecCtxDesc_t desc)
{
    CHK_ARG_NONNULL(lib);
    CHK_ARG_EXPR(desc.validate != NULL);
    CHK_ARG_EXPR(desc.execute != NULL);

    BSL_SecCtxDict_set_at(lib->sc_reg, sec_ctx_id, desc);
    return BSL_SUCCESS;
}

int BSL_API_RegisterPolicyProvider(BSL_LibCtx_t *lib, uint64_t pp_id, BSL_PolicyDesc_t desc)
{
    CHK_ARG_NONNULL(lib);
    CHK_ARG_EXPR(desc.query_fn != NULL);
    CHK_ARG_EXPR(desc.finalize_fn != NULL);
    CHK_ARG_EXPR(desc.deinit_fn != NULL);

    BSL_PolicyDict_set_at(lib->policy_reg, pp_id, desc);
    return BSL_SUCCESS;
}

int BSL_API_QuerySecurity(const BSL_LibCtx_t *bsl, BSL_SecurityActionSet_t *output_action_set,
                          const BSL_BundleRef_t *bundle, BSL_PolicyLocation_e location)
{
    CHK_ARG_NONNULL(bsl);
    CHK_ARG_NONNULL(output_action_set);
    CHK_ARG_NONNULL(bundle);

    BSL_LOG_INFO("Querying policy provider for security actions...");
    BSL_SecurityActionSet_Init(output_action_set);
    int query_status = BSL_PolicyRegistry_InspectActions(bsl, output_action_set, bundle, location);
    BSL_LOG_INFO("Completed query: status=%d", query_status);

    // Here - find the sec block numbers for all ASBs

    // Explanation:
    // This segment of code finds the block number of the security block
    // that targets (protects) a block whose ID is `target_block_num`
    //
    // I.e., "Get me the security block whose target contains `target_block_num`"
    BSL_PrimaryBlock_t primary_block = { 0 };
    if (BSL_SUCCESS != BSL_BundleCtx_GetBundleMetadata(bundle, &primary_block))
    {
        BSL_LOG_ERR("Cannot get bundle primary block");
        return BSL_ERR_HOST_CALLBACK_FAILED;
    }

    for (size_t ix = 0; ix < primary_block.block_count; ix++)
    {
        BSL_CanonicalBlock_t block = { 0 };
        if (BSL_SUCCESS != BSL_BundleCtx_GetBlockMetadata(bundle, primary_block.block_numbers[ix], &block))
        {
            BSL_LOG_WARNING("Failed to get block number %" PRIu64, primary_block.block_numbers[ix]);
            continue;
        }
        BSL_SecActionList_it_t act_it;
        for (BSL_SecActionList_it(act_it, output_action_set->actions); !BSL_SecActionList_end_p(act_it);
             BSL_SecActionList_next(act_it))
        {
            BSL_SecurityAction_t *act = BSL_SecActionList_ref(act_it);
            for (size_t j = 0; j < BSL_SecurityAction_CountSecOpers(act); j++)
            {
                BSL_SecOper_t *sec_oper = BSL_SecurityAction_GetSecOperAtIndex(act, j);
                if (block.type_code != sec_oper->_service_type)
                {
                    continue;
                }
                // Now set it's sec_block
                BSL_AbsSecBlock_t *abs_sec_block = BSL_CALLOC(1, BSL_AbsSecBlock_Sizeof());
                BSL_Data_t         block_btsd    = { 0 };
                BSL_Data_InitView(&block_btsd, block.btsd_len, block.btsd);
                if (BSL_AbsSecBlock_DecodeFromCBOR(abs_sec_block, &block_btsd) == 0)
                {
                    if (BSL_AbsSecBlock_ContainsTarget(abs_sec_block, sec_oper->target_block_num))
                    {
                        sec_oper->sec_block_num = block.block_num;
                    }
                }
                else
                {
                    BSL_LOG_WARNING("Failed to parse ASB from BTSD");
                }
                BSL_AbsSecBlock_Deinit(abs_sec_block);
                BSL_FREE(abs_sec_block);
            }
        }
    }
    BSL_PrimaryBlock_deinit(&primary_block);

    if (BSL_SecCtx_ValidatePolicyActionSet((BSL_LibCtx_t *)bsl, bundle, output_action_set) == false)
    {
        query_status = BSL_ERR_SECURITY_CONTEXT_VALIDATION_FAILED;
        BSL_LOG_WARNING("Security Context validation failed");
    }

    return query_status;
}

int BSL_API_ApplySecurity(const BSL_LibCtx_t *bsl, BSL_SecurityResponseSet_t *response_output, BSL_BundleRef_t *bundle,
                          const BSL_SecurityActionSet_t *policy_actions)
{
    CHK_ARG_NONNULL(bsl);
    CHK_ARG_NONNULL(response_output);
    CHK_ARG_NONNULL(bundle);
    CHK_ARG_NONNULL(policy_actions);

    int exec_code = BSL_SecCtx_ExecutePolicyActionSet((BSL_LibCtx_t *)bsl, response_output, bundle, policy_actions);
    if (exec_code < BSL_SUCCESS)
    {
        BSL_LOG_ERR("Failed to execute policy action set");
    }

    int finalize_status = BSL_PolicyRegistry_FinalizeActions(bsl, policy_actions, bundle, response_output);
    BSL_LOG_INFO("Completed finalize: status=%d", finalize_status);

    BSL_SecActionList_it_t act_it;
    for (BSL_SecActionList_it(act_it, policy_actions->actions); !BSL_SecActionList_end_p(act_it);
         BSL_SecActionList_next(act_it))
    {
        BSL_SecurityAction_t *act = BSL_SecActionList_ref(act_it);
        for (size_t i = 0; i < BSL_SecurityAction_CountSecOpers(act); i++)
        {
            BSL_SecOper_t *sec_oper = BSL_SecurityAction_GetSecOperAtIndex(act, i);

            BSL_SecOper_ConclusionState_e conclusion = BSL_SecOper_GetConclusion(sec_oper);

            // When the operation was a success, there's nothing further to do.
            if (conclusion == BSL_SECOP_CONCLUSION_SUCCESS)
            {
                BSL_LOG_DEBUG("Security operation success, target block num = %" PRIu64, sec_oper->target_block_num);
                continue;
            }

            BSL_PolicyAction_e err_action_code = sec_oper->failure_code;

            // Now handle a specific error
            switch (err_action_code)
            {
                case BSL_POLICYACTION_NOTHING:
                {
                    // Do nothing, per policy (Indicate in telemetry.)
                    BSL_LOG_WARNING("Instructed to do nothing for failed security operation");
                    break;
                }
                case BSL_POLICYACTION_DROP_BLOCK:
                {
                    // Drop the failed target block, but otherwise continue
                    BSL_LOG_WARNING("***** Dropping block over which security operation failed *******");
                    BSL_BundleCtx_RemoveBlock(bundle, sec_oper->target_block_num);
                    break;
                }
                case BSL_POLICYACTION_DROP_BUNDLE:
                {
                    BSL_LOG_WARNING("Deleting bundle due to block target num %" PRIu64 " security failure",
                                    sec_oper->target_block_num);
                    // Drop the bundle and return operation error
                    BSL_LOG_WARNING("***** Delete bundle due to failed security operation *******");
                    BSL_BundleCtx_DeleteBundle(bundle);
                    break;
                }
                case BSL_POLICYACTION_UNDEFINED:
                default:
                {
                    BSL_LOG_ERR("Unhandled policy action: %" PRIu64, err_action_code);
                }
            }
        }
    }

    // TODO CHK_POSTCONDITION
    return BSL_SUCCESS;
}
