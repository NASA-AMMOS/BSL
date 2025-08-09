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

int BSL_API_InitLib(BSL_LibCtx_t *lib)
{
    CHK_ARG_NONNULL(lib);

    BSL_SecCtxDict_init(lib->sc_reg);
    return BSL_SUCCESS;
}

int BSL_API_DeinitLib(BSL_LibCtx_t *lib)
{
    CHK_ARG_NONNULL(lib);

    if (lib->policy_registry.deinit_fn != NULL)
    {
        // Call the policy deinit function
        (lib->policy_registry.deinit_fn)(lib->policy_registry.user_data);

        // TODO - We should not assume this is dynamically allocated.
        free(lib->policy_registry.user_data);
    }
    else
    {
        BSL_LOG_WARNING("Policy Provider offered no deinit function");
    }

    BSL_SecCtxDict_clear(lib->sc_reg);
    return BSL_SUCCESS;
}

int BSL_API_RegisterSecurityContext(BSL_LibCtx_t *lib, uint64_t sec_ctx_id, BSL_SecCtxDesc_t desc)
{
    CHK_ARG_NONNULL(lib);
    CHK_ARG_EXPR(desc.validate != NULL);
    CHK_ARG_EXPR(desc.execute != NULL);

    BSL_SecCtxDict_set_at(lib->sc_reg, sec_ctx_id, desc);
    return BSL_SUCCESS;
}

int BSL_API_RegisterPolicyProvider(BSL_LibCtx_t *lib, BSL_PolicyDesc_t desc)
{
    CHK_ARG_NONNULL(lib);
    CHK_ARG_EXPR(desc.query_fn != NULL);
    CHK_ARG_EXPR(desc.finalize_fn != NULL);
    CHK_ARG_EXPR(desc.deinit_fn != NULL);

    lib->policy_registry = desc;
    return BSL_SUCCESS;
}

int BSL_API_QuerySecurity(const BSL_LibCtx_t *bsl, BSL_SecurityActionSet_t *output_action_set,
                          const BSL_BundleRef_t *bundle, BSL_PolicyLocation_e location)
{
    CHK_ARG_NONNULL(bsl);
    CHK_ARG_NONNULL(output_action_set);
    CHK_ARG_NONNULL(bundle);

    CHK_PRECONDITION(bsl->policy_registry.query_fn != NULL);

    BSL_LOG_INFO("Querying policy provider for security actions...");
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

    uint64_t blocks_array[primary_block.block_count];
    size_t   total_blocks = 0;
    if (BSL_SUCCESS != BSL_BundleCtx_GetBlockIds(bundle, primary_block.block_count, blocks_array, &total_blocks))
    {
        BSL_LOG_ERR("Failed to get block indices");
        return BSL_ERR_HOST_CALLBACK_FAILED;
    }

    CHK_PROPERTY(total_blocks == primary_block.block_count);

    for (size_t i = 0; i < total_blocks; i++)
    {
        BSL_CanonicalBlock_t block = { 0 };
        if (BSL_SUCCESS != BSL_BundleCtx_GetBlockMetadata(bundle, blocks_array[i], &block))
        {
            BSL_LOG_WARNING("Failed to get block number %lu", blocks_array[i]);
            continue;
        }
        for (size_t sec_op_index = 0; sec_op_index < output_action_set->sec_operations_count; sec_op_index++)
        {
            BSL_SecOper_t *sec_oper = &output_action_set->sec_operations[sec_op_index];
            if (block.type_code != sec_oper->_service_type)
            {
                continue;
            }
            // Now set it's sec_block
            BSL_AbsSecBlock_t *abs_sec_block = calloc(1, BSL_AbsSecBlock_Sizeof());
            BSL_Data_t         block_btsd    = { 0 };
            BSL_Data_InitView(&block_btsd, block.btsd_len, block.btsd);
            if (BSL_AbsSecBlock_DecodeFromCBOR(abs_sec_block, block_btsd) == 0)
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
            free(abs_sec_block);
        }
    }

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

    CHK_PRECONDITION(bsl->policy_registry.finalize_fn != NULL);

    int exec_code = BSL_SecCtx_ExecutePolicyActionSet((BSL_LibCtx_t *)bsl, response_output, bundle, policy_actions);
    if (exec_code < BSL_SUCCESS)
    {
        BSL_LOG_ERR("Failed to execute policy action set");
    }

    BSL_PrimaryBlock_t primary_block = { 0 };
    if (BSL_SUCCESS != BSL_BundleCtx_GetBundleMetadata(bundle, &primary_block))
    {
        BSL_LOG_ERR("Failed to get bundle metadata");
        return BSL_ERR_HOST_CALLBACK_FAILED;
    }

    // There should be as many responses as there were sec operations
    ASSERT_PROPERTY(response_output->total_operations == policy_actions->sec_operations_count);

    int finalize_status = BSL_PolicyRegistry_FinalizeActions(bsl, policy_actions, bundle, response_output);
    BSL_LOG_INFO("Completed finalize: status=%d", finalize_status);

    bool must_drop = false;
    for (size_t oper_index = 0; oper_index < policy_actions->sec_operations_count; oper_index++)
    {
        // First, get the error code for the security operation ()
        int                block_err_code  = response_output->results[oper_index];
        BSL_PolicyAction_e err_action_code = policy_actions->sec_operations[oper_index].failure_code;

        // When the operation was a success, there's nothing further to do.
        if (block_err_code == BSL_SUCCESS)
        {
            BSL_LOG_DEBUG("Security operation [%lu] success, target block num = %lu", oper_index,
                          policy_actions->sec_operations[oper_index].target_block_num);
            continue;
        }

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
                BSL_BundleCtx_RemoveBlock(bundle, policy_actions->sec_operations[oper_index].target_block_num);
                break;
            }
            case BSL_POLICYACTION_DROP_BUNDLE:
            {
                BSL_LOG_WARNING("Deleting bundle due to block target num %lu security failure",
                                policy_actions->sec_operations[oper_index].target_block_num);
                must_drop = true;
                break;
            }
            case BSL_POLICYACTION_UNDEFINED:
            default:
            {
                BSL_LOG_ERR("Unhandled policy action: %lu", err_action_code);
            }
        }

        if (must_drop)
        {
            break;
        }
    }

    if (must_drop)
    {
        // Drop the bundle and return operation error
        BSL_LOG_WARNING("***** Delete bundle due to failed security operation *******");
        BSL_BundleCtx_DeleteBundle(bundle);
    }

    // TODO CHK_POSTCONDITION
    //return (must_drop) ? BSL_ERR_SECURITY_OPERATION_FAILED : BSL_SUCCESS;
    return BSL_SUCCESS;
}
