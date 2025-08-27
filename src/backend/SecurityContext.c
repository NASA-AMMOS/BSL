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
 * @brief Implementation of functions to interact with the security context
 * @ingroup backend_dyn
 *
 * @todo Enable checking (not just using a stub returning True.)
 * @todo Complete implementation for BCB acceptor.
 */
#include <BPSecLib_Private.h>

#include "AbsSecBlock.h"
#include "PublicInterfaceImpl.h"
#include "SecOperation.h"
#include "SecurityActionSet.h"
#include "SecurityResultSet.h"

static int Encode_ASB(BSL_BundleRef_t *bundle, uint64_t blk_num, const BSL_AbsSecBlock_t *abs_sec_block)
{
    // Get the needed size first
    BSL_Data_t asb_data;
    BSL_Data_Init(&asb_data);
    ssize_t encode_result = BSL_AbsSecBlock_EncodeToCBOR(abs_sec_block, &asb_data);
    BSL_Data_Deinit(&asb_data);
    if (encode_result <= 0)
    {
        BSL_LOG_ERR("Failed to calculate ASB size");
        return BSL_ERR_ENCODING;
    }

    BSL_Data_InitBuffer(&asb_data, (size_t)encode_result);
    encode_result = BSL_AbsSecBlock_EncodeToCBOR(abs_sec_block, &asb_data);
    if (encode_result <= BSL_SUCCESS)
    {
        BSL_LOG_ERR("Failed to encode ASB");
        return BSL_ERR_ENCODING;
    }

    BSL_SeqWriter_t *btsd_write = BSL_BundleCtx_WriteBTSD(bundle, blk_num, asb_data.len);
    if (!btsd_write)
    {
        BSL_LOG_ERR("Failed to get BTSD writer");
        return BSL_ERR_ENCODING;
    }
    if (BSL_SeqWriter_Put(btsd_write, asb_data.ptr, asb_data.len))
    {
        BSL_LOG_ERR("Failed to write BTSD");
        return BSL_ERR_ENCODING;
    }
    // finalize the write
    BSL_SeqWriter_Destroy(btsd_write);

    BSL_Data_Deinit(&asb_data);
    return BSL_SUCCESS;
}

static int BSL_ExecBIBSource(BSL_SecCtx_Execute_f sec_context_fn, BSL_LibCtx_t *lib, BSL_BundleRef_t *bundle,
                             BSL_SecOper_t *sec_oper, BSL_SecOutcome_t *outcome)
{
    (void)lib;
    CHK_ARG_NONNULL(sec_context_fn);
    CHK_ARG_NONNULL(bundle);
    CHK_ARG_NONNULL(sec_oper);
    CHK_ARG_NONNULL(outcome);

    // TODO(bvb) - This should already have been created ahead of time, around the time of inspect
    uint64_t created_block_num = 0;
    int      created_result    = BSL_BundleCtx_CreateBlock(bundle, BSL_SECBLOCKTYPE_BIB, &created_block_num);
    if (created_result != BSL_SUCCESS)
    {
        BSL_LOG_ERR("Failed to create BIB block, error=%d", created_result);
        return BSL_ERR_BUNDLE_OPERATION_FAILED;
    }

    CHK_PROPERTY(created_block_num > 1);

    const int bib_result = (*sec_context_fn)(lib, bundle, sec_oper, outcome);
    if (bib_result != 0) // || outcome->is_success == false)
    {
        BSL_LOG_ERR("BIB Source failed!");
        return BSL_ERR_SECURITY_OPERATION_FAILED;
    }

    BSL_CanonicalBlock_t sec_blk = { 0 };
    if (BSL_BundleCtx_GetBlockMetadata(bundle, created_block_num, &sec_blk) != BSL_SUCCESS)
    {
        BSL_LOG_ERR("Could not get BIB block (id=%" PRIu64 ")", created_block_num);
        return BSL_ERR_SECURITY_OPERATION_FAILED;
    }

    BSL_HostEID_t sec_source_eid = { 0 };
    // TODO - The ownership of this should be cleaned up(!)
    BSL_HostEID_Init(&sec_source_eid);
    if (BSL_Host_GetSecSrcEID(&sec_source_eid) != BSL_SUCCESS)
    {
        BSL_LOG_ERR("Could not get local security source EID");
        return BSL_ERR_HOST_CALLBACK_FAILED;
    }
    BSL_AbsSecBlock_t abs_sec_block = { 0 };
    BSL_AbsSecBlock_Init(&abs_sec_block, sec_oper->context_id, sec_source_eid);
    BSL_AbsSecBlock_AddTarget(&abs_sec_block, sec_oper->target_block_num);

    size_t n_results = BSL_SecOutcome_CountResults(outcome);
    for (size_t index = 0; index < n_results; index++)
    {
        BSL_AbsSecBlock_AddResult(&abs_sec_block, BSL_SecOutcome_GetResultAtIndex(outcome, index));
    }

    size_t n_params = BSL_SecOutcome_CountParams(outcome);
    for (size_t index = 0; index < n_params; index++)
    {
        BSL_AbsSecBlock_AddParam(&abs_sec_block, BSL_SecOutcome_GetParamAt(outcome, index));
    }

    int res = Encode_ASB(bundle, created_block_num, &abs_sec_block);
    if (res != BSL_SUCCESS)
    {
        return res;
    }

    BSL_AbsSecBlock_Deinit(&abs_sec_block);
    return BSL_SUCCESS;
}

static int BSL_ExecBIBAccept(BSL_SecCtx_Execute_f sec_context_fn, BSL_LibCtx_t *lib, BSL_BundleRef_t *bundle,
                             BSL_SecOper_t *sec_oper, BSL_SecOutcome_t *outcome)
{
    CHK_ARG_NONNULL(lib);
    CHK_ARG_NONNULL(bundle);
    CHK_PRECONDITION(BSL_SecOper_IsConsistent(sec_oper));
    CHK_PRECONDITION(BSL_SecOutcome_IsConsistent(outcome));

    BSL_CanonicalBlock_t sec_blk = { 0 };
    if (BSL_BundleCtx_GetBlockMetadata(bundle, sec_oper->sec_block_num, &sec_blk) != BSL_SUCCESS)
    {
        BSL_LOG_ERR("Could not get block metadata");
        return BSL_ERR_HOST_CALLBACK_FAILED;
    }

    // ASB decoder needs the whole BTSD now
    BSL_Data_t btsd_copy;
    BSL_Data_InitBuffer(&btsd_copy, sec_blk.btsd_len);

    BSL_SeqReader_t *btsd_read = BSL_BundleCtx_ReadBTSD(bundle, sec_blk.block_num);
    BSL_SeqReader_Get(btsd_read, btsd_copy.ptr, &btsd_copy.len);
    BSL_SeqReader_Destroy(btsd_read);

    BSL_AbsSecBlock_t abs_sec_block;
    BSL_AbsSecBlock_InitEmpty(&abs_sec_block);
    if (BSL_AbsSecBlock_DecodeFromCBOR(&abs_sec_block, &btsd_copy) != BSL_SUCCESS)
    {
        BSL_LOG_ERR("Failed to parse ASB CBOR");
        BSL_AbsSecBlock_Deinit(&abs_sec_block);
        BSL_Data_Deinit(&btsd_copy);
        return BSL_ERR_DECODING;
    }
    BSL_Data_Deinit(&btsd_copy);

    CHK_PROPERTY(BSL_AbsSecBlock_IsConsistent(&abs_sec_block));

    for (size_t i = 0; i < BSLB_SecParamList_size(abs_sec_block.params); i++)
    {
        const BSL_SecParam_t *param = BSLB_SecParamList_cget(abs_sec_block.params, i);
        CHK_PROPERTY(BSL_SecParam_IsConsistent(param));
        BSLB_SecParamList_push_back(sec_oper->_param_list, *param);
    }

    const int sec_context_result = (*sec_context_fn)(lib, bundle, sec_oper, outcome);
    if (sec_context_result != BSL_SUCCESS) // || outcome->is_success == false)
    {
        BSL_LOG_ERR("BIB Acceptor failed!");
        BSL_AbsSecBlock_Deinit(&abs_sec_block);
        return BSL_ERR_SECURITY_OPERATION_FAILED;
    }

    bool auth_success = BSL_SecOutcome_IsInAbsSecBlock(outcome, &abs_sec_block);
    if (!auth_success)
    {
        BSL_LOG_ERR("BIB Accepting failed");
    }

    // TODO/FIXME - This logic seems to be correct, but should be refactored and simplified.
    // There are too many branches/conditionals each with their own return statement.

    if (BSL_SecOper_IsRoleAcceptor(sec_oper))
    {
        uint64_t target_block_num = BSL_SecOper_GetTargetBlockNum(sec_oper);
        int      status           = BSL_AbsSecBlock_StripResults(&abs_sec_block, target_block_num);
        if (status < 0)
        {
            BSL_LOG_ERR("Failure to strip ASB of results");
            BSL_AbsSecBlock_Deinit(&abs_sec_block);
            return BSL_ERR_FAILURE;
        }

        if (BSL_AbsSecBlock_IsEmpty(&abs_sec_block))
        {
            if (BSL_BundleCtx_RemoveBlock(bundle, sec_blk.block_num) != BSL_SUCCESS)
            {
                BSL_LOG_ERR("Failed to remove block when ASB is empty");
                BSL_AbsSecBlock_Deinit(&abs_sec_block);
                return BSL_ERR_HOST_CALLBACK_FAILED;
            }
        }
        else
        {
            int res = Encode_ASB(bundle, sec_blk.block_num, &abs_sec_block);
            if (res != BSL_SUCCESS)
            {
                return res;
            }
        }
    }

    BSL_AbsSecBlock_Deinit(&abs_sec_block);

    // TODO(bvb) Check postconditions that the block actually was removed
    if (auth_success)
    {
        BSL_LOG_INFO("BIB Accept SUCCESS");
    }
    else
    {
        BSL_LOG_ERR("BIB Accept FAIL");
    }

    return auth_success ? BSL_SUCCESS : BSL_ERR_SECURITY_OPERATION_FAILED;
}

static int BSL_ExecBCBAcceptor(BSL_SecCtx_Execute_f sec_context_fn, BSL_LibCtx_t *lib, BSL_BundleRef_t *bundle,
                               BSL_SecOper_t *sec_oper, BSL_SecOutcome_t *outcome)
{
    (void)lib;
    CHK_ARG_NONNULL(sec_context_fn);
    CHK_ARG_NONNULL(bundle);
    CHK_ARG_NONNULL(sec_oper);
    CHK_ARG_NONNULL(outcome);

    BSL_CanonicalBlock_t sec_blk = { 0 };
    if (BSL_BundleCtx_GetBlockMetadata(bundle, sec_oper->sec_block_num, &sec_blk) != BSL_SUCCESS)
    {
        BSL_LOG_ERR("Could not get block metadata");
        return BSL_ERR_HOST_CALLBACK_FAILED;
    }

    // ASB decoder needs the whole BTSD now
    BSL_Data_t btsd_copy;
    BSL_Data_InitBuffer(&btsd_copy, sec_blk.btsd_len);

    BSL_SeqReader_t *btsd_read = BSL_BundleCtx_ReadBTSD(bundle, sec_blk.block_num);
    BSL_SeqReader_Get(btsd_read, btsd_copy.ptr, &btsd_copy.len);
    BSL_SeqReader_Destroy(btsd_read);

    BSL_AbsSecBlock_t abs_sec_block;
    BSL_AbsSecBlock_InitEmpty(&abs_sec_block);
    if (BSL_AbsSecBlock_DecodeFromCBOR(&abs_sec_block, &btsd_copy) != BSL_SUCCESS)
    {
        BSL_LOG_ERR("Failed to parse ASB CBOR");
        BSL_AbsSecBlock_Deinit(&abs_sec_block);
        return BSL_ERR_DECODING;
    }
    BSL_Data_Deinit(&btsd_copy);

    CHK_PROPERTY(BSL_AbsSecBlock_IsConsistent(&abs_sec_block));

    for (size_t i = 0; i < BSLB_SecParamList_size(abs_sec_block.params); i++)
    {
        const BSL_SecParam_t *param = BSLB_SecParamList_cget(abs_sec_block.params, i);
        CHK_PROPERTY(BSL_SecParam_IsConsistent(param));
        BSLB_SecParamList_push_back(sec_oper->_param_list, *param);
    }

    const size_t   result_count = BSLB_SecResultList_size(abs_sec_block.results);
    BSL_SecParam_t results_as_params[result_count];
    for (size_t i = 0; i < result_count; i++)
    {
        BSL_SecResult_t *result = BSLB_SecResultList_get(abs_sec_block.results, i);
        if (result->target_block_num == sec_oper->target_block_num)
        {
            CHK_PROPERTY(BSL_SecResult_IsConsistent(result));
            BSL_SecParam_t *result_param = &results_as_params[i];
            BSL_Data_t      as_data      = { .ptr = result->_bytes, .len = result->_bytelen };
            BSL_SecParam_InitBytestr(result_param, BSL_SECPARAM_TYPE_AUTH_TAG, as_data);
            BSLB_SecParamList_push_back(sec_oper->_param_list, *result_param);
        }
    }

    const int sec_context_result = (*sec_context_fn)(lib, bundle, sec_oper, outcome);
    if (sec_context_result != BSL_SUCCESS) // || outcome->is_success == false)
    {
        BSL_LOG_ERR("BCB Acceptor failed!");
        BSL_AbsSecBlock_Deinit(&abs_sec_block);
        return BSL_ERR_SECURITY_OPERATION_FAILED;
    }

    // TODO/FIXME - This logic seems to be correct, but should be refactored and simplified.
    // There are too many branches/conditionals each with their own return statement.

    if (BSL_SecOper_IsRoleAcceptor(sec_oper))
    {
        uint64_t target_block_num = BSL_SecOper_GetTargetBlockNum(sec_oper);
        int      status           = BSL_AbsSecBlock_StripResults(&abs_sec_block, target_block_num);
        if (status < 0)
        {
            BSL_LOG_ERR("Failure to strip ASB of results");
            BSL_AbsSecBlock_Deinit(&abs_sec_block);
            return BSL_ERR_FAILURE;
        }

        if (BSL_AbsSecBlock_IsEmpty(&abs_sec_block))
        {
            if (BSL_BundleCtx_RemoveBlock(bundle, sec_blk.block_num) != BSL_SUCCESS)
            {
                BSL_LOG_ERR("Failed to remove block when ASB is empty");
                BSL_AbsSecBlock_Deinit(&abs_sec_block);
                return BSL_ERR_HOST_CALLBACK_FAILED;
            }
        }
        else
        {
            int res = Encode_ASB(bundle, sec_blk.block_num, &abs_sec_block);
            if (res != BSL_SUCCESS)
            {
                return res;
            }
        }
    }

    BSL_AbsSecBlock_Deinit(&abs_sec_block);

    // TODO(bvb) Check postconditions that the block actually was removed
    return BSL_SUCCESS;
}

static int BSL_ExecBCBSource(BSL_SecCtx_Execute_f sec_context_fn, BSL_LibCtx_t *lib, BSL_BundleRef_t *bundle,
                             BSL_SecOper_t *sec_oper, BSL_SecOutcome_t *outcome)
{
    (void)lib;

    CHK_ARG_NONNULL(sec_context_fn);
    CHK_ARG_NONNULL(bundle);
    CHK_ARG_NONNULL(sec_oper);
    CHK_ARG_NONNULL(outcome);

    uint64_t created_block_id = 0;
    if (BSL_SUCCESS != BSL_BundleCtx_CreateBlock(bundle, BSL_SECBLOCKTYPE_BCB, &created_block_id))
    {
        BSL_LOG_ERR("Failed to create BCB block");
        return BSL_ERR_HOST_CALLBACK_FAILED;
    }
    BSL_LOG_INFO("Created new BCB block id = %" PRIu64, created_block_id);

    sec_oper->sec_block_num = created_block_id;
    int res                 = (*sec_context_fn)(lib, bundle, sec_oper, outcome);
    if (res != 0) // || outcome->is_success == false)
    {
        BSL_LOG_ERR("BCB Source failed!");
        return BSL_ERR_SECURITY_OPERATION_FAILED;
    }
    BSL_LOG_INFO("BCB SOURCE operation success.");

    BSL_CanonicalBlock_t sec_blk = { 0 };
    if (BSL_BundleCtx_GetBlockMetadata(bundle, sec_oper->sec_block_num, &sec_blk) != BSL_SUCCESS)
    {
        BSL_LOG_ERR("Failed to get security block");
        return BSL_ERR_HOST_CALLBACK_FAILED;
    }

    BSL_AbsSecBlock_t abs_sec_block;
    if (true)
    {
        BSL_HostEID_t src_eid = { 0 };
        BSL_HostEID_Init(&src_eid);
        if (BSL_SUCCESS != BSL_Host_GetSecSrcEID(&src_eid))
        {
            BSL_LOG_ERR("Failed to get host EID");
            return BSL_ERR_HOST_CALLBACK_FAILED;
        }
        BSL_AbsSecBlock_Init(&abs_sec_block, sec_oper->context_id, src_eid);
    }
    else
    {
        // ASB decoder needs the whole BTSD now
        BSL_Data_t btsd_copy;
        BSL_Data_InitBuffer(&btsd_copy, sec_blk.btsd_len);

        BSL_SeqReader_t *btsd_read = BSL_BundleCtx_ReadBTSD(bundle, sec_blk.block_num);
        BSL_SeqReader_Get(btsd_read, btsd_copy.ptr, &btsd_copy.len);
        BSL_SeqReader_Destroy(btsd_read);

        if (BSL_AbsSecBlock_DecodeFromCBOR(&abs_sec_block, &btsd_copy) != BSL_SUCCESS)
        {
            BSL_LOG_ERR("Failed to parse ASB CBOR");
            BSL_Data_Deinit(&btsd_copy);
            return BSL_ERR_DECODING;
        }
        BSL_Data_Deinit(&btsd_copy);
    }

    BSL_AbsSecBlock_AddTarget(&abs_sec_block, sec_oper->target_block_num);

    size_t n_results = BSL_SecOutcome_CountResults(outcome);
    for (size_t index = 0; index < n_results; index++)
    {
        const BSL_SecResult_t *result_ptr = BSL_SecOutcome_GetResultAtIndex(outcome, index);
        BSL_AbsSecBlock_AddResult(&abs_sec_block, result_ptr);
    }

    size_t n_params = BSL_SecOutcome_CountParams(outcome);
    for (size_t index = 0; index < n_params; index++)
    {
        const BSL_SecParam_t *param_ptr = BSL_SecOutcome_GetParamAt(outcome, index);
        BSL_AbsSecBlock_AddParam(&abs_sec_block, param_ptr);
    }

    // TODO does this handle both cases as above?
    res = Encode_ASB(bundle, sec_blk.block_num, &abs_sec_block);
    if (res != BSL_SUCCESS)
    {
        return res;
    }

    BSL_AbsSecBlock_Deinit(&abs_sec_block);
    return BSL_SUCCESS;
}

int BSL_SecCtx_ExecutePolicyActionSet(BSL_LibCtx_t *lib, BSL_SecurityResponseSet_t *output_response,
                                      BSL_BundleRef_t *bundle, const BSL_SecurityActionSet_t *action_set)
{
    // NOLINTBEGIN
    CHK_ARG_NONNULL(lib);
    CHK_ARG_NONNULL(output_response);
    CHK_ARG_NONNULL(bundle);
    CHK_PRECONDITION(BSL_SecurityActionSet_IsConsistent(action_set));
    // NOLINTEND

    BSL_SecurityResponseSet_Init(output_response, BSL_SecurityActionSet_CountOperations(action_set), 0);
    /**
     * Notes:
     *  - It should evaluate every security operation, even if earlier ones failed.
     *  - The outcome can indicate in the policy action response how exactly it fared (pass, fail, etc)
     *  - BCB will be a special case, since it actively manipulates the BTSD
     *
     */
    BSL_SecOutcome_t *outcome = BSL_CALLOC(1, BSL_SecOutcome_Sizeof());

    BSL_SecActionList_it_t act_it;
    for (BSL_SecActionList_it(act_it, action_set->actions); !BSL_SecActionList_end_p(act_it);
         BSL_SecActionList_next(act_it))
    {
        BSL_SecurityAction_t *act = BSL_SecActionList_ref(act_it);
        for (size_t i = 0; i < BSL_SecurityAction_CountSecOpers(act); i++)
        {
            memset(outcome, 0, BSL_SecOutcome_Sizeof());

            BSL_SecOper_t          *sec_oper = BSL_SecurityAction_GetSecOperAtIndex(act, i);
            const BSL_SecCtxDesc_t *sec_ctx  = BSL_SecCtxDict_cget(lib->sc_reg, sec_oper->context_id);
            ASSERT_PROPERTY(sec_ctx != NULL);

            BSL_SecOutcome_Init(outcome, sec_oper, 100000);

            int errcode = -1;
            if (BSL_SecOper_IsBIB(sec_oper))
            {
                errcode = BSL_SecOper_IsRoleSource(sec_oper) == true
                              ? BSL_ExecBIBSource(sec_ctx->execute, lib, bundle, sec_oper, outcome)
                              : BSL_ExecBIBAccept(sec_ctx->execute, lib, bundle, sec_oper, outcome);
            }
            else
            {
                if (BSL_SecOper_IsRoleSource(sec_oper))
                {
                    errcode = BSL_ExecBCBSource(sec_ctx->execute, lib, bundle, sec_oper, outcome);
                }
                else
                {
                    errcode = BSL_ExecBCBAcceptor(sec_ctx->execute, lib, bundle, sec_oper, outcome);
                }
            }

            BSL_SecOutcome_Deinit(outcome);

            if (errcode != 0)
            {
                BSL_LOG_ERR("Security Op failed: %d", errcode);
                BSL_SecOper_SetConclusion(sec_oper, BSL_SECOP_CONCLUSION_FAILURE);
                break; // stop processing secops if there is a failure
            }
            BSL_SecOper_SetConclusion(sec_oper, BSL_SECOP_CONCLUSION_SUCCESS);
        }
    }
    BSL_FREE(outcome);

    return BSL_SUCCESS;
}

bool BSL_SecCtx_ValidatePolicyActionSet(BSL_LibCtx_t *lib, const BSL_BundleRef_t *bundle,
                                        const BSL_SecurityActionSet_t *action_set)
{
    (void)lib;
    (void)bundle;
    (void)action_set;
    return true;
}
