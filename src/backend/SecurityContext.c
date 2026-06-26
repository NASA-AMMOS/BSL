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

/** @file
 * @brief Implementation of functions to interact with the security context
 * @ingroup backend_dyn
 *
 */
#include <BPSecLib_Private.h>

#include "AbsSecBlock.h"
#include "PublicInterfaceImpl.h"
#include "SecOperation.h"
#include "SecOutcome.h"
#include "SecurityActionSet.h"

static int Encode_ASB(BSL_LibCtx_t *lib, BSL_BundleRef_t *bundle, uint64_t blk_num,
                      const BSL_AbsSecBlock_t *abs_sec_block)
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

    BSL_TlmCounters_IncrementCounter(lib, BSL_TLM_ASB_ENCODE_BYTES, (uint64_t)asb_data.len);
    BSL_TlmCounters_IncrementCounter(lib, BSL_TLM_ASB_ENCODE_COUNT, 1);

    BSL_Data_Deinit(&asb_data);
    return BSL_SUCCESS;
}

/** Common handling of informing new ASB content after an operation.
 */
static int BSL_ExecAnySource_Post(BSL_LibCtx_t *lib, BSL_BundleRef_t *bundle, const BSL_SecOper_t *sec_oper,
                                  const BSL_SecOutcome_t *outcome, BSL_AbsSecBlock_t *asb)
{
    BSL_CanonicalBlock_t sec_blk;
    if (BSL_BundleCtx_GetBlockMetadata(bundle, sec_oper->sec_block_num, &sec_blk) != BSL_SUCCESS)
    {
        BSL_LOG_ERR("Failed to get security block");
        return BSL_ERR_HOST_CALLBACK_FAILED;
    }

    asb->sec_context_id = sec_oper->context_id;

    if (BSL_SUCCESS != BSL_Host_GetSecSrcEID(&asb->source_eid))
    {
        BSL_LOG_ERR("Failed to get host EID");
        return BSL_ERR_HOST_CALLBACK_FAILED;
    }

    // target-independent data
    BSLB_IdValPairPtrList_it_t param_it;
    for (BSLB_IdValPairPtrList_it(param_it, outcome->param_list); !BSLB_IdValPairPtrList_end_p(param_it);
         BSLB_IdValPairPtrList_next(param_it))
    {
        BSLB_IdValPairPtr_t **ptr = BSLB_IdValPairPtrList_ref(param_it);
        // copy shared ptr
        BSLB_IdValPairPtrList_push_back(asb->params, *ptr);
    }

    // target-specific data
    BSL_AbsSecBlock_Target_t *tgt = BSL_AbsSecBlock_AddTarget(asb, sec_oper->target_block_num);

    BSLB_IdValPairPtrList_it_t result_it;
    for (BSLB_IdValPairPtrList_it(result_it, outcome->result_list); !BSLB_IdValPairPtrList_end_p(result_it);
         BSLB_IdValPairPtrList_next(result_it))
    {
        BSLB_IdValPairPtr_t **ptr = BSLB_IdValPairPtrList_ref(result_it);
        // copy shared ptr
        BSLB_IdValPairPtrList_push_back(tgt->results, *ptr);
    }

    int res = Encode_ASB(lib, bundle, sec_blk.block_num, asb);
    if (res != BSL_SUCCESS)
    {
        BSL_TlmCounters_IncrementCounter(lib, BSL_TLM_SECOP_FAIL_COUNT, 1);
    }

    return BSL_SUCCESS;
}

int BSL_ExecBIBSource(BSL_SecCtx_Execute_f sec_context_fn, BSL_LibCtx_t *lib, BSL_BundleRef_t *bundle,
                      BSL_SecOper_t *sec_oper, BSL_SecOutcome_t *outcome)
{
    CHK_ARG_NONNULL(sec_context_fn);
    CHK_ARG_NONNULL(bundle);
    CHK_ARG_NONNULL(sec_oper);
    CHK_ARG_NONNULL(outcome);

    BSL_TlmCounters_IncrementCounter(lib, BSL_TLM_SECOP_SOURCE_COUNT, 1);

    uint64_t created_block_num = 0;
    int      created_result    = BSL_BundleCtx_CreateBlock(bundle, BSL_SECBLOCKTYPE_BIB, &created_block_num);
    if (created_result != BSL_SUCCESS)
    {
        BSL_LOG_ERR("Failed to create BIB block, error=%d", created_result);
        BSL_TlmCounters_IncrementCounter(lib, BSL_TLM_SECOP_FAIL_COUNT, 1);
        return BSL_ERR_BUNDLE_OPERATION_FAILED;
    }

    CHK_PROPERTY(created_block_num > 1);

    sec_oper->sec_block_num = created_block_num;

    const int bib_result = (*sec_context_fn)(lib, bundle, sec_oper, outcome);
    if (bib_result != 0) // || outcome->is_success == false)
    {
        BSL_LOG_ERR("BIB Source failed!");
        BSL_TlmCounters_IncrementCounter(lib, BSL_TLM_SECOP_FAIL_COUNT, 1);
        return BSL_ERR_SECURITY_OPERATION_FAILED;
    }

    BSL_CanonicalBlock_t sec_blk = { 0 };
    if (BSL_BundleCtx_GetBlockMetadata(bundle, created_block_num, &sec_blk) != BSL_SUCCESS)
    {
        BSL_LOG_ERR("Could not get BIB block (num=%" PRIu64 ")", created_block_num);
        BSL_TlmCounters_IncrementCounter(lib, BSL_TLM_SECOP_FAIL_COUNT, 1);
        return BSL_ERR_SECURITY_OPERATION_FAILED;
    }

    BSL_AbsSecBlock_t asb;
    BSL_AbsSecBlock_Init(&asb);
    int res = BSL_ExecAnySource_Post(lib, bundle, sec_oper, outcome, &asb);
    if (BSL_SUCCESS != res)
    {
        BSL_TlmCounters_IncrementCounter(lib, BSL_TLM_SECOP_FAIL_COUNT, 1);
    }

    BSL_AbsSecBlock_Deinit(&asb);
    return res;
}

/** Common handling of binding to existing ASB content from an operation.
 */
static int BSL_ExecAnyVerifierAcceptor_Pre(BSL_LibCtx_t *lib, BSL_BundleRef_t *bundle, BSL_SecOper_t *sec_oper,
                                           BSL_AbsSecBlock_t *asb)
{
    BSL_CanonicalBlock_t sec_blk;

    int res = BSL_BundleCtx_GetBlockMetadata(bundle, sec_oper->sec_block_num, &sec_blk);
    if (res != BSL_SUCCESS)
    {
        BSL_LOG_ERR("Could not get block metadata for security block number %" PRIu64, sec_oper->sec_block_num);
        return BSL_ERR_HOST_CALLBACK_FAILED;
    }

    // ASB decoder needs the whole BTSD now
    BSL_Data_t btsd_copy;
    BSL_Data_InitBuffer(&btsd_copy, sec_blk.btsd_len);

    BSL_SeqReader_t *btsd_read = BSL_BundleCtx_ReadBTSD(bundle, sec_blk.block_num);
    BSL_SeqReader_Get(btsd_read, btsd_copy.ptr, &btsd_copy.len);
    BSL_SeqReader_Destroy(btsd_read);

    if (BSL_AbsSecBlock_DecodeFromCBOR(asb, &btsd_copy) != BSL_SUCCESS)
    {
        BSL_LOG_ERR("Failed to parse ASB CBOR");
        BSL_Data_Deinit(&btsd_copy);
        BSL_TlmCounters_IncrementCounter(lib, BSL_TLM_SECOP_FAIL_COUNT, 1);
        return BSL_ERR_DECODING;
    }
    BSL_TlmCounters_IncrementCounter(lib, BSL_TLM_ASB_DECODE_BYTES, sec_blk.btsd_len);
    BSL_TlmCounters_IncrementCounter(lib, BSL_TLM_ASB_DECODE_COUNT, 1);
    BSL_Data_Deinit(&btsd_copy);

    CHK_PROPERTY(BSL_AbsSecBlock_IsConsistent(asb));

    // reference all parameters
    BSLB_IdValPairPtrList_it_t param_iter;
    for (BSLB_IdValPairPtrList_it(param_iter, asb->params); !BSLB_IdValPairPtrList_end_p(param_iter);
         BSLB_IdValPairPtrList_next(param_iter))
    {
        BSLB_IdValPairPtr_t *const *ptr = BSLB_IdValPairPtrList_cref(param_iter);

        // index by ID
        const BSL_IdValPair_t *param = BSLB_IdValPairPtr_cref(*ptr);
        BSLB_IdValPairPtrDict_set_at(sec_oper->_params_in, param->id, *ptr);
    }

    sec_oper->_target_index = 0;
    // reference relevant results
    BSL_AbsSecBlock_TargetList_it_t tgt_iter;
    for (BSL_AbsSecBlock_TargetList_it(tgt_iter, asb->target_results); !BSL_AbsSecBlock_TargetList_end_p(tgt_iter);
         BSL_AbsSecBlock_TargetList_next(tgt_iter))
    {
        const BSL_AbsSecBlock_Target_t *tgt = BSL_AbsSecBlock_TargetPtr_cref(*BSL_AbsSecBlock_TargetList_ref(tgt_iter));
        if (tgt->target_block_num != sec_oper->target_block_num)
        {
            ++(sec_oper->_target_index);
            continue;
        }

        BSLB_IdValPairPtrList_it_t result_iter;
        for (BSLB_IdValPairPtrList_it(result_iter, tgt->results); !BSLB_IdValPairPtrList_end_p(result_iter);
             BSLB_IdValPairPtrList_next(result_iter))
        {
            BSLB_IdValPairPtr_t *const *ptr = BSLB_IdValPairPtrList_cref(result_iter);

            // index by ID
            const BSL_IdValPair_t *result = BSLB_IdValPairPtr_cref(*ptr);
            BSLB_IdValPairPtrDict_set_at(sec_oper->_results_in, result->id, *ptr);
        }

        // first one wins
        break;
    }

    return BSL_SUCCESS;
}

int BSL_ExecBIBVerifierAcceptor(BSL_SecCtx_Execute_f sec_context_fn, BSL_LibCtx_t *lib, BSL_BundleRef_t *bundle,
                                BSL_SecOper_t *sec_oper, BSL_SecOutcome_t *outcome)
{
    CHK_ARG_NONNULL(lib);
    CHK_ARG_NONNULL(bundle);
    CHK_PRECONDITION(BSL_SecOper_IsConsistent(sec_oper));
    CHK_PRECONDITION(BSL_SecOutcome_IsConsistent(outcome));

    BSL_AbsSecBlock_t asb;
    BSL_AbsSecBlock_Init(&asb);
    int res = BSL_ExecAnyVerifierAcceptor_Pre(lib, bundle, sec_oper, &asb);
    if (res != BSL_SUCCESS)
    {
        BSL_LOG_ERR("Could not get existing ASB information");
        BSL_AbsSecBlock_Deinit(&asb);
        BSL_TlmCounters_IncrementCounter(lib, BSL_TLM_SECOP_FAIL_COUNT, 1);
        return res;
    }

    const int sec_context_result = (*sec_context_fn)(lib, bundle, sec_oper, outcome);
    if (sec_context_result != BSL_SUCCESS) // || outcome->is_success == false)
    {
        BSL_LOG_ERR("BIB Sec Ctx processing for verifier/acceptor failed!");
        BSL_AbsSecBlock_Deinit(&asb);
        BSL_TlmCounters_IncrementCounter(lib, BSL_TLM_SECOP_FAIL_COUNT, 1);
        return BSL_ERR_SECURITY_OPERATION_FAILED;
    }

    // If secop is to verify, processing is complete
    if (BSL_SecOper_IsRoleVerifier(sec_oper))
    {
        BSL_TlmCounters_IncrementCounter(lib, BSL_TLM_SECOP_VERIFIER_COUNT, 1);
        BSL_AbsSecBlock_Deinit(&asb);
        return BSL_SUCCESS;
    }

    // TODO/FIXME - This logic seems to be correct, but should be refactored and simplified.
    // There are too many branches/conditionals each with their own return statement.

    // If secop is to accept, BIB must be removed from bundle
    uint64_t target_block_num = BSL_SecOper_GetTargetBlockNum(sec_oper);
    int      status           = BSL_AbsSecBlock_StripResults(&asb, target_block_num);
    if (status <= 0)
    {
        BSL_LOG_ERR("Failure to strip ASB of results");
        BSL_AbsSecBlock_Deinit(&asb);
        BSL_TlmCounters_IncrementCounter(lib, BSL_TLM_SECOP_FAIL_COUNT, 1);
        return BSL_ERR_FAILURE;
    }

    if (BSL_AbsSecBlock_IsEmpty(&asb))
    {
        if (BSL_BundleCtx_RemoveBlock(bundle, sec_oper->sec_block_num) != BSL_SUCCESS)
        {
            BSL_LOG_ERR("Failed to remove block when ASB is empty");
            BSL_AbsSecBlock_Deinit(&asb);
            BSL_TlmCounters_IncrementCounter(lib, BSL_TLM_SECOP_FAIL_COUNT, 1);
            return BSL_ERR_HOST_CALLBACK_FAILED;
        }
    }
    else
    {
        res = Encode_ASB(lib, bundle, sec_oper->sec_block_num, &asb);
        if (res != BSL_SUCCESS)
        {
            BSL_TlmCounters_IncrementCounter(lib, BSL_TLM_SECOP_FAIL_COUNT, 1);
            return res;
        }
    }
    BSL_TlmCounters_IncrementCounter(lib, BSL_TLM_SECOP_ACCEPTOR_COUNT, 1);
    BSL_AbsSecBlock_Deinit(&asb);

    return BSL_SUCCESS;
}

int BSL_ExecBCBVerifierAcceptor(BSL_SecCtx_Execute_f sec_context_fn, BSL_LibCtx_t *lib, BSL_BundleRef_t *bundle,
                                BSL_SecOper_t *sec_oper, BSL_SecOutcome_t *outcome)
{
    CHK_ARG_NONNULL(sec_context_fn);
    CHK_ARG_NONNULL(bundle);
    CHK_ARG_NONNULL(sec_oper);
    CHK_ARG_NONNULL(outcome);

    BSL_AbsSecBlock_t asb;
    BSL_AbsSecBlock_Init(&asb);
    int res = BSL_ExecAnyVerifierAcceptor_Pre(lib, bundle, sec_oper, &asb);
    if (res != BSL_SUCCESS)
    {
        BSL_LOG_ERR("Could not get existing ASB information");
        BSL_AbsSecBlock_Deinit(&asb);
        BSL_TlmCounters_IncrementCounter(lib, BSL_TLM_SECOP_FAIL_COUNT, 1);
        return res;
    }

    const int sec_context_result = (*sec_context_fn)(lib, bundle, sec_oper, outcome);
    if (sec_context_result != BSL_SUCCESS)
    {
        BSL_LOG_ERR("BCB Sec Ctx processing for verifier/acceptor failed!");
        BSL_AbsSecBlock_Deinit(&asb);
        BSL_TlmCounters_IncrementCounter(lib, BSL_TLM_SECOP_FAIL_COUNT, 1);
        return BSL_ERR_SECURITY_OPERATION_FAILED;
    }

    // If secop is to verify, processing is complete
    if (BSL_SecOper_IsRoleVerifier(sec_oper))
    {
        BSL_TlmCounters_IncrementCounter(lib, BSL_TLM_SECOP_VERIFIER_COUNT, 1);
        BSL_AbsSecBlock_Deinit(&asb);
        return BSL_SUCCESS;
    }

    // If secop is to accept, BCB must be removed from bundle
    uint64_t target_block_num = BSL_SecOper_GetTargetBlockNum(sec_oper);
    int      status           = BSL_AbsSecBlock_StripResults(&asb, target_block_num);
    if (status <= 0)
    {
        BSL_LOG_ERR("Failure to strip ASB of results");
        BSL_AbsSecBlock_Deinit(&asb);
        BSL_TlmCounters_IncrementCounter(lib, BSL_TLM_SECOP_FAIL_COUNT, 1);
        return BSL_ERR_FAILURE;
    }

    if (BSL_AbsSecBlock_IsEmpty(&asb))
    {
        if (BSL_BundleCtx_RemoveBlock(bundle, sec_oper->sec_block_num) != BSL_SUCCESS)
        {
            BSL_LOG_ERR("Failed to remove block when ASB is empty");
            BSL_AbsSecBlock_Deinit(&asb);
            BSL_TlmCounters_IncrementCounter(lib, BSL_TLM_SECOP_FAIL_COUNT, 1);
            return BSL_ERR_HOST_CALLBACK_FAILED;
        }
    }
    else
    {
        res = Encode_ASB(lib, bundle, sec_oper->sec_block_num, &asb);
        if (res != BSL_SUCCESS)
        {
            BSL_TlmCounters_IncrementCounter(lib, BSL_TLM_SECOP_FAIL_COUNT, 1);
            return res;
        }
    }
    BSL_TlmCounters_IncrementCounter(lib, BSL_TLM_SECOP_ACCEPTOR_COUNT, 1);
    BSL_AbsSecBlock_Deinit(&asb);

    return BSL_SUCCESS;
}

int BSL_ExecBCBSource(BSL_SecCtx_Execute_f sec_context_fn, BSL_LibCtx_t *lib, BSL_BundleRef_t *bundle,
                      BSL_SecOper_t *sec_oper, BSL_SecOutcome_t *outcome)
{
    CHK_ARG_NONNULL(sec_context_fn);
    CHK_ARG_NONNULL(bundle);
    CHK_ARG_NONNULL(sec_oper);
    CHK_ARG_NONNULL(outcome);

    BSL_TlmCounters_IncrementCounter(lib, BSL_TLM_SECOP_SOURCE_COUNT, 1);

    uint64_t created_block_id = 0;
    if (BSL_SUCCESS != BSL_BundleCtx_CreateBlock(bundle, BSL_SECBLOCKTYPE_BCB, &created_block_id))
    {
        BSL_LOG_ERR("Failed to create BCB block");
        BSL_TlmCounters_IncrementCounter(lib, BSL_TLM_SECOP_FAIL_COUNT, 1);
        return BSL_ERR_HOST_CALLBACK_FAILED;
    }
    BSL_LOG_INFO("Created new BCB block id = %" PRIu64, created_block_id);

    sec_oper->sec_block_num = created_block_id;

    int res = (*sec_context_fn)(lib, bundle, sec_oper, outcome);
    if (res != 0) // || outcome->is_success == false)
    {
        BSL_LOG_ERR("BCB Source failed!");
        BSL_TlmCounters_IncrementCounter(lib, BSL_TLM_SECOP_FAIL_COUNT, 1);
        return BSL_ERR_SECURITY_OPERATION_FAILED;
    }
    BSL_LOG_INFO("BCB SOURCE operation success.");

    BSL_AbsSecBlock_t asb;
    BSL_AbsSecBlock_Init(&asb);
    res = BSL_ExecAnySource_Post(lib, bundle, sec_oper, outcome, &asb);
    if (BSL_SUCCESS != res)
    {
        BSL_TlmCounters_IncrementCounter(lib, BSL_TLM_SECOP_FAIL_COUNT, 1);
    }

    BSL_AbsSecBlock_Deinit(&asb);
    return res;
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

    /**
     * Notes:
     *  - It should evaluate every security operation, even if earlier ones failed.
     *  - The outcome can indicate in the policy action response how exactly it fared (pass, fail, etc)
     *  - BCB will be a special case, since it actively manipulates the BTSD
     *
     */
    BSL_SecOutcome_t *outcome = BSL_calloc(1, BSL_SecOutcome_Sizeof());

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

            BSL_SecOutcome_Init(outcome, sec_oper);

            int errcode = -1;
            if (BSL_SecOper_IsBIB(sec_oper))
            {
                if (BSL_SecOper_IsRoleSource(sec_oper))
                {
                    errcode = BSL_ExecBIBSource(sec_ctx->execute, lib, bundle, sec_oper, outcome);
                }
                else
                {
                    errcode = BSL_ExecBIBVerifierAcceptor(sec_ctx->execute, lib, bundle, sec_oper, outcome);
                }
            }
            else
            {
                if (BSL_SecOper_IsRoleSource(sec_oper))
                {
                    errcode = BSL_ExecBCBSource(sec_ctx->execute, lib, bundle, sec_oper, outcome);
                }
                else
                {
                    errcode = BSL_ExecBCBVerifierAcceptor(sec_ctx->execute, lib, bundle, sec_oper, outcome);
                }
            }

            BSL_SecOutcome_Deinit(outcome);

            if (errcode != BSL_SUCCESS)
            {
                BSL_LOG_ERR("Security Op failed: %d", errcode);
                if (BSL_REASONCODE_NO_ADDITIONAL_INFO == BSL_SecOper_GetReasonCode(sec_oper))
                {
                    BSL_LOG_INFO("SETTING (prev=%d)", BSL_SecOper_GetReasonCode(sec_oper));
                    BSL_SecOper_SetReasonCode(sec_oper, BSL_REASONCODE_FAILED_SECOP);
                }
                BSL_SecOper_SetConclusion(sec_oper, BSL_SECOP_CONCLUSION_FAILURE);
                BSL_SecurityResponseSet_AppendResult(output_response, errcode, sec_oper->policy_action);
                break; // stop processing secops if there is a failure
            }
            BSL_SecOper_SetConclusion(sec_oper, BSL_SECOP_CONCLUSION_SUCCESS);
            BSL_SecurityResponseSet_AppendResult(output_response, errcode, sec_oper->policy_action);
        }
    }
    BSL_free(outcome);

    return BSL_SUCCESS;
}

int BSL_SecCtx_ValidatePolicyActionSet(BSL_LibCtx_t *lib, const BSL_BundleRef_t *bundle,
                                       const BSL_SecurityActionSet_t *action_set)
{
    CHK_ARG_NONNULL(lib);
    CHK_ARG_NONNULL(bundle);
    CHK_ARG_NONNULL(action_set);

    BSL_SecActionList_it_t actlist_it;
    for (BSL_SecActionList_it(actlist_it, action_set->actions); !BSL_SecActionList_end_p(actlist_it);
         BSL_SecActionList_next(actlist_it))
    {
        BSL_SecurityAction_t *action = BSL_SecActionList_ref(actlist_it);

        uint64_t             secop_invalid_count = 0;
        BSL_SecOperList_it_t secoplist_it;
        for (BSL_SecOperList_it(secoplist_it, action->sec_op_list); !BSL_SecOperList_end_p(secoplist_it);
             BSL_SecOperList_next(secoplist_it))
        {
            const BSL_SecOper_t    *sec_oper = BSL_SecOperList_cref(secoplist_it);
            const BSL_SecCtxDesc_t *sec_ctx  = BSL_SecCtxDict_cget(lib->sc_reg, sec_oper->context_id);

            if (sec_ctx == NULL)
            {
                BSL_LOG_ERR("No security context validator registered for context ID %" PRId64, sec_oper->context_id);
                continue;
            }

            if (!sec_ctx->validate(lib, bundle, sec_oper))
            {
                secop_invalid_count++;
                BSL_LOG_WARNING("Security context validator failed for context ID %" PRId64, sec_oper->context_id);
            }
        }

        action->validated = (0 == secop_invalid_count);
    }

    return BSL_SUCCESS;
}
