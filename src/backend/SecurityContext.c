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
#include "CBOR.h"
#include "PublicInterfaceImpl.h"
#include "SecOperation.h"
#include "SecurityActionSet.h"

static int Encode_ASB(BSL_LibCtx_t *lib, BSL_BundleRef_t *bundle, uint64_t blk_num, const BSL_AbsSecBlock_t *asb)
{
    BSL_Data_t asb_data;
    BSL_Data_Init(&asb_data);

    int res = BSL_CBOR_Encode_Twopass(&asb_data, (BSL_CBOR_Encode_f)&BSL_AbsSecBlock_Encode, asb);
    if (BSL_SUCCESS != res)
    {
        BSL_Data_Deinit(&asb_data);
        return res;
    }

    BSL_SeqWriter_t *btsd_write = BSL_BundleCtx_WriteBTSD(bundle, blk_num, asb_data.len);
    if (!btsd_write)
    {
        BSL_LOG_ERR("Failed to get BTSD writer");
        BSL_Data_Deinit(&asb_data);
        return BSL_ERR_ENCODING;
    }

    int retval = BSL_SUCCESS;
    if (BSL_SeqWriter_Put(btsd_write, asb_data.ptr, asb_data.len))
    {
        BSL_LOG_ERR("Failed to write BTSD");
        retval = BSL_ERR_ENCODING;
    }
    // finalize the write
    BSL_SeqWriter_Destroy(btsd_write, retval == BSL_SUCCESS);

    BSL_TlmCounters_IncrementCounter(lib, BSL_TLM_ASB_ENCODE_BYTES, (uint64_t)asb_data.len);
    BSL_TlmCounters_IncrementCounter(lib, BSL_TLM_ASB_ENCODE_COUNT, 1);

    BSL_Data_Deinit(&asb_data);
    return retval;
}

/** Common handling of needed ASB content before an operation.
 */
static int BSL_ExecAnySource_Pre(BSL_LibCtx_t *lib _U_, BSL_BundleRef_t *bundle _U_, BSL_SecOper_t *sec_oper,
                                 BSL_AbsSecBlock_t *asb)
{
    asb->sec_context_id = sec_oper->context_id;

    if (BSL_SUCCESS != BSL_Host_GetSecSrcEID(&asb->source_eid))
    {
        BSL_LOG_ERR("Failed to get host EID");
        return BSL_ERR_HOST_CALLBACK_FAILED;
    }

    sec_oper->sec_src_eid = &asb->source_eid;

    return BSL_SUCCESS;
}

/** Common handling of informing new ASB content after an operation.
 */
static int BSL_ExecAnySource_Post(BSL_LibCtx_t *lib, BSL_BundleRef_t *bundle, BSL_SecOper_t *sec_oper,
                                  BSL_AbsSecBlock_t *asb)
{
    // un-reference outside of execution
    sec_oper->sec_src_eid = NULL;

    BSL_CanonicalBlock_t sec_blk;
    if (BSL_BundleCtx_GetBlockMetadata(bundle, sec_oper->sec_block_num, &sec_blk) != BSL_SUCCESS)
    {
        BSL_LOG_ERR("Failed to get security block");
        return BSL_ERR_HOST_CALLBACK_FAILED;
    }

    // target-independent data
    BSLB_VariantPtrMap_it_t param_it;
    for (BSLB_VariantPtrMap_it(param_it, sec_oper->_params); !BSLB_VariantPtrMap_end_p(param_it);
         BSLB_VariantPtrMap_next(param_it))
    {
        const BSLB_VariantPtrMap_subtype_ct *pair = BSLB_VariantPtrMap_ref(param_it);
        // copy shared ptr
        BSLB_VariantPtrMap_set_at(asb->params, *(pair->key_ptr), *(pair->value_ptr));
    }

    // target-specific data
    BSL_AbsSecBlock_Target_t *tgt = BSL_AbsSecBlock_AddTarget(asb, sec_oper->target_block_num);

    BSLB_VariantPtrMap_it_t result_it;
    for (BSLB_VariantPtrMap_it(result_it, sec_oper->_results); !BSLB_VariantPtrMap_end_p(result_it);
         BSLB_VariantPtrMap_next(result_it))
    {
        const BSLB_VariantPtrMap_subtype_ct *pair = BSLB_VariantPtrMap_ref(result_it);
        // copy shared ptr
        BSLB_VariantPtrMap_set_at(tgt->results, *(pair->key_ptr), *(pair->value_ptr));
    }

    int res = Encode_ASB(lib, bundle, sec_blk.block_num, asb);
    if (res != BSL_SUCCESS)
    {
        BSL_TlmCounters_IncrementCounter(lib, BSL_TLM_SECOP_FAIL_COUNT, 1);
    }

    return BSL_SUCCESS;
}

int BSL_ExecBIBSource(BSL_SecCtx_Execute_f sec_context_fn, BSL_LibCtx_t *lib, BSL_BundleRef_t *bundle,
                      BSL_SecOper_t *sec_oper)
{
    CHK_ARG_NONNULL(sec_context_fn);
    CHK_ARG_NONNULL(bundle);
    CHK_ARG_NONNULL(sec_oper);

    int retval = BSL_SUCCESS;

    BSL_TlmCounters_IncrementCounter(lib, BSL_TLM_SECOP_SOURCE_COUNT, 1);

    // policy may request a block number
    int res = BSL_BundleCtx_CreateBlock(bundle, BSL_SECBLOCKTYPE_BIB, &sec_oper->sec_block_num);
    if (BSL_SUCCESS != res)
    {
        BSL_LOG_ERR("Failed to create BIB block, error=%d", res);
        retval = BSL_ERR_BUNDLE_OPERATION_FAILED;
    }
    else
    {
        BSL_LOG_DEBUG("Created new BIB block number = %" PRIu64, sec_oper->sec_block_num);
        CHK_PROPERTY(sec_oper->sec_block_num > 1);
    }

    BSL_AbsSecBlock_t asb;
    BSL_AbsSecBlock_Init(&asb);
    if (BSL_SUCCESS == retval)
    {
        res = BSL_ExecAnySource_Pre(lib, bundle, sec_oper, &asb);
        if (BSL_SUCCESS != res)
        {
            retval = BSL_ERR_BUNDLE_OPERATION_FAILED;
        }
    }

    if (BSL_SUCCESS == retval)
    {
        res = (*sec_context_fn)(lib, bundle, sec_oper);
        if (res != 0)
        {
            BSL_LOG_ERR("BIB Source failed!");
            retval = BSL_ERR_SECURITY_OPERATION_FAILED;
        }
    }

    if (BSL_SUCCESS == retval)
    {
        res = BSL_ExecAnySource_Post(lib, bundle, sec_oper, &asb);
        if (BSL_SUCCESS != res)
        {
            retval = BSL_ERR_SECURITY_OPERATION_FAILED;
        }
    }

    if (BSL_SUCCESS != retval)
    {
        // any failure
        BSL_TlmCounters_IncrementCounter(lib, BSL_TLM_SECOP_FAIL_COUNT, 1);
    }

    BSL_AbsSecBlock_Deinit(&asb);
    return retval;
}

/** Common handling of binding to existing ASB content from an operation.
 */
static int BSL_ExecAnyVerifierAcceptor_Pre(BSL_LibCtx_t *lib, const BSL_BundleRef_t *bundle, BSL_SecOper_t *sec_oper,
                                           const BSL_AbsSecBlock_t *asb)
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

    if (BSL_CBOR_Decode(&btsd_copy, (BSL_CBOR_Decode_f)&BSL_AbsSecBlock_Decode, asb) != BSL_SUCCESS)
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

    // reference to persistent instance
    sec_oper->sec_src_eid = &asb->source_eid;

    // reference all parameters
    BSLB_VariantPtrMap_it_t param_iter;
    for (BSLB_VariantPtrMap_it(param_iter, asb->params); !BSLB_VariantPtrMap_end_p(param_iter);
         BSLB_VariantPtrMap_next(param_iter))
    {
        const BSLB_VariantPtrMap_subtype_ct *pair = BSLB_VariantPtrMap_cref(param_iter);

        BSLB_VariantPtrMap_set_at(sec_oper->_params, *(pair->key_ptr), *(pair->value_ptr));
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

        BSLB_VariantPtrMap_it_t result_iter;
        for (BSLB_VariantPtrMap_it(result_iter, tgt->results); !BSLB_VariantPtrMap_end_p(result_iter);
             BSLB_VariantPtrMap_next(result_iter))
        {
            const BSLB_VariantPtrMap_subtype_ct *pair = BSLB_VariantPtrMap_cref(result_iter);

            BSLB_VariantPtrMap_set_at(sec_oper->_results, *(pair->key_ptr), *(pair->value_ptr));
        }

        // first one wins
        break;
    }

    return BSL_SUCCESS;
}

int BSL_ExecBIBVerifierAcceptor(BSL_SecCtx_Execute_f sec_context_fn, BSL_LibCtx_t *lib, BSL_BundleRef_t *bundle,
                                BSL_SecOper_t *sec_oper)
{
    CHK_ARG_NONNULL(lib);
    CHK_ARG_NONNULL(bundle);
    CHK_PRECONDITION(BSL_SecOper_IsConsistent(sec_oper));

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

    const int sec_context_result = (*sec_context_fn)(lib, bundle, sec_oper);
    if (sec_context_result != BSL_SUCCESS)
    {
        BSL_LOG_ERR("BIB Sec Ctx processing for verifier/acceptor failed!");
        BSL_AbsSecBlock_Deinit(&asb);
        BSL_TlmCounters_IncrementCounter(lib, BSL_TLM_SECOP_FAIL_COUNT, 1);
        return BSL_ERR_SECURITY_OPERATION_FAILED;
    }

    // un-reference outside of execution
    sec_oper->sec_src_eid = NULL;

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
                                BSL_SecOper_t *sec_oper)
{
    CHK_ARG_NONNULL(sec_context_fn);
    CHK_ARG_NONNULL(bundle);
    CHK_ARG_NONNULL(sec_oper);

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

    const int sec_context_result = (*sec_context_fn)(lib, bundle, sec_oper);
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
                      BSL_SecOper_t *sec_oper)
{
    CHK_ARG_NONNULL(sec_context_fn);
    CHK_ARG_NONNULL(bundle);
    CHK_ARG_NONNULL(sec_oper);

    int retval = BSL_SUCCESS;

    BSL_TlmCounters_IncrementCounter(lib, BSL_TLM_SECOP_SOURCE_COUNT, 1);

    // policy may request a block number
    int res = BSL_BundleCtx_CreateBlock(bundle, BSL_SECBLOCKTYPE_BCB, &sec_oper->sec_block_num);
    if (BSL_SUCCESS != res)
    {
        BSL_LOG_ERR("Failed to create BCB block, error=%d", res);
        retval = BSL_ERR_BUNDLE_OPERATION_FAILED;
    }
    else
    {
        BSL_LOG_DEBUG("Created new BCB block number = %" PRIu64, sec_oper->sec_block_num);
        CHK_PROPERTY(sec_oper->sec_block_num > 1);
    }

    BSL_AbsSecBlock_t asb;
    BSL_AbsSecBlock_Init(&asb);
    if (BSL_SUCCESS == retval)
    {
        res = BSL_ExecAnySource_Pre(lib, bundle, sec_oper, &asb);
        if (BSL_SUCCESS != res)
        {
            retval = BSL_ERR_BUNDLE_OPERATION_FAILED;
        }
    }

    if (BSL_SUCCESS == retval)
    {
        res = (*sec_context_fn)(lib, bundle, sec_oper);
        if (res != 0)
        {
            BSL_LOG_ERR("BCB Source failed!");
            retval = BSL_ERR_SECURITY_OPERATION_FAILED;
        }
        else
        {
            BSL_LOG_DEBUG("BCB SOURCE operation success.");
        }
    }

    if (BSL_SUCCESS == retval)
    {
        res = BSL_ExecAnySource_Post(lib, bundle, sec_oper, &asb);
        if (BSL_SUCCESS != res)
        {
            retval = BSL_ERR_SECURITY_OPERATION_FAILED;
        }
    }

    if (BSL_SUCCESS != retval)
    {
        // any failure
        BSL_TlmCounters_IncrementCounter(lib, BSL_TLM_SECOP_FAIL_COUNT, 1);
    }

    BSL_AbsSecBlock_Deinit(&asb);
    return retval;
}

int BSL_SecCtx_ExecutePolicyActionSet(BSL_LibCtx_t *lib, BSL_BundleRef_t *bundle,
                                      const BSL_SecurityActionSet_t *action_set)
{
    // NOLINTBEGIN
    CHK_ARG_NONNULL(lib);
    CHK_ARG_NONNULL(bundle);
    CHK_PRECONDITION(BSL_SecurityActionSet_IsConsistent(action_set));
    // NOLINTEND

    /**
     * Notes:
     *  - It should evaluate every security operation, even if earlier ones failed.
     *  - The operation conclusion indicates how processing fared (pass, fail, etc.)
     *  - BCB will be a special case, since it actively manipulates the BTSD
     *
     */
    BSL_SecActionList_it_t act_it;
    for (BSL_SecActionList_it(act_it, action_set->actions); !BSL_SecActionList_end_p(act_it);
         BSL_SecActionList_next(act_it))
    {
        BSL_SecurityAction_t *act = BSL_SecActionList_ref(act_it);
        for (size_t i = 0; i < BSL_SecurityAction_CountSecOpers(act); i++)
        {
            BSL_SecOper_t *sec_oper = BSL_SecurityAction_GetSecOperAtIndex(act, i);
            BSL_SecOper_ClearParamsAndResults(sec_oper);
            const BSL_SecCtxDesc_t *sec_ctx = BSL_SecCtxDict_cget(lib->sc_reg, sec_oper->context_id);

            int errcode;
            if (!sec_ctx)
            {
                BSL_LOG_CRIT("Unknown security context %" PRId64, sec_oper->context_id);
                errcode = BSL_REASONCODE_FAILED_SECOP;
            }
            else if (BSL_SecOper_IsBIB(sec_oper))
            {
                if (BSL_SecOper_IsRoleSource(sec_oper))
                {
                    errcode = BSL_ExecBIBSource(sec_ctx->execute, lib, bundle, sec_oper);
                }
                else
                {
                    errcode = BSL_ExecBIBVerifierAcceptor(sec_ctx->execute, lib, bundle, sec_oper);
                }
            }
            else
            {
                if (BSL_SecOper_IsRoleSource(sec_oper))
                {
                    errcode = BSL_ExecBCBSource(sec_ctx->execute, lib, bundle, sec_oper);
                }
                else
                {
                    errcode = BSL_ExecBCBVerifierAcceptor(sec_ctx->execute, lib, bundle, sec_oper);
                }
            }

            if (errcode != BSL_SUCCESS)
            {
                BSL_LOG_ERR("Security Op failed: %d", errcode);
                if (BSL_REASONCODE_NO_ADDITIONAL_INFO == BSL_SecOper_GetReasonCode(sec_oper))
                {
                    BSL_LOG_INFO("SETTING (prev=%d)", BSL_SecOper_GetReasonCode(sec_oper));
                    BSL_SecOper_SetReasonCode(sec_oper, BSL_REASONCODE_FAILED_SECOP);
                }
                BSL_SecOper_SetConclusion(sec_oper, BSL_SECOP_CONCLUSION_FAILURE);
                break; // stop processing secops if there is a failure
            }
            BSL_SecOper_SetConclusion(sec_oper, BSL_SECOP_CONCLUSION_SUCCESS);
        }
    }
    return BSL_SUCCESS;
}

int BSL_SecCtx_ValidatePolicyActionSet(BSL_LibCtx_t *lib, BSL_BundleRef_t *bundle,
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
            BSL_SecOper_t          *sec_oper = BSL_SecOperList_ref(secoplist_it);
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
