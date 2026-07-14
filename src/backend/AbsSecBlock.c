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
/** @file AbsSecBlock.c
 * @brief Concrete implementation of the Abstract Security Block defined in RFC 9172.
 * @ingroup backend_dyn
 */
#include <qcbor/qcbor_encode.h>
#include <qcbor/qcbor_spiffy_decode.h>

#include <BPSecLib_Private.h>

#include "AbsSecBlock.h"
#include "TextUtil.h"
#include "CBOR.h"

void BSL_AbsSecBlock_Target_Init(BSL_AbsSecBlock_Target_t *self)
{
    self->target_block_num = 0;
    BSLB_VariantPtrMap_init(self->results);
}

void BSL_AbsSecBlock_Target_Deinit(BSL_AbsSecBlock_Target_t *self)
{
    BSLB_VariantPtrMap_clear(self->results);
    self->target_block_num = 0;
}

size_t BSL_AbsSecBlock_Sizeof(void)
{
    return sizeof(BSL_AbsSecBlock_t);
}

bool BSL_AbsSecBlock_IsConsistent(const BSL_AbsSecBlock_t *self)
{
    // GCOV_EXCL_START
    // NOLINTBEGIN
    CHK_AS_BOOL(self != NULL);
    CHK_AS_BOOL(self->source_eid.handle != NULL);
    // NOLINTEND
    // GCOV_EXCL_STOP
    return true;
}

static void BSL_Variant_Print(const BSLB_VariantPtrMap_subtype_ct *pair, const char *label, size_t index)
{
    const int64_t *const key_ptr = pair->key_ptr;

    const BSL_Variant_t *var = BSLB_VariantPtr_cref(*(pair->value_ptr));

    if (BSL_Variant_IsInt64(var))
    {
        BSL_LOG_DEBUG("ASB  %s[%zu]: id=%" PRIu64 " val=%" PRIu64, label, index, *key_ptr, var->_val.as_int);
    }
    else if (BSL_Variant_IsBytestr(var))
    {
        BSL_Data_t val;
        BSL_Variant_GetAsBytestr(var, &val);

        BSL_Data_t hex_str = BSL_DATA_INIT_NULL;
        BSL_TextUtil_Base16_Encode(&hex_str, &val, false);
        BSL_LOG_DEBUG("ASB  %s[%zu]: id=%" PRIu64 " val=%s", label, index, *key_ptr, hex_str.ptr);
        BSL_Data_Deinit(&hex_str);
    }
    else if (BSL_Variant_IsTextstr(var))
    {
        const char *val;
        BSL_Variant_GetAsTextstr(var, &val);

        BSL_LOG_DEBUG("ASB  %s[%zu]: id=%" PRIu64 " val=%s", label, index, *key_ptr, val);
    }
}

void BSL_AbsSecBlock_Print(const BSL_AbsSecBlock_t *self)
{
    BSL_LOG_DEBUG("ASB  context id: %" PRId64, self->sec_context_id);

    size_t                          target_ix = 0;
    BSL_AbsSecBlock_TargetList_it_t tgt_iter;
    for (BSL_AbsSecBlock_TargetList_it(tgt_iter, self->target_results); !BSL_AbsSecBlock_TargetList_end_p(tgt_iter);
         BSL_AbsSecBlock_TargetList_next(tgt_iter), ++target_ix)
    {
        const BSL_AbsSecBlock_Target_t *tgt = BSL_AbsSecBlock_TargetPtr_cref(*BSL_AbsSecBlock_TargetList_ref(tgt_iter));

        BSL_LOG_DEBUG("ASB  target[%zu]: %" PRIu64, target_ix, tgt->target_block_num);
    }

    size_t                  param_ix = 0;
    BSLB_VariantPtrMap_it_t param_iter;
    for (BSLB_VariantPtrMap_it(param_iter, self->params); !BSLB_VariantPtrMap_end_p(param_iter);
         BSLB_VariantPtrMap_next(param_iter), ++param_ix)
    {
        const BSLB_VariantPtrMap_subtype_ct *param_pair = BSLB_VariantPtrMap_cref(param_iter);
        BSL_Variant_Print(param_pair, "Param", param_ix);
    }

    for (BSL_AbsSecBlock_TargetList_it(tgt_iter, self->target_results); !BSL_AbsSecBlock_TargetList_end_p(tgt_iter);
         BSL_AbsSecBlock_TargetList_next(tgt_iter))
    {
        const BSL_AbsSecBlock_Target_t *tgt = BSL_AbsSecBlock_TargetPtr_cref(*BSL_AbsSecBlock_TargetList_ref(tgt_iter));
        BSL_LOG_DEBUG("ASB  Results for target block %" PRIu64 " are:", tgt->target_block_num);

        size_t                  result_ix = 0;
        BSLB_VariantPtrMap_it_t result_iter;
        for (BSLB_VariantPtrMap_it(result_iter, tgt->results); !BSLB_VariantPtrMap_end_p(result_iter);
             BSLB_VariantPtrMap_next(result_iter), ++result_ix)
        {
            const BSLB_VariantPtrMap_subtype_ct *result_pair = BSLB_VariantPtrMap_cref(result_iter);
            BSL_Variant_Print(result_pair, "Result", result_ix);
        }
    }
}

void BSL_AbsSecBlock_Init(BSL_AbsSecBlock_t *self)
{
    // GCOV_EXCL_START
    ASSERT_ARG_NONNULL(self);
    // GCOV_EXCL_STOP

    memset(self, 0, sizeof(*self));

    self->sec_context_id = 0;
    BSL_HostEID_Init(&self->source_eid);
    BSLB_VariantPtrMap_init(self->params);
    BSL_AbsSecBlock_TargetList_init(self->target_results);

    // GCOV_EXCL_START
    ASSERT_POSTCONDITION(BSL_AbsSecBlock_IsConsistent(self));
    // GCOV_EXCL_STOP
}

void BSL_AbsSecBlock_Deinit(BSL_AbsSecBlock_t *self)
{
    // GCOV_EXCL_START
    ASSERT_PRECONDITION(BSL_AbsSecBlock_IsConsistent(self));
    // GCOV_EXCL_STOP

    BSL_AbsSecBlock_TargetList_clear(self->target_results);
    BSLB_VariantPtrMap_clear(self->params);
    BSL_HostEID_Deinit(&self->source_eid);

    memset(self, 0, sizeof(*self));
}

bool BSL_AbsSecBlock_IsEmpty(const BSL_AbsSecBlock_t *self)
{
    // GCOV_EXCL_START
    ASSERT_ARG_NONNULL(self);
    // GCOV_EXCL_STOP

    bool is_empty = BSL_AbsSecBlock_TargetList_empty_p(self->target_results);
    return is_empty;
}

int64_t BSL_AbsSecBlock_GetContextID(const BSL_AbsSecBlock_t *self)
{
    // GCOV_EXCL_START
    ASSERT_ARG_NONNULL(self);
    // GCOV_EXCL_STOP

    return self->sec_context_id;
}

bool BSL_AbsSecBlock_ContainsTarget(const BSL_AbsSecBlock_t *self, uint64_t target_block_num)
{
    // GCOV_EXCL_START
    ASSERT_PRECONDITION(BSL_AbsSecBlock_IsConsistent(self));
    // GCOV_EXCL_STOP

    BSL_AbsSecBlock_TargetList_it_t tgt_iter;
    for (BSL_AbsSecBlock_TargetList_it(tgt_iter, self->target_results); !BSL_AbsSecBlock_TargetList_end_p(tgt_iter);
         BSL_AbsSecBlock_TargetList_next(tgt_iter))
    {
        const BSL_AbsSecBlock_Target_t *tgt = BSL_AbsSecBlock_TargetPtr_cref(*BSL_AbsSecBlock_TargetList_ref(tgt_iter));

        if (tgt->target_block_num == target_block_num)
        {
            return true;
        }
    }
    return false;
}

BSL_AbsSecBlock_Target_t *BSL_AbsSecBlock_AddTarget(BSL_AbsSecBlock_t *self, uint64_t target_block_num)
{
    // GCOV_EXCL_START
    ASSERT_PRECONDITION(BSL_AbsSecBlock_IsConsistent(self));
    // GCOV_EXCL_STOP

    BSL_AbsSecBlock_TargetPtr_t **tgt_ptr = BSL_AbsSecBlock_TargetList_push_new(self->target_results);
    *tgt_ptr                              = BSL_AbsSecBlock_TargetPtr_new();

    BSL_AbsSecBlock_Target_t *tgt = BSL_AbsSecBlock_TargetPtr_ref(*tgt_ptr);
    // leave results empty
    tgt->target_block_num = target_block_num;

    return tgt;
}

int BSL_AbsSecBlock_StripResults(BSL_AbsSecBlock_t *self, uint64_t target_block_num)
{
    // GCOV_EXCL_START
    CHK_PRECONDITION(BSL_AbsSecBlock_IsConsistent(self));
    // GCOV_EXCL_STOP

    size_t things_removed = 0;

    // Remove target and its results
    BSL_AbsSecBlock_TargetList_it_t iter;
    for (BSL_AbsSecBlock_TargetList_it(iter, self->target_results); !BSL_AbsSecBlock_TargetList_end_p(iter);)
    {
        const BSL_AbsSecBlock_Target_t *tgt = BSL_AbsSecBlock_TargetPtr_cref(*BSL_AbsSecBlock_TargetList_ref(iter));

        if (tgt->target_block_num == target_block_num)
        {
            things_removed += 1 + BSLB_VariantPtrMap_size(tgt->results);
            BSL_AbsSecBlock_TargetList_remove(self->target_results, iter);
        }
        else
        {
            BSL_AbsSecBlock_TargetList_next(iter);
        }
    }

    CHK_POSTCONDITION(BSL_AbsSecBlock_IsConsistent(self));
    return (int)things_removed;
}

int BSL_AbsSecBlock_Encode(QCBOREncodeContext *enc, const BSL_AbsSecBlock_t *asb)
{
    CHK_PRECONDITION(BSL_AbsSecBlock_IsConsistent(asb));

    {
        QCBOREncode_OpenArray(enc);
        BSL_AbsSecBlock_TargetList_it_t tgt_iter;
        for (BSL_AbsSecBlock_TargetList_it(tgt_iter, asb->target_results); !BSL_AbsSecBlock_TargetList_end_p(tgt_iter);
             BSL_AbsSecBlock_TargetList_next(tgt_iter))
        {
            const BSL_AbsSecBlock_Target_t *tgt =
                BSL_AbsSecBlock_TargetPtr_cref(*BSL_AbsSecBlock_TargetList_ref(tgt_iter));

            QCBOREncode_AddUInt64(enc, tgt->target_block_num);
        }
        QCBOREncode_CloseArray(enc);
    }

    QCBOREncode_AddInt64(enc, asb->sec_context_id);

    {
        uint64_t flags = 0;
        if (!BSLB_VariantPtrMap_empty_p(asb->params))
        {
            flags |= BSL_ABSSECBLOCK_FLAG_HAS_PARAM;
        }
        QCBOREncode_AddUInt64(enc, flags);
    }

    int res = BSL_CBOR_EncodeEID(enc, &asb->source_eid);
    if (res != BSL_SUCCESS)
    {
        return res;
    }

    if (!BSLB_VariantPtrMap_empty_p(asb->params))
    {
        QCBOREncode_OpenArray(enc);

        BSLB_VariantPtrMap_it_t pit;
        for (BSLB_VariantPtrMap_it(pit, asb->params); !BSLB_VariantPtrMap_end_p(pit); BSLB_VariantPtrMap_next(pit))
        {
            const BSLB_VariantPtrMap_subtype_ct *pair = BSLB_VariantPtrMap_cref(pit);
            QCBOREncode_OpenArray(enc);

            QCBOREncode_AddInt64(enc, *(pair->key_ptr));

            const BSL_Variant_t *param = BSLB_VariantPtr_cref(*(pair->value_ptr));
            BSL_Variant_Encode(enc, param);

            QCBOREncode_CloseArray(enc);
        }
        QCBOREncode_CloseArray(enc);
    }

    {
        // Encode results for each target
        QCBOREncode_OpenArray(enc);

        BSL_AbsSecBlock_TargetList_it_t tgt_iter;
        for (BSL_AbsSecBlock_TargetList_it(tgt_iter, asb->target_results); !BSL_AbsSecBlock_TargetList_end_p(tgt_iter);
             BSL_AbsSecBlock_TargetList_next(tgt_iter))
        {
            const BSL_AbsSecBlock_Target_t *tgt =
                BSL_AbsSecBlock_TargetPtr_cref(*BSL_AbsSecBlock_TargetList_ref(tgt_iter));

            QCBOREncode_OpenArray(enc);

            BSLB_VariantPtrMap_it_t result_iter;
            for (BSLB_VariantPtrMap_it(result_iter, tgt->results); !BSLB_VariantPtrMap_end_p(result_iter);
                 BSLB_VariantPtrMap_next(result_iter))
            {
                const BSLB_VariantPtrMap_subtype_ct *pair = BSLB_VariantPtrMap_cref(result_iter);
                QCBOREncode_OpenArray(enc);

                QCBOREncode_AddInt64(enc, *(pair->key_ptr));

                const BSL_Variant_t *result = BSLB_VariantPtr_cref(*(pair->value_ptr));
                BSL_Variant_Encode(enc, result);

                QCBOREncode_CloseArray(enc);
            }

            QCBOREncode_CloseArray(enc);
        }

        QCBOREncode_CloseArray(enc);
    }
    return BSL_SUCCESS;
}

int BSL_AbsSecBlock_Decode(QCBORDecodeContext *dec, BSL_AbsSecBlock_t *self)
{
    ASSERT_ARG_NONNULL(dec);
    ASSERT_ARG_NONNULL(self);
    QCBORItem asbitem;
    int res;

    QCBORDecode_EnterArray(dec, NULL);

    // Make sure actually entered an array - otherwise, the following while loop could be infinite
    QCBORError tgt_array_err = QCBORDecode_GetError(dec);
    if (QCBOR_SUCCESS != tgt_array_err)
    {
        BSL_LOG_ERR("ASB decoding: Failed to enter target array ; error %d (%s)", tgt_array_err,
                    qcbor_err_to_str(tgt_array_err));
        return BSL_ERR_DECODING;
    }

    while (QCBOR_SUCCESS == QCBORDecode_PeekNext(dec, &asbitem))
    {
        uint64_t target_block_num = 0;
        QCBORDecode_GetUInt64(dec, &target_block_num);
        if (QCBOR_SUCCESS != QCBORDecode_GetError(dec))
        {
            BSL_LOG_ERR("Failed processing a security target");
            return BSL_ERR_DECODING;
        }

        BSL_LOG_DEBUG("got tgt %" PRIu64, target_block_num);
        BSL_AbsSecBlock_AddTarget(self, target_block_num);
    }
    QCBORDecode_ExitArray(dec);
    const size_t targets_size = BSL_AbsSecBlock_TargetList_size(self->target_results);

    {
        int64_t ctx_id = 0;
        QCBORDecode_GetInt64(dec, &ctx_id);
        BSL_LOG_DEBUG("got ctx_id %" PRId64, ctx_id);
        if ((ctx_id < INT16_MIN) || (ctx_id > INT16_MAX))
        {
            BSL_LOG_ERR("Invalid context id: %" PRId64, ctx_id);
        }
        self->sec_context_id = ctx_id;
    }

    uint64_t flags = 0;
    QCBORDecode_GetUInt64(dec, &flags);
    BSL_LOG_DEBUG("got flags %" PRId64, flags);

    {
        // Host-specific parsing of EID
        const UsefulBufC raw_buf = QCBORDecode_RetrieveUndecodedInput(dec);

        QCBORItem eid_item;
        // Get size of next CBOR item
        uint32_t eid_item_start_index = QCBORDecode_Tell(dec);
        QCBORDecode_VGetNextConsume(dec, &eid_item);
        uint32_t eid_item_end_index = QCBORDecode_Tell(dec);

        // Validate indexes
        if ((QCBOR_SUCCESS != QCBORDecode_GetError(dec)) || (eid_item_end_index <= eid_item_start_index))
        {
            BSL_LOG_ERR("BSL DECODE FAIL");
            return BSL_ERR_DECODING;
        }

        UsefulBufC eid_raw = (UsefulBufC) { ((const uint8_t *)raw_buf.ptr) + eid_item_start_index,
                                            eid_item_end_index - eid_item_start_index };

        BSL_Data_t eid_cbor_data;
        BSL_Data_InitView(&eid_cbor_data, eid_raw.len, (uint8_t *)eid_raw.ptr);

        res = BSL_HostEID_DecodeFromCBOR(&eid_cbor_data, &self->source_eid);
        BSL_Data_Deinit(&eid_cbor_data);
        if (res != BSL_SUCCESS)
        {
            BSL_LOG_ERR("BSL HOST EID DECODE FAIL");
            return BSL_ERR_DECODING;
        }
    }

    // A zero value for flags means there are NO paramers, a value of 1 indicates there are parameters to parse.
    if (flags & BSL_ABSSECBLOCK_FLAG_HAS_PARAM)
    {
        // variable length array of parameters
        BSL_LOG_DEBUG("Parsing parameter array");
        QCBORDecode_EnterArray(dec, NULL);
        while (QCBOR_SUCCESS == QCBORDecode_PeekNext(dec, &asbitem))
        {
            // each parameter is a 2-item array
            QCBORDecode_EnterArray(dec, NULL);

            int64_t item_id = 0;
            QCBORDecode_GetInt64(dec, &item_id);
            res = QCBORDecode_GetError(dec);
            if (QCBOR_SUCCESS != res)
            {
                BSL_LOG_ERR("Failed getting an int ID: code %d", res);
                return BSL_ERR_DECODING;
            }

            {
                BSLB_VariantPtr_t *item_ptr = BSLB_VariantPtr_new();
                BSLB_VariantPtrMap_set_at(self->params, item_id, item_ptr);
                BSL_Variant_t *param = BSLB_VariantPtr_ref(item_ptr);
                res = BSL_Variant_Decode(dec, param);
                BSLB_VariantPtr_release(item_ptr);
            if (BSL_SUCCESS != res)
            {
                BSL_LOG_ERR("Failed getting a parameter value: code %d", res);
                return BSL_ERR_DECODING;
            }
            }

            QCBORDecode_ExitArray(dec);
            if (QCBOR_SUCCESS != QCBORDecode_GetError(dec))
            {
                BSL_LOG_ERR("Failed processing a security parameter");
                return BSL_ERR_DECODING;
            }
        }
        QCBORDecode_ExitArray(dec);
    }

    QCBORDecode_EnterArray(dec, NULL);
    size_t target_index;
    for (target_index = 0; QCBOR_SUCCESS == QCBORDecode_PeekNext(dec, &asbitem); ++target_index)
    {
        if (target_index >= targets_size)
        {
            BSL_LOG_ERR("ASB result array has too many items, expected %zu got %zu", targets_size, target_index);
            return BSL_ERR_DECODING;
        }
        // Each result array correlates to the same ordinal number of the target list
        BSL_AbsSecBlock_TargetPtr_t **tgt_ptr = BSL_AbsSecBlock_TargetList_get(self->target_results, target_index);

        BSL_AbsSecBlock_Target_t *tgt = BSL_AbsSecBlock_TargetPtr_ref(*tgt_ptr);

        // variable length array of result pairs
        BSL_LOG_DEBUG("Parsing result array for target %" PRIu64, tgt->target_block_num);
        QCBORDecode_EnterArray(dec, NULL);
        while (QCBOR_SUCCESS == QCBORDecode_PeekNext(dec, &asbitem))
        {
            // each result is a 2-item array
            QCBORDecode_EnterArray(dec, NULL);

            int64_t item_id = 0;
            QCBORDecode_GetInt64(dec, &item_id);
            res = QCBORDecode_GetError(dec);
            if (QCBOR_SUCCESS != res)
            {
                BSL_LOG_ERR("Failed getting an int ID: code %d", res);
                return BSL_ERR_DECODING;
            }

            {
                BSLB_VariantPtr_t *item_ptr = BSLB_VariantPtr_new();
                BSLB_VariantPtrMap_set_at(tgt->results, item_id, item_ptr);
                BSL_Variant_t *result = BSLB_VariantPtr_ref(item_ptr);
                res = BSL_Variant_Decode(dec, result);
                BSLB_VariantPtr_release(item_ptr);
            if (BSL_SUCCESS != res)
            {
                BSL_LOG_ERR("Failed getting a result value: code %d", res);
                return BSL_ERR_DECODING;
            }
            }

            QCBORDecode_ExitArray(dec);
            if (QCBOR_SUCCESS != QCBORDecode_GetError(dec))
            {
                BSL_LOG_ERR("Failed processing a security result");
                return BSL_ERR_DECODING;
            }
        }
        QCBORDecode_ExitArray(dec);
    }
    QCBORDecode_ExitArray(dec);

    if (target_index < targets_size)
    {
        BSL_LOG_ERR("ASB result array has too few items, expected %zu got %zu", targets_size, target_index);
        return BSL_ERR_DECODING;
    }

    ASSERT_POSTCONDITION(BSL_AbsSecBlock_IsConsistent(self));
    return BSL_SUCCESS;
}
