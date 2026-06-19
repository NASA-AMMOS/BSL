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
#include "CBOR.h"

void BSL_AbsSecBlock_Target_Init(BSL_AbsSecBlock_Target_t *self)
{
    self->target_block_num = 0;
    BSLB_IdValPairPtrList_init(self->results);
}

void BSL_AbsSecBlock_Target_Deinit(BSL_AbsSecBlock_Target_t *self)
{
    BSLB_IdValPairPtrList_clear(self->results);
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

static void BSL_IdValPair_Print(const BSL_IdValPair_t *pair, const char *label, size_t index)
{
    if (BSL_IdValPair_IsInt64(pair))
    {
        BSL_LOG_DEBUG("ASB  %s[%zu]: id=%" PRIu64 " val=%" PRIu64, label, index, pair->id, pair->_val.as_int);
    }
    else if (BSL_IdValPair_IsBytestr(pair))
    {
        BSL_Data_t val;
        BSL_IdValPair_GetAsBytestr(pair, &val);

        char hex_str[2 * val.len + 1];
        BSL_Log_DumpAsHexString(hex_str, sizeof(hex_str), val.ptr, val.len);
        BSL_LOG_DEBUG("ASB  %s[%zu]: id=%" PRIu64 " val=%s", label, index, pair->id, hex_str);
    }
    else if (BSL_IdValPair_IsTextstr(pair))
    {
        const char *val;
        BSL_IdValPair_GetAsTextstr(pair, &val);

        BSL_LOG_DEBUG("ASB  %s[%zu]: id=%" PRIu64 " val=%s", label, index, pair->id, val);
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

    size_t                     param_ix = 0;
    BSLB_IdValPairPtrList_it_t param_iter;
    for (BSLB_IdValPairPtrList_it(param_iter, self->params); !BSLB_IdValPairPtrList_end_p(param_iter);
         BSLB_IdValPairPtrList_next(param_iter), ++param_ix)
    {
        const BSL_IdValPair_t *param = BSLB_IdValPairPtr_cref(*BSLB_IdValPairPtrList_cref(param_iter));
        BSL_IdValPair_Print(param, "Param", param_ix);
    }

    for (BSL_AbsSecBlock_TargetList_it(tgt_iter, self->target_results); !BSL_AbsSecBlock_TargetList_end_p(tgt_iter);
         BSL_AbsSecBlock_TargetList_next(tgt_iter))
    {
        const BSL_AbsSecBlock_Target_t *tgt = BSL_AbsSecBlock_TargetPtr_cref(*BSL_AbsSecBlock_TargetList_ref(tgt_iter));
        BSL_LOG_DEBUG("ASB  Results for target block %" PRIu64 " are:", tgt->target_block_num);

        size_t                     result_ix = 0;
        BSLB_IdValPairPtrList_it_t result_iter;
        for (BSLB_IdValPairPtrList_it(result_iter, tgt->results); !BSLB_IdValPairPtrList_end_p(result_iter);
             BSLB_IdValPairPtrList_next(result_iter), ++result_ix)
        {
            const BSL_IdValPair_t *result = BSLB_IdValPairPtr_cref(*BSLB_IdValPairPtrList_cref(result_iter));
            BSL_IdValPair_Print(result, "Result", result_ix);
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
    BSLB_IdValPairPtrList_init(self->params);
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
    BSLB_IdValPairPtrList_clear(self->params);
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

    BSL_AbsSecBlock_Target_t *tgt =
        BSL_AbsSecBlock_TargetPtr_ref(*BSL_AbsSecBlock_TargetList_push_new(self->target_results));
    // leave results empty
    tgt->target_block_num = target_block_num;

    return tgt;
}

#if 0
void BSL_AbsSecBlock_AddParam(BSL_AbsSecBlock_t *self, BSL_IdValPair_t *param)
{
    // GCOV_EXCL_START
    ASSERT_ARG_NONNULL(param);
    ASSERT_PRECONDITION(BSL_AbsSecBlock_IsConsistent(self));
    // GCOV_EXCL_STOP

    BSL_IdValPair_t *item = BSLB_IdValPairPtr_ref(*BSLB_IdValPairPtrList_push_new(self->params));
    BSL_IdValPair_Set(item, param);

    // GCOV_EXCL_START
    ASSERT_POSTCONDITION(BSL_AbsSecBlock_IsConsistent(self));
    // GCOV_EXCL_STOP
}

void BSL_AbsSecBlock_AddResult(BSL_AbsSecBlock_t *self, uint64_t target_index, BSL_IdValPair_t *result)
{
    // GCOV_EXCL_START
    ASSERT_ARG_NONNULL(result);
    ASSERT_PRECONDITION(BSL_AbsSecBlock_IsConsistent(self));
    ASSERT_PRECONDITION(target_index < BSL_AbsSecBlock_TargetList_size(self->target_results));
    // GCOV_EXCL_STOP

    BSL_AbsSecBlock_TargetPtr_t *tgt_ptr = BSL_AbsSecBlock_TargetList_get(self->target_results, target_index);

    BSL_AbsSecBlock_Target_t *tgt = BSL_AbsSecBlock_TargetPtr_ref(tgt_ptr);

    BSL_IdValPair_t *item = BSLB_IdValPairPtr_ref(*BSLB_IdValPairPtrList_push_new(tgt->results));
    BSL_IdValPair_Set(item, result);

    // GCOV_EXCL_START
    ASSERT_POSTCONDITION(BSL_AbsSecBlock_IsConsistent(self));
    // GCOV_EXCL_STOP
}
#endif

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
            things_removed += 1 + BSLB_IdValPairPtrList_size(tgt->results);
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

static void BSL_IdValPair_Encode(QCBOREncodeContext *enc, const BSL_IdValPair_t *pair)
{
    QCBOREncode_OpenArray(enc);

    QCBOREncode_AddUInt64(enc, pair->id);

    if (BSL_IdValPair_IsInt64(pair))
    {
        int64_t as_int;
        BSL_IdValPair_GetAsInt64(pair, &as_int);
        QCBOREncode_AddInt64(enc, as_int);
    }
    else if (BSL_IdValPair_IsBytestr(pair))
    {
        BSL_Data_t bytestr;
        BSL_IdValPair_GetAsBytestr(pair, &bytestr);
        QCBOREncode_AddBytes(enc, UsefulBufC_FROM_BSL_Data(bytestr));
    }
    else
    {
        BSL_LOG_CRIT("Unhandled parameter type for ID %" PRIu64, pair->id);
        QCBOREncode_AddUndef(enc);
    }

    QCBOREncode_CloseArray(enc);
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
        if (!BSLB_IdValPairPtrList_empty_p(asb->params))
        {
            flags |= 0x1;
        }
        QCBOREncode_AddUInt64(enc, flags);
    }

    {
        // get needed size first
        ssize_t encode_result = BSL_HostEID_EncodeToCBOR(&asb->source_eid, NULL);
        if (encode_result <= 0)
        {
            BSL_LOG_ERR("Failed to calculate EID size");
            return BSL_ERR_ENCODING;
        }

        BSL_Data_t eid_data;
        BSL_Data_InitBuffer(&eid_data, (size_t)encode_result);
        encode_result = BSL_HostEID_EncodeToCBOR(&asb->source_eid, &eid_data);
        if (encode_result <= BSL_SUCCESS)
        {
            BSL_LOG_ERR("Failed to encode EID");
            BSL_Data_Deinit(&eid_data);
            return BSL_ERR_ENCODING;
        }

        UsefulBufC eid_buf = { .ptr = eid_data.ptr, .len = eid_data.len };
        QCBOREncode_AddEncoded(enc, eid_buf);
        BSL_Data_Deinit(&eid_data);
    }

    {
        QCBOREncode_OpenArray(enc);

        BSLB_IdValPairPtrList_it_t pit;
        for (BSLB_IdValPairPtrList_it(pit, asb->params); !BSLB_IdValPairPtrList_end_p(pit);
             BSLB_IdValPairPtrList_next(pit))
        {
            const BSL_IdValPair_t *param = BSLB_IdValPairPtr_cref(*BSLB_IdValPairPtrList_cref(pit));
            BSL_IdValPair_Encode(enc, param);
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

            BSLB_IdValPairPtrList_it_t result_iter;
            for (BSLB_IdValPairPtrList_it(result_iter, tgt->results); !BSLB_IdValPairPtrList_end_p(result_iter);
                 BSLB_IdValPairPtrList_next(result_iter))
            {
                const BSL_IdValPair_t *result = BSLB_IdValPairPtr_cref(*BSLB_IdValPairPtrList_cref(result_iter));
                BSL_IdValPair_Encode(enc, result);
            }

            QCBOREncode_CloseArray(enc);
        }

        QCBOREncode_CloseArray(enc);
    }
    return BSL_SUCCESS;
}

static int BSL_IdValPair_Decode(QCBORDecodeContext *dec, BSL_IdValPair_t *pair)
{
    ASSERT_ARG_NONNULL(dec);
    ASSERT_ARG_NONNULL(pair);
    QCBORItem asbitem;

    // each parameter is a 2-item array
    QCBORDecode_EnterArray(dec, NULL);

    uint64_t item_id = 0;
    QCBORDecode_GetUInt64(dec, &item_id);
    if (QCBOR_SUCCESS != QCBORDecode_GetError(dec))
    {
        BSL_LOG_ERR("Failed getting an ID");
        return BSL_ERR_DECODING;
    }

    const size_t value_begin = QCBORDecode_Tell(dec);
    QCBORDecode_PeekNext(dec, &asbitem);
    switch (asbitem.uDataType)
    {
        // Collapse both encoded types, with restriction to INT64_MAX
        case QCBOR_TYPE_INT64:
        case QCBOR_TYPE_UINT64:
        {
            int64_t dec_value = 0;
            QCBORDecode_GetInt64(dec, &dec_value);
            if (QCBOR_SUCCESS != QCBORDecode_GetError(dec))
            {
                BSL_LOG_ERR("Invalid integer value for ID %" PRIu64, item_id);
                return BSL_ERR_DECODING;
            }
            BSL_LOG_DEBUG("ASB: Parsed pair[%" PRIu64 "] at %zu as uint %" PRIu64, item_id, value_begin, dec_value);

            BSL_IdValPair_SetInt64(pair, item_id, dec_value);
            break;
        }
        case QCBOR_TYPE_BYTE_STRING:
        {
            UsefulBufC target_buf = NULLUsefulBufC;
            QCBORDecode_GetByteString(dec, &target_buf);
            if (QCBOR_SUCCESS != QCBORDecode_GetError(dec))
            {
                BSL_LOG_ERR("Invalid bytestring value for ID %" PRIu64, item_id);
                return BSL_ERR_DECODING;
            }
            BSL_LOG_DEBUG("ASB: Parsed pair[%" PRIu64 "] at %zu as bytestr with %zu bytes", item_id, value_begin,
                          target_buf.len);
            BSL_Data_t data_view;
            BSL_Data_InitView(&data_view, target_buf.len, (BSL_DataPtr_t)target_buf.ptr);

            BSL_IdValPair_SetBytestr(pair, item_id, data_view);
            break;
        }
        default:
        {
            // skip over entire item (recursively) if possible
            QCBORDecode_VGetNextConsume(dec, &asbitem);
            if (QCBOR_SUCCESS != QCBORDecode_GetError(dec))
            {
                BSL_LOG_ERR("Invalid raw for ID %" PRIu64, item_id);
                return BSL_ERR_DECODING;
            }

            const size_t value_end = QCBORDecode_Tell(dec);
            BSL_LOG_DEBUG("ASB: Parsed pair[%" PRIu64 "] at %zu as raw QCBOR type %u, size %zu bytes", item_id,
                          value_begin, asbitem.uDataType, value_end - value_begin);

            const UsefulBufC raw_buf = QCBORDecode_RetrieveUndecodedInput(dec);

            BSL_IdValPair_SetRaw(pair, item_id, UsefulBuf_OffsetToPointer(raw_buf, value_begin),
                                 value_end - value_begin);
            break;
        }
    }
    const size_t value_end = QCBORDecode_Tell(dec);

    QCBORDecode_ExitArray(dec);
    if (QCBOR_SUCCESS != QCBORDecode_GetError(dec))
    {
        BSL_LOG_ERR("Failed processing a security parameter");
        return BSL_ERR_DECODING;
    }
    BSL_LOG_DEBUG("pair %" PRIu64 " between %zu and %zu", item_id, value_begin, value_end);

    return BSL_SUCCESS;
}

int BSL_AbsSecBlock_Decode(QCBORDecodeContext *dec, BSL_AbsSecBlock_t *self)
{
    ASSERT_ARG_NONNULL(dec);
    ASSERT_ARG_NONNULL(self);
    QCBORItem asbitem;

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

        int res = BSL_HostEID_DecodeFromCBOR(&eid_cbor_data, &self->source_eid);
        BSL_Data_Deinit(&eid_cbor_data);
        if (res != BSL_SUCCESS)
        {
            BSL_LOG_ERR("BSL HOST EID DECODE FAIL");
            return BSL_ERR_DECODING;
        }
    }

    // A zero value for flags means there are NO paramers, a value of 1 indicates there are parameters to parse.
    if (flags & 0x01)
    {
        // variable length array of parameters
        BSL_LOG_DEBUG("Parsing parameter array");
        QCBORDecode_EnterArray(dec, NULL);
        while (QCBOR_SUCCESS == QCBORDecode_PeekNext(dec, &asbitem))
        {
            BSL_IdValPair_t *param = BSLB_IdValPairPtr_ref(*BSLB_IdValPairPtrList_push_new(self->params));
            if (BSL_SUCCESS != BSL_IdValPair_Decode(dec, param))
            {
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
            BSL_IdValPair_t *param = BSLB_IdValPairPtr_ref(*BSLB_IdValPairPtrList_push_new(tgt->results));
            if (BSL_SUCCESS != BSL_IdValPair_Decode(dec, param))
            {
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
