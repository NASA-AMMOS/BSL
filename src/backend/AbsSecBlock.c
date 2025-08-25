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
/** @file AbsSecBlock.c
 * @brief Concrete implementation of the Abstract Security Block defined in RFC 9172.
 * @ingroup backend_dyn
 */
#include <qcbor/qcbor_encode.h>
#include <qcbor/qcbor_spiffy_decode.h>

#include <BPSecLib_Private.h>

#include "AbsSecBlock.h"

size_t BSL_AbsSecBlock_Sizeof(void)
{
    return sizeof(BSL_AbsSecBlock_t);
}

bool BSL_AbsSecBlock_IsConsistent(const BSL_AbsSecBlock_t *self)
{
    // NOLINTBEGIN
    CHK_AS_BOOL(self != NULL);
    // CHK_AS_BOOL(self->sec_context_id > 0);
    CHK_AS_BOOL(self->source_eid.handle != NULL);
    CHK_AS_BOOL(BSLB_SecParamList_size(self->params) < 10000);

    // Invariant: Must have at least one result
    CHK_AS_BOOL(BSLB_SecResultList_size(self->results) < 10000);

    // Invariant: Must have at least one target
    CHK_AS_BOOL(uint64_list_size(self->targets) < 10000);
    // NOLINTEND
    return true;
}

void BSL_AbsSecBlock_Print(const BSL_AbsSecBlock_t *self)
{
    BSL_LOG_INFO("ASB  context id: %" PRId64, self->sec_context_id);
    for (size_t index = 0; index < uint64_list_size(self->targets); index++)
    {
        BSL_LOG_INFO("ASB  target[%zu]: %" PRIu64, index, *uint64_list_cget(self->targets, index));
    }

    for (size_t index = 0; index < BSLB_SecParamList_size(self->params); index++)
    {
        BSL_SecParam_t *param = BSLB_SecParamList_get(self->params, index);
        BSL_LOG_INFO("ASB  Param[%zu]:  id=%" PRIu64 " val=%" PRIu64, index, param->param_id, param->_uint_value);
    }

    for (size_t index = 0; index < BSLB_SecResultList_size(self->results); index++)
    {
        BSL_SecResult_t *sec_result = BSLB_SecResultList_get(self->results, index);

        char hex_str[2*sec_result->_bytelen+1];
        BSL_Log_DumpAsHexString((uint8_t *)hex_str, sizeof(hex_str), sec_result->_bytes, sec_result->_bytelen);
        BSL_LOG_INFO("ASB  Result[%zu]: tgt=%" PRIu64 ", id=%" PRIu64 " %s", index, sec_result->target_block_num,
                     sec_result->result_id, hex_str);
    }
}

void BSL_AbsSecBlock_InitEmpty(BSL_AbsSecBlock_t *self)
{
    ASSERT_ARG_NONNULL(self);

    memset(self, 0, sizeof(*self));
    BSLB_SecParamList_init(self->params);
    BSLB_SecResultList_init(self->results);
    uint64_list_init(self->targets);
}

void BSL_AbsSecBlock_Init(BSL_AbsSecBlock_t *self, int64_t sec_context_id, BSL_HostEID_t source_eid)
{
    ASSERT_ARG_NONNULL(self);
    memset(self, 0, sizeof(*self));
    self->sec_context_id = sec_context_id;
    self->source_eid     = source_eid;
    BSLB_SecParamList_init(self->params);
    BSLB_SecResultList_init(self->results);
    uint64_list_init(self->targets);
    ASSERT_POSTCONDITION(BSL_AbsSecBlock_IsConsistent(self));
}

void BSL_AbsSecBlock_Deinit(BSL_AbsSecBlock_t *self)
{
    ASSERT_PRECONDITION(BSL_AbsSecBlock_IsConsistent(self));

    BSLB_SecParamList_clear(self->params);
    BSLB_SecResultList_clear(self->results);
    uint64_list_clear(self->targets);
    BSL_HostEID_Deinit(&self->source_eid);
    memset(self, 0, sizeof(*self));
}

bool BSL_AbsSecBlock_IsEmpty(const BSL_AbsSecBlock_t *self)
{
    ASSERT_ARG_NONNULL(self);
    bool is_empty = (uint64_list_size(self->targets) == 0) && (BSLB_SecResultList_size(self->results) == 0);
    return is_empty;
}

bool BSL_AbsSecBlock_ContainsTarget(const BSL_AbsSecBlock_t *self, uint64_t target_block_num)
{
    ASSERT_PRECONDITION(BSL_AbsSecBlock_IsConsistent(self));
    for
        M_EACH(target_num, self->targets, M_ARRAY_OPLIST(uint64_list))
        {
            if (*target_num == target_block_num)
            {
                return true;
            }
        }
    return false;
}

void BSL_AbsSecBlock_AddTarget(BSL_AbsSecBlock_t *self, uint64_t target_block_id)
{
    ASSERT_PRECONDITION(BSL_AbsSecBlock_IsConsistent(self));

    uint64_list_push_back(self->targets, target_block_id);

    ASSERT_POSTCONDITION(BSL_AbsSecBlock_IsConsistent(self));
}

void BSL_AbsSecBlock_AddParam(BSL_AbsSecBlock_t *self, const BSL_SecParam_t *param)
{
    ASSERT_ARG_NONNULL(param);
    ASSERT_PRECONDITION(BSL_AbsSecBlock_IsConsistent(self));

    BSLB_SecParamList_push_back(self->params, *param);

    ASSERT_POSTCONDITION(BSL_AbsSecBlock_IsConsistent(self));
}

void BSL_AbsSecBlock_AddResult(BSL_AbsSecBlock_t *self, const BSL_SecResult_t *result)
{
    ASSERT_ARG_NONNULL(result);
    ASSERT_PRECONDITION(BSL_AbsSecBlock_IsConsistent(self));

    BSLB_SecResultList_push_back(self->results, *result);

    ASSERT_POSTCONDITION(BSL_AbsSecBlock_IsConsistent(self));
}

static size_t BSL_AbsSecBlock_GetResultCnt(const BSL_AbsSecBlock_t *self, uint64_t target_block_id)
{
    ASSERT_PRECONDITION(BSL_AbsSecBlock_IsConsistent(self));

    size_t match_count = 0;
    for (size_t index = 0; index < BSLB_SecResultList_size(self->results); index++)
    {
        BSL_SecResult_t *result = BSLB_SecResultList_get(self->results, index);
        if (result->target_block_num == target_block_id)
        {
            match_count++;
        }
    }
    return match_count;
}

int BSL_AbsSecBlock_StripResults(BSL_AbsSecBlock_t *self, uint64_t target_block_num)
{
    CHK_PRECONDITION(BSL_AbsSecBlock_IsConsistent(self));

    size_t things_removed = 0;

    // Remove target uint64 from target list
    // TODO - The m-list is not ideal. We should just use an array.
    uint64_list_it_t target_iter;
    uint64_list_it(target_iter, self->targets);
    for (size_t i = 0; i < uint64_list_size(self->targets); i++)
    {
        uint64_t *curr_target = uint64_list_ref(target_iter);
        if (*curr_target == target_block_num)
        {
            break;
        }
        uint64_list_next(target_iter);
    }
    ASSERT_PROPERTY(!uint64_list_end_p(target_iter));

    uint64_list_remove(self->targets, target_iter);
    things_removed++;

    while (BSL_AbsSecBlock_GetResultCnt(self, target_block_num) > 0)
    {
        BSLB_SecResultList_it_t result_iter;
        BSLB_SecResultList_it(result_iter, self->results);
        size_t index = 0;
        for (index = 0; index < BSLB_SecResultList_size(self->results); index++)
        {
            BSL_SecResult_t *sec_result = BSLB_SecResultList_ref(result_iter);
            if (sec_result->target_block_num == target_block_num)
            {
                break;
            }
            BSLB_SecResultList_next(result_iter);
        }

        if (!BSLB_SecResultList_end_p(result_iter) && index < BSLB_SecResultList_size(self->results))
        {
            BSLB_SecResultList_remove(self->results, result_iter);
            things_removed++;
        }
        else
        {
            // It should have always found one.
            BSL_LOG_ERR("Expected to have result to remove");
            return BSL_ERR_PROPERTY_CHECK_FAILED;
        }
    }

    CHK_POSTCONDITION(BSL_AbsSecBlock_IsConsistent(self));
    return (int)things_removed;
}

ssize_t BSL_AbsSecBlock_EncodeToCBOR(const BSL_AbsSecBlock_t *self, BSL_Data_t *buf)
{
    CHK_PRECONDITION(BSL_AbsSecBlock_IsConsistent(self));

    QCBOREncodeContext encoder;

    UsefulBuf qcbor_buf = buf->ptr ? (UsefulBuf) { .ptr = buf->ptr, .len = buf->len } : SizeCalculateUsefulBuf;
    QCBOREncode_Init(&encoder, qcbor_buf);

    {
        QCBOREncode_OpenArray(&encoder);
        uint64_list_it_t it;
        for (uint64_list_it(it, self->targets); !uint64_list_end_p(it); uint64_list_next(it))
        {
            QCBOREncode_AddUInt64(&encoder, *uint64_list_cref(it));
        }
        QCBOREncode_CloseArray(&encoder);
    }

    {
        QCBOREncode_AddInt64(&encoder, self->sec_context_id);
    }

    {
        // TODO - Maybe this should be generated on-the-fly
        uint64_t flags = 0;
        if (BSLB_SecParamList_size(self->params) > 0)
        {
            flags |= 0x1;
        }
        QCBOREncode_AddUInt64(&encoder, flags);
    }

    BSL_HostEID_EncodeToCBOR(&self->source_eid, (void *)&encoder);

    {
        QCBOREncode_OpenArray(&encoder);

        for (size_t param_index = 0; param_index < BSLB_SecParamList_size(self->params); param_index++)
        {
            const BSL_SecParam_t *param = BSLB_SecParamList_cget(self->params, param_index);
            QCBOREncode_OpenArray(&encoder);
            QCBOREncode_AddUInt64(&encoder, param->param_id);
            if (BSL_SecParam_IsInt64(param))
            {
                QCBOREncode_AddUInt64(&encoder, BSL_SecParam_GetAsUInt64(param));
            }
            else
            {
                BSL_Data_t bytestr;
                BSL_SecParam_GetAsBytestr(param, &bytestr);
                UsefulBufC bytestr_buf = { .ptr = bytestr.ptr, .len = bytestr.len };
                QCBOREncode_AddBytes(&encoder, bytestr_buf);
            }
            QCBOREncode_CloseArray(&encoder);
        }
        QCBOREncode_CloseArray(&encoder);
    }

    {
        // Encode results for each target.
        QCBOREncode_OpenArray(&encoder);
        for (size_t target_index = 0; target_index < uint64_list_size(self->targets); target_index++)
        {
            QCBOREncode_OpenArray(&encoder);
            const uint64_t *target_block_num = uint64_list_cget(self->targets, target_index);
            for (size_t result_index = 0; result_index < BSLB_SecResultList_size(self->results); result_index++)
            {
                const BSL_SecResult_t *sec_result = BSLB_SecResultList_cget(self->results, result_index);
                if (sec_result->target_block_num != *target_block_num)
                {
                    continue;
                }
                QCBOREncode_OpenArray(&encoder);
                QCBOREncode_AddUInt64(&encoder, sec_result->result_id);
                UsefulBufC result_buf = { .ptr = sec_result->_bytes, .len = sec_result->_bytelen };
                QCBOREncode_AddBytes(&encoder, result_buf);
                QCBOREncode_CloseArray(&encoder);
            }
            QCBOREncode_CloseArray(&encoder);
        }

        QCBOREncode_CloseArray(&encoder);
    }

    size_t     encode_sz;
    QCBORError qcbor_err = QCBOREncode_FinishGetSize(&encoder, &encode_sz);
    BSL_LOG_INFO("QCBOR ENCODE SIZE: %zu", encode_sz);
    if (qcbor_err != QCBOR_SUCCESS)
    {
        BSL_LOG_ERR("Encoding ASB into BTSD failed: %s", qcbor_err_to_str(qcbor_err));
        return BSL_ERR_ENCODING;
    }
    return (ssize_t)encode_sz;
}

int BSL_AbsSecBlock_DecodeFromCBOR(BSL_AbsSecBlock_t *self, const BSL_Data_t *buf)
{
    CHK_ARG_NONNULL(self);
    CHK_ARG_EXPR(buf->len > 0);
    CHK_ARG_EXPR(buf->ptr != NULL);

    BSL_AbsSecBlock_InitEmpty(self);

    QCBORDecodeContext asbdec;

    UsefulBufC qcbor_buf = { .ptr = buf->ptr, .len = buf->len };
    QCBORDecode_Init(&asbdec, qcbor_buf, QCBOR_DECODE_MODE_NORMAL);
    QCBORItem asbitem;

    QCBORDecode_EnterArray(&asbdec, NULL);

    // Make sure actually entered an array - otherwise, the following while loop could be infinite
    QCBORError tgt_array_err = QCBORDecode_GetError(&asbdec);
    if (QCBOR_SUCCESS != tgt_array_err)
    {
        BSL_LOG_ERR("ASB decoding: Failed to enter target array ; error %d (%s)", tgt_array_err,
                    qcbor_err_to_str(tgt_array_err));
        return BSL_ERR_DECODING;
    }

    while (QCBOR_SUCCESS == QCBORDecode_PeekNext(&asbdec, &asbitem))
    {
        uint64_t tgt_num = 0;
        QCBORDecode_GetUInt64(&asbdec, &tgt_num);
        if (QCBOR_SUCCESS != QCBORDecode_GetError(&asbdec))
        {
            BSL_LOG_ERR("Failed processing a security target");
            return BSL_ERR_DECODING;
        }

        BSL_LOG_DEBUG("got tgt %" PRIu64, tgt_num);
        uint64_list_push_back(self->targets, tgt_num);
    }
    QCBORDecode_ExitArray(&asbdec);
    const size_t targets_size = uint64_list_size(self->targets);

    {
        int64_t ctx_id = 0;
        QCBORDecode_GetInt64(&asbdec, &ctx_id);
        if ((ctx_id < INT16_MIN) || (ctx_id > INT16_MAX))
        {
            BSL_LOG_ERR("Invalid context id: %" PRId64, ctx_id);
        }
        else
        {
            self->sec_context_id = ctx_id;
        }
        BSL_LOG_DEBUG("got ctx_id %" PRId64, ctx_id);
    }

    uint64_t flags = 0;
    QCBORDecode_GetUInt64(&asbdec, &flags);
    BSL_LOG_DEBUG("got flags %" PRId64, flags);

    // Host-specific parsing of EID
    BSL_HostEID_Init(&self->source_eid);
    BSL_HostEID_DecodeFromCBOR(&self->source_eid, &asbdec);

    // A zero value for flags means there are NO paramers, a value of 1 indicates there are parameters to parse.
    if (flags & 0x01)
    {
        // variable length array of parameters
        QCBORDecode_EnterArray(&asbdec, NULL);
        while (QCBOR_SUCCESS == QCBORDecode_PeekNext(&asbdec, &asbitem))
        {
            // each parameter is a 2-item array
            QCBORDecode_EnterArray(&asbdec, NULL);

            uint64_t item_id = 0;
            QCBORDecode_GetUInt64(&asbdec, &item_id);
            if (QCBOR_SUCCESS != QCBORDecode_GetError(&asbdec))
            {
                BSL_LOG_ERR("Failed getting a parameter type ID");
                return BSL_ERR_DECODING;
            }

            const size_t item_begin = QCBORDecode_Tell(&asbdec);
            QCBORDecode_PeekNext(&asbdec, &asbitem);
            if (asbitem.uDataType == QCBOR_TYPE_INT64)
            {
                uint64_t param_u64_value = 0;
                QCBORDecode_GetUInt64(&asbdec, &param_u64_value);
                BSL_LOG_DEBUG("ASB: Parsed Param[%" PRIu64 "] = %" PRIu64, item_id, param_u64_value);
                BSL_SecParam_t param;
                BSL_SecParam_InitInt64(&param, item_id, param_u64_value);
                BSLB_SecParamList_push_back(self->params, param);
            }
            else if (asbitem.uDataType == QCBOR_TYPE_BYTE_STRING)
            {
                UsefulBufC target_buf;
                QCBORDecode_GetByteString(&asbdec, &target_buf);
                BSL_LOG_DEBUG("ASB: Parsed Param[%" PRIu64 "] (ByteStr) = %zu bytes at %p", item_id, target_buf.len,
                              target_buf.ptr);
                BSL_Data_t data_view;
                BSL_Data_InitView(&data_view, target_buf.len, (BSL_DataPtr_t)target_buf.ptr);
                BSL_SecParam_t param;
                BSL_SecParam_InitBytestr(&param, item_id, data_view);
                BSLB_SecParamList_push_back(self->params, param);
            }
            else
            {
                BSL_LOG_ERR("ASB ignoring non-bytestring item with QCBOR type %u", asbitem.uDataType);
                // skip over entire item (recursively)
                QCBORDecode_VGetNextConsume(&asbdec, &asbitem);
                // NOLINTNEXTLINE
                return BSL_ERR_DECODING;
            }
            const size_t item_end = QCBORDecode_Tell(&asbdec);

            QCBORDecode_ExitArray(&asbdec);
            if (QCBOR_SUCCESS != QCBORDecode_GetError(&asbdec))
            {
                BSL_LOG_ERR("Failed processing a security parameter");
                return BSL_ERR_DECODING;
            }
            BSL_LOG_DEBUG("param %" PRIu64 " between %zu and %zu", item_id, item_begin, item_end);
        }
        QCBORDecode_ExitArray(&asbdec);
    }

    QCBORDecode_EnterArray(&asbdec, NULL);
    size_t target_index = 0;
    while (QCBOR_SUCCESS == QCBORDecode_PeekNext(&asbdec, &asbitem))
    {
        if (target_index >= targets_size)
        {
            BSL_LOG_ERR("ASB result array has too many items, expected %zu got %zu", targets_size, target_index);
            return BSL_ERR_DECODING;
        }
        // Each set of results correlates to the same ordinal number of the target list
        uint64_t target_id = *uint64_list_cget(self->targets, target_index);
        BSL_LOG_DEBUG("Parsing ASB results for target[index=%zu, block#=%zu]", target_index, target_id);
        target_index++;

        // variable length array of result pairs
        QCBORDecode_EnterArray(&asbdec, NULL);
        while (QCBOR_SUCCESS == QCBORDecode_PeekNext(&asbdec, &asbitem))
        {
            // each parameter is a 2-item array
            QCBORDecode_EnterArray(&asbdec, NULL);

            uint64_t item_id = 0;
            QCBORDecode_GetUInt64(&asbdec, &item_id);
            if (QCBOR_SUCCESS != QCBORDecode_GetError(&asbdec))
            {
                BSL_LOG_ERR("Failed getting a result type ID");
                return BSL_ERR_DECODING;
            }

            const size_t item_begin = QCBORDecode_Tell(&asbdec);

            QCBORError is_ok = QCBORDecode_PeekNext(&asbdec, &asbitem);
            CHK_PROPERTY(is_ok == QCBOR_SUCCESS);

            if (asbitem.uDataType == QCBOR_TYPE_BYTE_STRING)
            {
                UsefulBufC bstr_qcbor_buf;
                QCBORDecode_GetByteString(&asbdec, &bstr_qcbor_buf);
                BSL_Data_t bstr_buf;
                BSL_Data_InitView(&bstr_buf, bstr_qcbor_buf.len, (BSL_DataPtr_t)bstr_qcbor_buf.ptr);

                BSL_SecResult_t result;
                int result_code = BSL_SecResult_Init(&result, item_id, self->sec_context_id, target_id, &bstr_buf);
                ASSERT_PROPERTY(result_code == 0);
                BSL_LOG_DEBUG("ASB: Parsed Result (target_block=%" PRIu64 ", len=%zu)", result.target_block_num,
                              result._bytelen);
                BSLB_SecResultList_push_back(self->results, result);
            }
            else
            {
                BSL_LOG_ERR("ASB ignoring non-bytestring item with QCBOR type %u", asbitem.uDataType);
                // skip over entire item (recursively)
                QCBORDecode_VGetNextConsume(&asbdec, &asbitem);
                // NOLINTNEXTLINE
                return BSL_ERR_DECODING;
            }
            const size_t item_end = QCBORDecode_Tell(&asbdec);

            QCBORDecode_ExitArray(&asbdec);
            if (QCBOR_SUCCESS != QCBORDecode_GetError(&asbdec))
            {
                BSL_LOG_ERR("Failed processing a security result");
                return BSL_ERR_DECODING;
            }
            BSL_LOG_DEBUG("result %" PRIu64 " between %zu and %zu", item_id, item_begin, item_end);
        }
        QCBORDecode_ExitArray(&asbdec);
    }
    QCBORDecode_ExitArray(&asbdec);

    QCBORError err = QCBORDecode_Finish(&asbdec);
    if (err != QCBOR_SUCCESS)
    {
        BSL_LOG_WARNING("ASB decoding error %d (%s)", err, qcbor_err_to_str(err));
        return BSL_ERR_DECODING;
    }

    if (target_index < targets_size)
    {
        BSL_LOG_ERR("ASB result array has too few items, expected %zu got %zu", targets_size, target_index);
        return BSL_ERR_DECODING;
    }

    ASSERT_POSTCONDITION(BSL_AbsSecBlock_IsConsistent(self));
    return BSL_SUCCESS;
}
