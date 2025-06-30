/*
 * Copyright (c) 2024 The Johns Hopkins University Applied Physics
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
 * @ingroup backend_dyn
 * Implementation of the Abstract Security Block defined in RFC 9172.
 */
#include <qcbor/qcbor_encode.h>
#include <qcbor/qcbor_spiffy_decode.h>

#include <AbsSecBlock.h>
#include <BPSecTypes.h>
#include <Logging.h>

bool BSL_AbsSecBlock_IsConsistent(const BSL_AbsSecBlock_t *self)
{
    assert(self != NULL);
    assert(self->sec_context_id > 0);
    assert(self->source_eid.handle != NULL);
    // NOLINTBEGIN
    assert(BSL_SecParamList_size(self->params) < 10000);

    // Invariant: Must have at least one result
    assert(BSL_SecResultList_size(self->results) < 10000);

    // Invariant: Must have at least one target
    assert(uint64_list_size(self->targets) < 10000);
    // NOLINTEND
    return true;
}

void BSL_AbsSecBlock_Print(const BSL_AbsSecBlock_t *self)
{
    uint8_t      str[500];
    const size_t strlen = sizeof(str);
    BSL_LOG_INFO("ASB  context id: %lu", self->sec_context_id);
    size_t index;
    for (index = 0; index < uint64_list_size(self->targets); index++)
    {
        BSL_LOG_INFO("ASB  target[%lu]: %lu", index, *uint64_list_get(self->targets, index));
    }

    for (index = 0; index < BSL_SecParamList_size(self->params); index++)
    {
        BSL_SecParam_t *p = BSL_SecParamList_get(self->params, index);
        BSL_LOG_INFO("ASB  Param[%lu]:  id=%lu val=%lu", index, p->param_id, p->_uint_value);
    }

    for (index = 0; index < BSL_SecResultList_size(self->results); index++)
    {
        BSL_SecResult_t *p = BSL_SecResultList_get(self->results, index);
        BSL_Log_DumpAsHexString(str, strlen, p->_bytes, p->_bytelen);
        BSL_LOG_INFO("ASB  Result[%lu]: tgt=%lu, id=%lu %s", index, p->target_block_num, p->result_id, str);
    }
}

void BSL_AbsSecBlock_InitEmpty(BSL_AbsSecBlock_t *self)
{
    assert(self != NULL);
    memset(self, 0, sizeof(*self));
    BSL_SecParamList_init(self->params);
    BSL_SecResultList_init(self->results);
    uint64_list_init(self->targets);
}

void BSL_AbsSecBlock_Init(BSL_AbsSecBlock_t *self, uint64_t sec_context_id, BSL_HostEID_t source_eid)
{
    assert(self != NULL);
    memset(self, 0, sizeof(*self));
    self->sec_context_id = sec_context_id;
    self->source_eid     = source_eid;
    BSL_SecParamList_init(self->params);
    BSL_SecResultList_init(self->results);
    uint64_list_init(self->targets);
    assert(BSL_AbsSecBlock_IsConsistent(self));
}

void BSL_AbsSecBlock_Deinit(BSL_AbsSecBlock_t *self)
{
    assert(BSL_AbsSecBlock_IsConsistent(self));

    BSL_SecParamList_clear(self->params);
    BSL_SecResultList_clear(self->results);
    uint64_list_clear(self->targets);
    BSL_HostEID_Deinit(&self->source_eid);
    memset(self, 0, sizeof(*self));
}

uint8_t     dbgstr[500];
static bool _ASBContainsResult(const BSL_AbsSecBlock_t *self, const BSL_SecResult_t *actual)
{
    assert(BSL_AbsSecBlock_IsConsistent(self));
    assert(actual != NULL);

    size_t index;
    for (index = 0; index < BSL_SecResultList_size(self->results); index++)
    {
        BSL_SecResult_t *expected = BSL_SecResultList_get(self->results, index);
        assert(expected != NULL);
        bool hdr_matches = (actual->context_id == expected->context_id) && (actual->result_id == expected->result_id)
                           && (actual->target_block_num == expected->target_block_num)
                           && (actual->_bytelen == expected->_bytelen);
        if (hdr_matches)
        {
            int cmp = memcmp(actual->_bytes, expected->_bytes, expected->_bytelen);
            BSL_LOG_DEBUG("Actual Result  : %s",
                          BSL_Log_DumpAsHexString(dbgstr, sizeof(dbgstr), actual->_bytes, actual->_bytelen));
            BSL_LOG_DEBUG("Expected Result: %s",
                          BSL_Log_DumpAsHexString(dbgstr, sizeof(dbgstr), expected->_bytes, expected->_bytelen));
            return cmp == 0;
        }
    }
    return false;
}

bool BSL_AbsSecBlock_IsEmpty(const BSL_AbsSecBlock_t *self)
{
    bool is_empty = (uint64_list_size(self->targets) == 0) && (BSL_SecResultList_size(self->results) == 0);
    return is_empty;
}

bool BSL_AbsSecBlock_ContainsTarget(const BSL_AbsSecBlock_t *self, uint64_t target_block_num)
{
    assert(BSL_AbsSecBlock_IsConsistent(self));
    for M_EACH(target_num, self->targets, LIST_OPLIST(uint64_list))
    {
        if (*target_num == target_block_num)
        {
            return true;
        }
    }
    return false;
}

bool BSL_AbsSecBlock_IsResultEqual(const BSL_AbsSecBlock_t *self, const BSL_SecOutcome_t *outcome)
{
    assert(BSL_AbsSecBlock_IsConsistent(self));
    assert(outcome != NULL);

    size_t found_matches    = 0;
    size_t expected_matches = BSL_SecResultList_size(outcome->result_list);
    assert(expected_matches > 0);

    size_t result_index;
    for (result_index = 0; result_index < expected_matches; result_index++)
    {
        const BSL_SecResult_t *actual_res = BSL_SecResultList_get(outcome->result_list, result_index);
        assert(actual_res != NULL);
        if (_ASBContainsResult(self, actual_res))
        {
            found_matches++;
        }
        else
        {
            BSL_LOG_ERR("Security operation mismatch!!!");
        }
    }
    BSL_LOG_DEBUG("Checking results: %lu expected, %lu found", expected_matches, found_matches);
    return (expected_matches == found_matches) && (found_matches > 0);
}

void BSL_AbsSecBlock_AddTarget(BSL_AbsSecBlock_t *self, uint64_t target_block_id)
{
    assert(BSL_AbsSecBlock_IsConsistent(self));
    
    uint64_list_push_back(self->targets, target_block_id);
    
    assert(BSL_AbsSecBlock_IsConsistent(self));
}

void BSL_AbsSecBlock_AddParam(BSL_AbsSecBlock_t *self, const BSL_SecParam_t *param)
{
    assert(param != NULL);
    assert(BSL_AbsSecBlock_IsConsistent(self));
    
    BSL_SecParamList_push_back(self->params, *param);
    
    assert(BSL_AbsSecBlock_IsConsistent(self));
}

void BSL_AbsSecBlock_AddResult(BSL_AbsSecBlock_t *self, const BSL_SecResult_t *result)
{
    assert(result != NULL);
    assert(BSL_AbsSecBlock_IsConsistent(self));
    
    BSL_SecResultList_push_back(self->results, *result);
    
    assert(BSL_AbsSecBlock_IsConsistent(self));
}


size_t _BSL_AbsSecBlock_GetResultCnt(const BSL_AbsSecBlock_t *self, uint64_t target_block_id)
{
    assert(target_block_id > 0);
    assert(BSL_AbsSecBlock_IsConsistent(self));

    size_t index;
    size_t match_count = 0;
    for (index = 0; index < BSL_SecResultList_size(self->results); index++)
    {
        const BSL_SecResult_t *result = BSL_SecResultList_cget(self->results, index);
        if (result->target_block_num == target_block_id)
        {
            match_count++;
        }
    }
    return match_count;
}

int BSL_AbsSecBlock_StripResults(BSL_AbsSecBlock_t *self, BSL_SecOutcome_t *outcome)
{
    assert(outcome != NULL);
    assert(BSL_AbsSecBlock_IsConsistent(self));

    size_t things_removed = 0;

    // BSL_AbsSecBlock_Print(self);

    // Remove target uint64 from target list
    uint64_list_it_t target_iter;
    uint64_list_it(target_iter, self->targets);
    for (; uint64_list_end_p(target_iter); uint64_list_next(target_iter))
    {
        uint64_t curr_target = *uint64_list_ref(target_iter);
        if (curr_target == outcome->sec_oper->target_block_num)
        {
            break;
        }
    }
    // TODO logging
    // TODO - Also check that there is only one instance of target in the list. (Part of integrity check)
    assert(!uint64_list_end_p(target_iter));
    uint64_list_remove(self->targets, target_iter);
    things_removed++;
    BSL_LOG_INFO("Removing target: %lu", outcome->sec_oper->target_block_num);

    // Remove results for that target.
    while (_BSL_AbsSecBlock_GetResultCnt(self, outcome->sec_oper->target_block_num) > 0)
    {
        BSL_SecResultList_it_t result_iter;
        BSL_SecResultList_it(result_iter, self->results);
        for (; BSL_SecResultList_end_p(result_iter); BSL_SecResultList_next(result_iter))
        {
            const BSL_SecResult_t *curr_result = BSL_SecResultList_cref(result_iter);
            if (curr_result->target_block_num == outcome->sec_oper->target_block_num)
            {
                break;
            }
        }
        if (!BSL_SecResultList_end_p(result_iter))
        {
            BSL_LOG_INFO("Removing result: %lu", outcome->sec_oper->target_block_num);
            BSL_SecResultList_remove(self->results, result_iter);
            things_removed++;
        }
        else
        {
            // It should have always found one.
            assert(0);
        }
    }
    // BSL_AbsSecBlock_Print(self);

    assert(BSL_AbsSecBlock_IsConsistent(self));
    return (int)things_removed;
}

int BSL_AbsSecBlock_EncodeToCBOR(const BSL_AbsSecBlock_t *self, BSL_Data_t allocated_target)
{
    assert(allocated_target.ptr != NULL);
    assert(allocated_target.len > 0);
    assert(BSL_AbsSecBlock_IsConsistent(self));

    QCBOREncodeContext c;
    UsefulBuf          allocated_buf = { .ptr = allocated_target.ptr, .len = allocated_target.len };
    QCBOREncode_Init(&c, allocated_buf);

    {
        QCBOREncode_OpenArray(&c);
        size_t target_index;
        for (target_index = 0; target_index < uint64_list_size(self->targets); target_index++)
        {
            QCBOREncode_AddUInt64(&c, *uint64_list_get(self->targets, target_index));
        }
        QCBOREncode_CloseArray(&c);
    }

    {
        QCBOREncode_AddUInt64(&c, self->sec_context_id);
    }

    {
        // TODO - Maybe this should be generated on-the-fly
        uint64_t flags = BSL_SecParamList_size(self->params) > 0 ? true : false;
        QCBOREncode_AddUInt64(&c, flags);
    }

    BSL_HostEID_EncodeToCBOR(&self->source_eid, (void *)&c);

    {
        QCBOREncode_OpenArray(&c);
        size_t param_index;
        for (param_index = 0; param_index < BSL_SecParamList_size(self->params); param_index++)
        {
            const BSL_SecParam_t *param = BSL_SecParamList_cget(self->params, param_index);
            QCBOREncode_OpenArray(&c);
            QCBOREncode_AddUInt64(&c, param->param_id);
            if (BSL_SecParam_IsInt64(param))
            {
                QCBOREncode_AddUInt64(&c, BSL_SecParam_GetAsUInt64(param));
            }
            else
            {
                BSL_Data_t bytestr;
                BSL_SecParam_GetAsBytestr(param, &bytestr);
                UsefulBufC bytestr_buf = { .ptr = bytestr.ptr, .len = bytestr.len };
                QCBOREncode_AddBytes(&c, bytestr_buf);
            }
            QCBOREncode_CloseArray(&c);
        }
        QCBOREncode_CloseArray(&c);
    }

    {
        // Encode results for each target.
        QCBOREncode_OpenArray(&c);
        size_t target_index;
        for (target_index = 0; target_index < uint64_list_size(self->targets); target_index++)
        {
            QCBOREncode_OpenArray(&c);
            size_t result_index;
            for (result_index = 0; result_index < BSL_SecResultList_size(self->results); result_index++)
            {
                const BSL_SecResult_t *sec_result = BSL_SecResultList_cget(self->results, result_index);
                QCBOREncode_OpenArray(&c);
                QCBOREncode_AddUInt64(&c, sec_result->result_id);
                UsefulBufC result_buf = { .ptr = sec_result->_bytes, .len = sec_result->_bytelen };
                QCBOREncode_AddBytes(&c, result_buf);
                QCBOREncode_CloseArray(&c);
            }
            QCBOREncode_CloseArray(&c);
        }

        QCBOREncode_CloseArray(&c);
    }

    UsefulBufC output_buf;
    QCBORError qcbor_err = QCBOREncode_Finish(&c, &output_buf);
    if (qcbor_err != QCBOR_SUCCESS)
    {
        BSL_LOG_ERR("Encoding ASB into BTSD failed: %s", qcbor_err_to_str(qcbor_err));
        return -99;
    }
    return (int)output_buf.len;
}

int BSL_AbsSecBlock_DecodeFromCBOR(BSL_AbsSecBlock_t *self, BSL_Data_t encoded_cbor)
{
    assert(self != NULL);
    assert(encoded_cbor.len > 0);
    assert(encoded_cbor.ptr != NULL);

    BSL_AbsSecBlock_InitEmpty(self);

    QCBORDecodeContext asbdec;
    UsefulBufC         useful_encoded_cbor = { .ptr = encoded_cbor.ptr, .len = encoded_cbor.len };
    QCBORDecode_Init(&asbdec, useful_encoded_cbor, QCBOR_DECODE_MODE_NORMAL);
    QCBORItem asbitem;

    QCBORDecode_EnterArray(&asbdec, NULL);
    while (QCBOR_SUCCESS == QCBORDecode_PeekNext(&asbdec, &asbitem))
    {
        uint64_t tgt_num;
        QCBORDecode_GetUInt64(&asbdec, &tgt_num);
        BSL_LOG_DEBUG("got tgt %" PRIu64 "", tgt_num);
        uint64_list_push_back(self->targets, tgt_num);
    }
    QCBORDecode_ExitArray(&asbdec);

    {
        int64_t ctx_id = 0;
        QCBORDecode_GetInt64(&asbdec, &ctx_id);
        if ((ctx_id < INT16_MIN) || (ctx_id > INT16_MAX))
        {
            BSL_LOG_WARNING("Invalid context id: %" PRId64, ctx_id);
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
    if (flags != 0)
    {
        // variable length array of parameters
        QCBORDecode_EnterArray(&asbdec, NULL);
        while (QCBOR_SUCCESS == QCBORDecode_PeekNext(&asbdec, &asbitem))
        {
            // each parameter is a 2-item array
            QCBORDecode_EnterArray(&asbdec, NULL);

            uint64_t item_id;
            QCBORDecode_GetUInt64(&asbdec, &item_id);

            const size_t item_begin = QCBORDecode_Tell(&asbdec);
            // QCBORDecode_VGetNextConsume(&asbdec, &asbitem);
            QCBORDecode_PeekNext(&asbdec, &asbitem);
            if (asbitem.uDataType == QCBOR_TYPE_INT64)
            {
                uint64_t param_uint64;
                QCBORDecode_GetUInt64(&asbdec, &param_uint64);
                BSL_LOG_DEBUG("ASB: Parsed Param[%lu] = %lu", item_id, param_uint64);
                BSL_SecParam_t param;
                BSL_SecParam_InitInt64(&param, item_id, param_uint64);
                BSL_SecParamList_push_back(self->params, param);
            }
            else if (asbitem.uDataType == QCBOR_TYPE_BYTE_STRING)
            {
                UsefulBufC target_buf;
                QCBORDecode_GetByteString(&asbdec, &target_buf);
                BSL_LOG_DEBUG("ASB: Parsed Param[%lu] (ByteStr) = %lu bytes", item_id, target_buf.len);
                BSL_SecParam_t param;
                BSL_Data_t     data_view = { .owned = 0, .ptr = (uint8_t *)target_buf.ptr, .len = target_buf.len };
                BSL_SecParam_InitBytestr(&param, item_id, data_view);
            }
            else
            {
                assert(0);
            }

            const size_t item_end = QCBORDecode_Tell(&asbdec);
            BSL_LOG_DEBUG("param %" PRIu64 " between %" PRId64 " and %" PRId64, item_id, item_begin, item_end);

            QCBORDecode_ExitArray(&asbdec);
        }
        QCBORDecode_ExitArray(&asbdec);
    }

    QCBORDecode_EnterArray(&asbdec, NULL);
    size_t result_index = 0;
    while (QCBOR_SUCCESS == QCBORDecode_PeekNext(&asbdec, &asbitem))
    {
        // Now get the target_id at that index
        size_t target_id = 0;
        size_t i;
        for (i = 0; i < uint64_list_size(self->targets); i++)
        {
            if (i == result_index)
            {
                target_id = *uint64_list_get(self->targets, i);
                break;
            }
        }
        result_index++;
        // This indicates an integrity error and mismatch between length of targets and length of results
        assert(target_id != 0);

        BSL_LOG_DEBUG("Parsing ASB results for target[index=%lu, block#=%lu]", result_index, target_id);

        // variable length array of results
        QCBORDecode_EnterArray(&asbdec, NULL);
        while (QCBOR_SUCCESS == QCBORDecode_PeekNext(&asbdec, &asbitem))
        {
            // each parameter is a 2-item array
            QCBORDecode_EnterArray(&asbdec, NULL);

            uint64_t item_id;
            QCBORDecode_GetUInt64(&asbdec, &item_id);

            const size_t item_begin = QCBORDecode_Tell(&asbdec);
            // QCBORDecode_VGetNextConsume(&asbdec, &asbitem);
            QCBORError is_ok = QCBORDecode_PeekNext(&asbdec, &asbitem);
            assert(is_ok == QCBOR_SUCCESS);

            if (asbitem.uDataType == QCBOR_TYPE_BYTE_STRING)
            {
                UsefulBufC buf;
                QCBORDecode_GetByteString(&asbdec, &buf);
                BSL_Data_t      bufdata = { .owned = 0, .ptr = (uint8_t *)buf.ptr, .len = buf.len };
                BSL_SecResult_t result;
                int             r = BSL_SecResult_Init(&result, item_id, self->sec_context_id, target_id, bufdata);
                assert(r == 0);
                BSL_LOG_DEBUG("ASB: Parsed Result (target_block=%lu, len=%lu)", result.target_block_num,
                              result._bytelen);
                BSL_SecResultList_push_back(self->results, result);
            }
            else
            {
                assert(0);
            }
            const size_t item_end = QCBORDecode_Tell(&asbdec);
            BSL_LOG_DEBUG("result %" PRIu64 " between %" PRId64 " and %" PRId64, item_id, item_begin, item_end);

            QCBORDecode_ExitArray(&asbdec);
        }
        QCBORDecode_ExitArray(&asbdec);
    }
    QCBORDecode_ExitArray(&asbdec);

    QCBORError err = QCBORDecode_Finish(&asbdec);
    if (err != QCBOR_SUCCESS)
    {
        BSL_LOG_WARNING("ASB decoding error %" PRIu32 " (%s)", err, qcbor_err_to_str(err));
        return -997;
    }
    
    assert(BSL_AbsSecBlock_IsConsistent(self));
    return 0;
}