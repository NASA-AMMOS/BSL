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
 * @ingroup backend_dyn
 * @brief Definition of an (id, value) pair container.
 */
#include "IdValPair.h"

size_t BSL_IdValPair_Sizeof(void)
{
    return sizeof(BSL_IdValPair_t);
}

void BSL_IdValPair_Init(BSL_IdValPair_t *self)
{
    ASSERT_ARG_NONNULL(self);
    memset(self, 0, sizeof(*self));
    self->_type = BSL_IDVALPAIR_TYPE_UNKNOWN;
}

void BSL_IdValPair_InitSet(BSL_IdValPair_t *self, const BSL_IdValPair_t *src)
{
    if (self == src)
    {
        return;
    }
    BSL_IdValPair_Init(self);
    BSL_IdValPair_Set(self, src);
}

void BSL_IdValPair_Deinit(BSL_IdValPair_t *self)
{
    ASSERT_ARG_NONNULL(self);
    switch (self->_type)
    {
        case BSL_IDVALPAIR_TYPE_UNKNOWN:
        case BSL_IDVALPAIR_TYPE_INT64:
            break;
        case BSL_IDVALPAIR_TYPE_BYTESTR:
        case BSL_IDVALPAIR_TYPE_TEXTSTR:
        case BSL_IDVALPAIR_TYPE_RAW:
            m_bstring_clear(self->_val.as_bytes);
            break;
        default:
            break;
    }
    self->_type = BSL_IDVALPAIR_TYPE_UNKNOWN;
}

void BSL_IdValPair_Set(BSL_IdValPair_t *self, const BSL_IdValPair_t *src)
{
    ASSERT_ARG_NONNULL(self);
    ASSERT_ARG_NONNULL(src);

    if (self == src)
    {
        return;
    }
    BSL_IdValPair_Deinit(self);

    self->id    = src->id;
    self->_type = src->_type;
    switch (self->_type)
    {
        case BSL_IDVALPAIR_TYPE_UNKNOWN:
            break;
        case BSL_IDVALPAIR_TYPE_INT64:
            self->_val.as_int = src->_val.as_int;
            break;
        case BSL_IDVALPAIR_TYPE_BYTESTR:
        case BSL_IDVALPAIR_TYPE_TEXTSTR:
        case BSL_IDVALPAIR_TYPE_RAW:
            // workaround m_bstring issue https://github.com/P-p-H-d/mlib/issues/142
            if (m_bstring_empty_p(src->_val.as_bytes))
            {
                m_bstring_init(self->_val.as_bytes);
            }
            else
            {
                m_bstring_init_set(self->_val.as_bytes, src->_val.as_bytes);
            }
            break;
        default:
            break;
    }
}

void BSL_IdValPair_Move(BSL_IdValPair_t *self, BSL_IdValPair_t *src)
{
    ASSERT_ARG_NONNULL(self);
    ASSERT_ARG_NONNULL(src);

    if (self == src)
    {
        return;
    }
    BSL_IdValPair_Deinit(self);

    self->id    = src->id;
    self->_type = src->_type;
    switch (self->_type)
    {
        case BSL_IDVALPAIR_TYPE_UNKNOWN:
            break;
        case BSL_IDVALPAIR_TYPE_INT64:
            self->_val.as_int = src->_val.as_int;
            break;
        case BSL_IDVALPAIR_TYPE_BYTESTR:
        case BSL_IDVALPAIR_TYPE_TEXTSTR:
        case BSL_IDVALPAIR_TYPE_RAW:
            m_bstring_init_move(self->_val.as_bytes, src->_val.as_bytes);
            break;
        default:
            break;
    }

    src->id    = 0;
    src->_type = BSL_IDVALPAIR_TYPE_UNKNOWN;
}

void BSL_IdValPair_SetTextstr(BSL_IdValPair_t *self, int64_t param_id, const char *value)
{
    ASSERT_ARG_NONNULL(self);
    BSL_IdValPair_Deinit(self);

    self->id    = param_id;
    self->_type = BSL_IDVALPAIR_TYPE_TEXTSTR;
    m_bstring_init(self->_val.as_bytes);

    // include terminating null
    if (value)
    {
        const size_t value_strlen = strlen(value);
        m_bstring_push_back_bytes(self->_val.as_bytes, value_strlen + 1, value);
    }
    else
    {
        m_bstring_push_back(self->_val.as_bytes, '\0');
    }
}

bool BSL_IdValPair_IsTextstr(const BSL_IdValPair_t *self)
{
    CHK_AS_BOOL(self);
    return (self->_type == BSL_IDVALPAIR_TYPE_TEXTSTR);
}

void BSL_IdValPair_SetBytestr(BSL_IdValPair_t *self, int64_t param_id, BSL_Data_t value)
{
    ASSERT_ARG_NONNULL(self);
    BSL_IdValPair_Deinit(self);

    self->id    = param_id;
    self->_type = BSL_IDVALPAIR_TYPE_BYTESTR;
    m_bstring_init(self->_val.as_bytes);
    if (value.len)
    {
        m_bstring_push_back_bytes(self->_val.as_bytes, value.len, value.ptr);
    }
}

void BSL_IdValPair_SetInt64(BSL_IdValPair_t *self, int64_t param_id, uint64_t value)
{
    ASSERT_ARG_NONNULL(self);
    BSL_IdValPair_Deinit(self);

    self->id          = param_id;
    self->_type       = BSL_IDVALPAIR_TYPE_INT64;
    self->_val.as_int = value;
}

bool BSL_IdValPair_IsInt64(const BSL_IdValPair_t *self)
{
    CHK_AS_BOOL(self);
    return (self->_type == BSL_IDVALPAIR_TYPE_INT64);
}

int BSL_IdValPair_GetAsInt64(const BSL_IdValPair_t *self, int64_t *out)
{
    CHK_PRECONDITION(BSL_IdValPair_IsConsistent(self));
    BSL_CHKRET(self->_type == BSL_IDVALPAIR_TYPE_INT64, BSL_ERR_NOT_FOUND);

    if (out)
    {
        *out = self->_val.as_int;
    }
    return BSL_SUCCESS;
}

bool BSL_IdValPair_IsBytestr(const BSL_IdValPair_t *self)
{
    CHK_AS_BOOL(self);
    return (self->_type == BSL_IDVALPAIR_TYPE_BYTESTR);
}

int BSL_IdValPair_GetAsBytestr(const BSL_IdValPair_t *self, BSL_Data_t *out)
{
    CHK_PRECONDITION(BSL_IdValPair_IsConsistent(self));
    BSL_CHKRET(self->_type == BSL_IDVALPAIR_TYPE_BYTESTR, BSL_ERR_NOT_FOUND);

    if (out)
    {
        const size_t   size = m_bstring_size(self->_val.as_bytes);
        const uint8_t *ptr  = m_bstring_view(self->_val.as_bytes, 0, size);
        BSL_Data_InitView(out, size, (BSL_DataPtr_t)ptr);
    }
    return BSL_SUCCESS;
}

int BSL_IdValPair_GetAsTextstr(const BSL_IdValPair_t *self, const char **out)
{
    CHK_PRECONDITION(BSL_IdValPair_IsConsistent(self));
    BSL_CHKRET(self->_type == BSL_IDVALPAIR_TYPE_TEXTSTR, BSL_ERR_NOT_FOUND);

    if (out)
    {
        const size_t   size = m_bstring_size(self->_val.as_bytes);
        const uint8_t *ptr  = m_bstring_view(self->_val.as_bytes, 0, size);

        *out = (const char *)ptr;
    }
    return BSL_SUCCESS;
}

void BSL_IdValPair_SetRaw(BSL_IdValPair_t *self, int64_t param_id, const void *ptr, size_t len)
{
    ASSERT_ARG_NONNULL(self);
    ASSERT_ARG_NONNULL(ptr);
    BSL_IdValPair_Deinit(self);

    self->id    = param_id;
    self->_type = BSL_IDVALPAIR_TYPE_RAW;
    m_bstring_init(self->_val.as_bytes);
    if (len)
    {
        m_bstring_push_back_bytes(self->_val.as_bytes, len, ptr);
    }
}

bool BSL_IdValPair_IsRaw(const BSL_IdValPair_t *self)
{
    CHK_AS_BOOL(self);
    return (self->_type == BSL_IDVALPAIR_TYPE_RAW);
}

int BSL_IdValPair_GetAsRaw(const BSL_IdValPair_t *self, BSL_Data_t *out)
{
    CHK_PRECONDITION(BSL_IdValPair_IsConsistent(self));
    BSL_CHKRET(self->_type == BSL_IDVALPAIR_TYPE_RAW, BSL_ERR_NOT_FOUND);

    if (out)
    {
        const size_t   size = m_bstring_size(self->_val.as_bytes);
        const uint8_t *ptr  = m_bstring_view(self->_val.as_bytes, 0, size);
        BSL_Data_InitView(out, size, (BSL_DataPtr_t)ptr);
    }
    return BSL_SUCCESS;
}

uint64_t BSL_IdValPair_GetId(const BSL_IdValPair_t *self)
{
    ASSERT_PRECONDITION(BSL_IdValPair_IsConsistent(self));

    return self->id;
}

bool BSL_IdValPair_IsConsistent(const BSL_IdValPair_t *self)
{
    CHK_AS_BOOL(self != NULL);
    CHK_AS_BOOL((self->_type > BSL_IDVALPAIR_TYPE_UNKNOWN) && (self->_type <= BSL_IDVALPAIR_TYPE_RAW));

    return true;
}

int BSL_IdValPair_Decode(QCBORDecodeContext *dec, BSL_IdValPair_t *pair)
{
    ASSERT_ARG_NONNULL(dec);
    ASSERT_ARG_NONNULL(pair);

    int64_t item_id = 0;
    QCBORDecode_GetInt64(dec, &item_id);
    int res = QCBORDecode_GetError(dec);
    if (QCBOR_SUCCESS != res)
    {
        BSL_LOG_ERR("Failed getting an int ID: code %d", res);
        return BSL_ERR_DECODING;
    }

    const size_t value_begin = QCBORDecode_Tell(dec);

    QCBORItem valitem;
    QCBORDecode_PeekNext(dec, &valitem);
    switch (valitem.uDataType)
    {
        // Collapse both encoded types, with restriction to INT64_MAX
        case QCBOR_TYPE_INT64:
        case QCBOR_TYPE_UINT64:
        {
            int64_t dec_value = 0;
            QCBORDecode_GetInt64(dec, &dec_value);
            if (QCBOR_SUCCESS != QCBORDecode_GetError(dec))
            {
                BSL_LOG_ERR("Invalid integer value for ID %" PRId64, item_id);
                return BSL_ERR_DECODING;
            }
            BSL_LOG_DEBUG("ASB: Parsed pair[%" PRId64 "] at %zu as int %" PRId64, item_id, value_begin, dec_value);

            BSL_IdValPair_SetInt64(pair, item_id, dec_value);
            break;
        }
        case QCBOR_TYPE_BYTE_STRING:
        {
            UsefulBufC target_buf = NULLUsefulBufC;
            QCBORDecode_GetByteString(dec, &target_buf);
            if (QCBOR_SUCCESS != QCBORDecode_GetError(dec))
            {
                BSL_LOG_ERR("Invalid bytestring value for ID %" PRId64, item_id);
                return BSL_ERR_DECODING;
            }
            BSL_LOG_DEBUG("ASB: Parsed pair[%" PRId64 "] at %zu as bytestr with %zu bytes", item_id, value_begin,
                          target_buf.len);
            BSL_Data_t data_view;
            BSL_Data_InitView(&data_view, target_buf.len, (BSL_DataPtr_t)target_buf.ptr);

            BSL_IdValPair_SetBytestr(pair, item_id, data_view);
            break;
        }
        default:
        {
            // skip over entire item (recursively) if possible
            QCBORDecode_VGetNextConsume(dec, &valitem);
            if (QCBOR_SUCCESS != QCBORDecode_GetError(dec))
            {
                BSL_LOG_ERR("Invalid raw for ID %" PRId64, item_id);
                return BSL_ERR_DECODING;
            }

            const size_t value_end = QCBORDecode_Tell(dec);
            BSL_LOG_DEBUG("ASB: Parsed pair[%" PRId64 "] at %zu as raw QCBOR type %u, size %zu bytes", item_id,
                          value_begin, valitem.uDataType, value_end - value_begin);

            const UsefulBufC raw_buf = QCBORDecode_RetrieveUndecodedInput(dec);

            BSL_IdValPair_SetRaw(pair, item_id, UsefulBuf_OffsetToPointer(raw_buf, value_begin),
                                 value_end - value_begin);
            break;
        }
    }
    const size_t value_end = QCBORDecode_Tell(dec);

    if (QCBOR_SUCCESS != QCBORDecode_GetError(dec))
    {
        BSL_LOG_ERR("Failed decoding a value");
        return BSL_ERR_DECODING;
    }
    BSL_LOG_DEBUG("pair %" PRId64 " between %zu and %zu", item_id, value_begin, value_end);

    return BSL_SUCCESS;
}

void BSL_IdValPair_Encode(QCBOREncodeContext *enc, const BSL_IdValPair_t *pair)
{
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
    else if (BSL_IdValPair_IsRaw(pair))
    {
        BSL_Data_t enc_data;
        BSL_IdValPair_GetAsRaw(pair, &enc_data);
        QCBOREncode_AddEncoded(enc, UsefulBufC_FROM_BSL_Data(enc_data));
    }
    else
    {
        BSL_LOG_CRIT("Unhandled parameter type for ID %" PRId64, pair->id);
        QCBOREncode_AddUndef(enc);
    }
}
