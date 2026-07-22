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
 * @brief Definition of a variant-type container.
 */
#include "Variant.h"

size_t BSL_Variant_Sizeof(void)
{
    return sizeof(BSL_Variant_t);
}

void BSL_Variant_Init(BSL_Variant_t *self)
{
    ASSERT_ARG_NONNULL(self);
    memset(self, 0, sizeof(*self));
    self->_type = BSLB_VARIANT_TYPE_UNKNOWN;
}

void BSL_Variant_InitSet(BSL_Variant_t *self, const BSL_Variant_t *src)
{
    if (self == src)
    {
        return;
    }
    BSL_Variant_Init(self);
    BSL_Variant_Set(self, src);
}

void BSL_Variant_Deinit(BSL_Variant_t *self)
{
    ASSERT_ARG_NONNULL(self);
    switch (self->_type)
    {
        case BSLB_VARIANT_TYPE_UNKNOWN:
        case BSLB_VARIANT_TYPE_INT64:
            break;
        case BSLB_VARIANT_TYPE_BYTESTR:
        case BSLB_VARIANT_TYPE_TEXTSTR:
        case BSLB_VARIANT_TYPE_RAW:
            m_bstring_clear(self->_val.as_bytes);
            break;
        default:
            break;
    }
    self->_type = BSLB_VARIANT_TYPE_UNKNOWN;
}

void BSL_Variant_Set(BSL_Variant_t *self, const BSL_Variant_t *src)
{
    ASSERT_ARG_NONNULL(self);
    ASSERT_ARG_NONNULL(src);

    if (self == src)
    {
        return;
    }
    BSL_Variant_Deinit(self);

    self->_type = src->_type;
    switch (self->_type)
    {
        case BSLB_VARIANT_TYPE_UNKNOWN:
            break;
        case BSLB_VARIANT_TYPE_INT64:
            self->_val.as_int = src->_val.as_int;
            break;
        case BSLB_VARIANT_TYPE_BYTESTR:
        case BSLB_VARIANT_TYPE_TEXTSTR:
        case BSLB_VARIANT_TYPE_RAW:
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

void BSL_Variant_Move(BSL_Variant_t *self, BSL_Variant_t *src)
{
    ASSERT_ARG_NONNULL(self);
    ASSERT_ARG_NONNULL(src);

    if (self == src)
    {
        return;
    }
    BSL_Variant_Deinit(self);

    self->_type = src->_type;
    switch (self->_type)
    {
        case BSLB_VARIANT_TYPE_UNKNOWN:
            break;
        case BSLB_VARIANT_TYPE_INT64:
            self->_val.as_int = src->_val.as_int;
            break;
        case BSLB_VARIANT_TYPE_BYTESTR:
        case BSLB_VARIANT_TYPE_TEXTSTR:
        case BSLB_VARIANT_TYPE_RAW:
            m_bstring_init_move(self->_val.as_bytes, src->_val.as_bytes);
            break;
        default:
            break;
    }

    src->_type = BSLB_VARIANT_TYPE_UNKNOWN;
}

void BSL_Variant_SetTextstr(BSL_Variant_t *self, const char *value)
{
    ASSERT_ARG_NONNULL(self);
    BSL_Variant_Deinit(self);

    self->_type = BSLB_VARIANT_TYPE_TEXTSTR;
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

bool BSL_Variant_IsTextstr(const BSL_Variant_t *self)
{
    CHK_AS_BOOL(self);
    return (self->_type == BSLB_VARIANT_TYPE_TEXTSTR);
}

void BSL_Variant_SetBytestr(BSL_Variant_t *self, BSL_Data_t value)
{
    ASSERT_ARG_NONNULL(self);
    BSL_Variant_Deinit(self);

    self->_type = BSLB_VARIANT_TYPE_BYTESTR;
    m_bstring_init(self->_val.as_bytes);
    if (value.len)
    {
        m_bstring_push_back_bytes(self->_val.as_bytes, value.len, value.ptr);
    }
}

void BSL_Variant_SetInt64(BSL_Variant_t *self, int64_t value)
{
    ASSERT_ARG_NONNULL(self);
    BSL_Variant_Deinit(self);

    self->_type       = BSLB_VARIANT_TYPE_INT64;
    self->_val.as_int = value;
}

bool BSL_Variant_IsInt64(const BSL_Variant_t *self)
{
    CHK_AS_BOOL(self);
    return (self->_type == BSLB_VARIANT_TYPE_INT64);
}

int BSL_Variant_GetAsInt64(const BSL_Variant_t *self, int64_t *out)
{
    CHK_PRECONDITION(BSL_Variant_IsConsistent(self));
    BSL_CHKRET(self->_type == BSLB_VARIANT_TYPE_INT64, BSL_ERR_NOT_FOUND);

    if (out)
    {
        *out = self->_val.as_int;
    }
    return BSL_SUCCESS;
}

bool BSL_Variant_IsBytestr(const BSL_Variant_t *self)
{
    CHK_AS_BOOL(self);
    return (self->_type == BSLB_VARIANT_TYPE_BYTESTR);
}

int BSL_Variant_GetAsBytestr(const BSL_Variant_t *self, BSL_Data_t *out)
{
    CHK_PRECONDITION(BSL_Variant_IsConsistent(self));
    BSL_CHKRET(self->_type == BSLB_VARIANT_TYPE_BYTESTR, BSL_ERR_NOT_FOUND);

    if (out)
    {
        const size_t   size = m_bstring_size(self->_val.as_bytes);
        const uint8_t *ptr  = m_bstring_view(self->_val.as_bytes, 0, size);
        BSL_Data_InitView(out, size, (BSL_DataPtr_t)ptr);
    }
    return BSL_SUCCESS;
}

int BSL_Variant_GetAsTextstr(const BSL_Variant_t *self, const char **out)
{
    CHK_PRECONDITION(BSL_Variant_IsConsistent(self));
    BSL_CHKRET(self->_type == BSLB_VARIANT_TYPE_TEXTSTR, BSL_ERR_NOT_FOUND);

    if (out)
    {
        const size_t   size = m_bstring_size(self->_val.as_bytes);
        const uint8_t *ptr  = m_bstring_view(self->_val.as_bytes, 0, size);

        *out = (const char *)ptr;
    }
    return BSL_SUCCESS;
}

void BSL_Variant_SetRaw(BSL_Variant_t *self, const void *ptr, size_t len)
{
    ASSERT_ARG_NONNULL(self);
    ASSERT_ARG_NONNULL(ptr);
    BSL_Variant_Deinit(self);

    self->_type = BSLB_VARIANT_TYPE_RAW;
    m_bstring_init(self->_val.as_bytes);
    if (len)
    {
        m_bstring_push_back_bytes(self->_val.as_bytes, len, ptr);
    }
}

bool BSL_Variant_IsRaw(const BSL_Variant_t *self)
{
    CHK_AS_BOOL(self);
    return (self->_type == BSLB_VARIANT_TYPE_RAW);
}

int BSL_Variant_GetAsRaw(const BSL_Variant_t *self, BSL_Data_t *out)
{
    CHK_PRECONDITION(BSL_Variant_IsConsistent(self));
    BSL_CHKRET(self->_type == BSLB_VARIANT_TYPE_RAW, BSL_ERR_NOT_FOUND);

    if (out)
    {
        const size_t   size = m_bstring_size(self->_val.as_bytes);
        const uint8_t *ptr  = m_bstring_view(self->_val.as_bytes, 0, size);
        BSL_Data_InitView(out, size, (BSL_DataPtr_t)ptr);
    }
    return BSL_SUCCESS;
}

bool BSL_Variant_IsConsistent(const BSL_Variant_t *self)
{
    CHK_AS_BOOL(self != NULL);
    CHK_AS_BOOL((self->_type > BSLB_VARIANT_TYPE_UNKNOWN) && (self->_type <= BSLB_VARIANT_TYPE_RAW));

    return true;
}

int BSL_Variant_Decode(QCBORDecodeContext *dec, BSL_Variant_t *var)
{
    ASSERT_ARG_NONNULL(dec);
    ASSERT_ARG_NONNULL(var);

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
                BSL_LOG_ERR("Invalid integer value");
                return BSL_ERR_DECODING;
            }
            BSL_LOG_DEBUG("ASB: Parsed variant at %zu as int %" PRId64, value_begin, dec_value);

            BSL_Variant_SetInt64(var, dec_value);
            break;
        }
        case QCBOR_TYPE_BYTE_STRING:
        {
            UsefulBufC target_buf = NULLUsefulBufC;
            QCBORDecode_GetByteString(dec, &target_buf);
            if (QCBOR_SUCCESS != QCBORDecode_GetError(dec))
            {
                BSL_LOG_ERR("Invalid bytestring value");
                return BSL_ERR_DECODING;
            }
            BSL_LOG_DEBUG("ASB: Parsed variant at %zu as bytestr with %zu bytes", value_begin, target_buf.len);
            BSL_Data_t data_view;
            BSL_Data_InitView(&data_view, target_buf.len, (BSL_DataPtr_t)target_buf.ptr);

            BSL_Variant_SetBytestr(var, data_view);
            break;
        }
        default:
        {
            // skip over entire item (recursively) if possible
            QCBORDecode_VGetNextConsume(dec, &valitem);
            if (QCBOR_SUCCESS != QCBORDecode_GetError(dec))
            {
                BSL_LOG_ERR("Invalid raw CBOR");
                return BSL_ERR_DECODING;
            }

            const size_t value_end = QCBORDecode_Tell(dec);
            BSL_LOG_DEBUG("ASB: Parsed var at %zu as raw QCBOR type %u, size %zu bytes", value_begin, valitem.uDataType,
                          value_end - value_begin);

            const UsefulBufC raw_buf = QCBORDecode_RetrieveUndecodedInput(dec);

            BSL_Variant_SetRaw(var, UsefulBuf_OffsetToPointer(raw_buf, value_begin), value_end - value_begin);
            break;
        }
    }
    const size_t value_end = QCBORDecode_Tell(dec);

    if (QCBOR_SUCCESS != QCBORDecode_GetError(dec))
    {
        BSL_LOG_ERR("Failed decoding a value");
        return BSL_ERR_DECODING;
    }
    BSL_LOG_DEBUG("var between %zu and %zu", value_begin, value_end);

    return BSL_SUCCESS;
}

void BSL_Variant_Encode(QCBOREncodeContext *enc, const BSL_Variant_t *pair)
{
    if (BSL_Variant_IsInt64(pair))
    {
        int64_t as_int;
        BSL_Variant_GetAsInt64(pair, &as_int);
        QCBOREncode_AddInt64(enc, as_int);
    }
    else if (BSL_Variant_IsBytestr(pair))
    {
        BSL_Data_t bytestr;
        BSL_Variant_GetAsBytestr(pair, &bytestr);
        QCBOREncode_AddBytes(enc, UsefulBufC_FROM_BSL_Data(bytestr));
    }
    else if (BSL_Variant_IsRaw(pair))
    {
        BSL_Data_t enc_data;
        BSL_Variant_GetAsRaw(pair, &enc_data);
        QCBOREncode_AddEncoded(enc, UsefulBufC_FROM_BSL_Data(enc_data));
    }
    else
    {
        BSL_LOG_CRIT("Unhandled variant type");
        QCBOREncode_AddUndef(enc);
    }
}
