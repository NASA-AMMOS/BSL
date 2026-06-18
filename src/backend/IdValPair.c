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
        case BSL_IDVALPAIR_TYPE_UINT64:
        case BSL_IDVALPAIR_TYPE_NINT64:
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

    self->id = src->id;
    self->_type    = src->_type;
    switch (self->_type)
    {
        case BSL_IDVALPAIR_TYPE_UNKNOWN:
            break;
        case BSL_IDVALPAIR_TYPE_UINT64:
            self->_val.as_uint = src->_val.as_uint;
            break;
        case BSL_IDVALPAIR_TYPE_NINT64:
            self->_val.as_nint = src->_val.as_nint;
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

void BSL_IdValPair_SetTextstr(BSL_IdValPair_t *self, uint64_t param_id, const char *value)
{
    ASSERT_ARG_NONNULL(self);
    BSL_IdValPair_Deinit(self);

    self->id = param_id;
    self->_type    = BSL_IDVALPAIR_TYPE_TEXTSTR;
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

void BSL_IdValPair_SetBytestr(BSL_IdValPair_t *self, uint64_t param_id, BSL_Data_t value)
{
    ASSERT_ARG_NONNULL(self);
    BSL_IdValPair_Deinit(self);

    self->id = param_id;
    self->_type    = BSL_IDVALPAIR_TYPE_BYTESTR;
    m_bstring_init(self->_val.as_bytes);
    if (value.len)
    {
        m_bstring_push_back_bytes(self->_val.as_bytes, value.len, value.ptr);
    }
}

void BSL_IdValPair_SetUint64(BSL_IdValPair_t *self, uint64_t param_id, uint64_t value)
{
    ASSERT_ARG_NONNULL(self);
    BSL_IdValPair_Deinit(self);

    self->id     = param_id;
    self->_type        = BSL_IDVALPAIR_TYPE_UINT64;
    self->_val.as_uint = value;
}

bool BSL_IdValPair_IsUint64(const BSL_IdValPair_t *self)
{
    CHK_AS_BOOL(self);
    return (self->_type == BSL_IDVALPAIR_TYPE_UINT64);
}

uint64_t BSL_IdValPair_GetAsUint64(const BSL_IdValPair_t *self)
{
    ASSERT_ARG_NONNULL(self);
    ASSERT_PRECONDITION(self->_type == BSL_IDVALPAIR_TYPE_UINT64);

    return self->_val.as_uint;
}

void BSL_IdValPair_SetNint64(BSL_IdValPair_t *self, uint64_t param_id, int64_t value)
{
    ASSERT_ARG_NONNULL(self);
    BSL_IdValPair_Deinit(self);

    self->id     = param_id;
    self->_type        = BSL_IDVALPAIR_TYPE_NINT64;
    self->_val.as_nint = value;
}

bool BSL_IdValPair_IsNint64(const BSL_IdValPair_t *self)
{
    CHK_AS_BOOL(self);
    return (self->_type == BSL_IDVALPAIR_TYPE_NINT64);
}

bool BSL_IdValPair_IsBytestr(const BSL_IdValPair_t *self)
{
    CHK_AS_BOOL(self);
    return (self->_type == BSL_IDVALPAIR_TYPE_BYTESTR);
}

int BSL_IdValPair_GetAsBytestr(const BSL_IdValPair_t *self, BSL_Data_t *out)
{
    CHK_ARG_NONNULL(out);
    CHK_PRECONDITION(BSL_IdValPair_IsConsistent(self));
    CHK_PROPERTY(self->_type == BSL_IDVALPAIR_TYPE_BYTESTR);

    const size_t   size = m_bstring_size(self->_val.as_bytes);
    const uint8_t *ptr  = m_bstring_view(self->_val.as_bytes, 0, size);
    return BSL_Data_InitView(out, size, (uint8_t *)ptr);
}

int BSL_IdValPair_GetAsTextstr(const BSL_IdValPair_t *self, const char **out)
{
    CHK_ARG_NONNULL(out);
    CHK_PRECONDITION(BSL_IdValPair_IsConsistent(self));
    CHK_PROPERTY(self->_type == BSL_IDVALPAIR_TYPE_TEXTSTR);

    const size_t   size = m_bstring_size(self->_val.as_bytes);
    const uint8_t *ptr  = m_bstring_view(self->_val.as_bytes, 0, size);
    *out                = (const char *)ptr;
    return BSL_SUCCESS;
}

void BSL_IdValPair_SetRaw(BSL_IdValPair_t *self, uint64_t param_id, const void *ptr, size_t len)
{
    ASSERT_ARG_NONNULL(self);
    ASSERT_ARG_NONNULL(ptr);
    BSL_IdValPair_Deinit(self);

    self->id = param_id;
    self->_type    = BSL_IDVALPAIR_TYPE_RAW;
    m_bstring_init(self->_val.as_bytes);
    if (len)
    {
        m_bstring_push_back_bytes(self->_val.as_bytes, len, ptr);
    }
}

uint64_t BSL_IdValPair_GetId(const BSL_IdValPair_t *self)
{
    ASSERT_PRECONDITION(BSL_IdValPair_IsConsistent(self));

    return self->id;
}

bool BSL_IdValPair_IsConsistent(const BSL_IdValPair_t *self)
{
    CHK_AS_BOOL(self != NULL);
    CHK_AS_BOOL(self->_type > BSL_IDVALPAIR_TYPE_UNKNOWN && self->_type <= BSL_IDVALPAIR_TYPE_TEXTSTR);

    return true;
}
