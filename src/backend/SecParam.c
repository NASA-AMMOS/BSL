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
 * @brief Implementation of a RFC9172 Parameter
 * @ingroup backend_dyn
 */
#include "SecParam.h"

size_t BSL_SecParam_Sizeof(void)
{
    return sizeof(BSL_SecParam_t);
}

void BSL_SecParam_Init(BSL_SecParam_t *self)
{
    ASSERT_ARG_NONNULL(self);
    memset(self, 0, sizeof(*self));
    m_bstring_init(self->_bytes);
}

void BSL_SecParam_InitSet(BSL_SecParam_t *self, const BSL_SecParam_t *src)
{
    BSL_SecParam_Init(self);
    BSL_SecParam_Set(self, src);
}

void BSL_SecParam_Deinit(BSL_SecParam_t *self)
{
    ASSERT_ARG_NONNULL(self);
    m_bstring_clear(self->_bytes);
}

void BSL_SecParam_Set(BSL_SecParam_t *self, const BSL_SecParam_t *src)
{
    ASSERT_ARG_NONNULL(self);
    ASSERT_ARG_NONNULL(src);
    self->param_id    = src->param_id;
    self->_type       = src->_type;
    self->_uint_value = src->_uint_value;
    // workaround m_bstring issue
    if (m_bstring_empty_p(src->_bytes))
    {
        m_bstring_reset(self->_bytes);
    }
    else
    {
        m_bstring_set(self->_bytes, src->_bytes);
    }
}

int BSL_SecParam_InitTextstr(BSL_SecParam_t *self, uint64_t param_id, const char *value)
{
    CHK_ARG_NONNULL(self);
    CHK_ARG_EXPR(value != NULL);
    size_t value_strlen = strlen(value);

    memset(self, 0, sizeof(*self));
    self->param_id = param_id;
    self->_type    = BSL_SECPARAM_TYPE_TEXTSTR;
    // include terminating null
    m_bstring_init(self->_bytes);
    m_bstring_push_back_bytes(self->_bytes, value_strlen + 1, value);

    return BSL_SUCCESS;
}

int BSL_SecParam_InitBytestr(BSL_SecParam_t *self, uint64_t param_id, BSL_Data_t value)
{
    CHK_ARG_NONNULL(self);

    memset(self, 0, sizeof(*self));
    self->param_id = param_id;
    self->_type    = BSL_SECPARAM_TYPE_BYTESTR;
    m_bstring_init(self->_bytes);
    if (value.len)
    {
        m_bstring_push_back_bytes(self->_bytes, value.len, value.ptr);
    }

    return BSL_SUCCESS;
}

int BSL_SecParam_InitInt64(BSL_SecParam_t *self, uint64_t param_id, uint64_t value)
{
    CHK_ARG_NONNULL(self);

    memset(self, 0, sizeof(*self));
    self->param_id    = param_id;
    self->_type       = BSL_SECPARAM_TYPE_INT64;
    self->_uint_value = value;
    m_bstring_init(self->_bytes);

    return BSL_SUCCESS;
}

bool BSL_SecParam_IsInt64(const BSL_SecParam_t *self)
{
    CHK_AS_BOOL(self);
    return (self->_type == BSL_SECPARAM_TYPE_INT64);
}

uint64_t BSL_SecParam_GetAsUInt64(const BSL_SecParam_t *self)
{
    ASSERT_ARG_NONNULL(self);
    ASSERT_PRECONDITION(self->_type == BSL_SECPARAM_TYPE_INT64);

    return self->_uint_value;
}

bool BSL_SecParam_IsBytestr(const BSL_SecParam_t *self)
{
    CHK_AS_BOOL(self);
    return (self->_type == BSL_SECPARAM_TYPE_BYTESTR);
}

int BSL_SecParam_GetAsBytestr(const BSL_SecParam_t *self, BSL_Data_t *result)
{
    CHK_ARG_NONNULL(result);
    CHK_PRECONDITION(BSL_SecParam_IsConsistent(self));
    CHK_PROPERTY(self->_type == BSL_SECPARAM_TYPE_BYTESTR);

    const size_t   size = m_bstring_size(self->_bytes);
    const uint8_t *ptr  = m_bstring_view(self->_bytes, 0, size);
    return BSL_Data_InitView(result, size, (uint8_t *)ptr);
}

int BSL_SecParam_GetAsTextstr(const BSL_SecParam_t *self, const char **result)
{
    CHK_ARG_NONNULL(result);
    CHK_PRECONDITION(BSL_SecParam_IsConsistent(self));
    CHK_PROPERTY(self->_type == BSL_SECPARAM_TYPE_TEXTSTR);

    const size_t   size = m_bstring_size(self->_bytes);
    const uint8_t *ptr  = m_bstring_view(self->_bytes, 0, size);
    *result             = (const char *)ptr;
    return BSL_SUCCESS;
}

uint64_t BSL_SecParam_GetId(const BSL_SecParam_t *self)
{
    ASSERT_PRECONDITION(BSL_SecParam_IsConsistent(self));

    return self->param_id;
}

bool BSL_SecParam_IsConsistent(const BSL_SecParam_t *self)
{
    CHK_AS_BOOL(self != NULL);
    CHK_AS_BOOL(self->param_id > 0);
    CHK_AS_BOOL(self->_type > BSL_SECPARAM_TYPE_UNKNOWN && self->_type <= BSL_SECPARAM_TYPE_TEXTSTR);

    if (self->_type == BSL_SECPARAM_TYPE_INT64)
    {
        CHK_AS_BOOL(m_bstring_empty_p(self->_bytes));
    }
    else
    {
        // TODO is this meaningful?
        CHK_AS_BOOL(self->_uint_value == 0);
    }
    return true;
}

bool BSL_SecParam_IsParamIDOutput(uint64_t param_id)
{
    // If this index is less than the start index for numbering
    // internal param ids, then it's probably a param_id from the spec.
    return param_id < BSL_SECPARAM_TYPE_INT_STARTINDEX;
}
