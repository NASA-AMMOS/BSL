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

int BSL_SecParam_InitStr(BSL_SecParam_t *self, uint64_t param_id, const char *value)
{
    CHK_ARG_NONNULL(self);
    CHK_ARG_EXPR(value != NULL);

    memset(self, 0, sizeof(*self));
    self->param_id = param_id;
    self->_type    = BSL_SECPARAM_TYPE_STR;
    self->_bytelen = strlen(value);
    memcpy(self->_bytes, value, strlen(value));

    return BSL_SUCCESS;
}

int BSL_SecParam_InitBytestr(BSL_SecParam_t *self, uint64_t param_id, BSL_Data_t value)
{
    CHK_ARG_NONNULL(self);

    CHK_ARG_EXPR(value.ptr != NULL);
    CHK_ARG_EXPR(value.len > 0);
    CHK_ARG_EXPR(value.len < sizeof(self->_bytes) - 1);

    memset(self, 0, sizeof(*self));
    self->param_id = param_id;
    self->_type    = BSL_SECPARAM_TYPE_BYTESTR;
    self->_bytelen = value.len;
    memcpy(self->_bytes, value.ptr, self->_bytelen);

    return BSL_SUCCESS;
}

int BSL_SecParam_InitInt64(BSL_SecParam_t *self, uint64_t param_id, uint64_t value)
{
    CHK_ARG_NONNULL(self);

    memset(self, 0, sizeof(*self));
    self->param_id    = param_id;
    self->_type       = BSL_SECPARAM_TYPE_INT64;
    self->_uint_value = value;

    return BSL_SUCCESS;
}

int BSL_SecParam_IsInt64(const BSL_SecParam_t *self)
{
    CHK_ARG_NONNULL(self);
    return (self->_type == BSL_SECPARAM_TYPE_INT64);
}

uint64_t BSL_SecParam_GetAsUInt64(const BSL_SecParam_t *self)
{
    ASSERT_ARG_NONNULL(self);
    ASSERT_PRECONDITION(self->_type == BSL_SECPARAM_TYPE_INT64);

    return self->_uint_value;
}

int BSL_SecParam_GetAsBytestr(const BSL_SecParam_t *self, BSL_Data_t *result)
{
    CHK_ARG_NONNULL(result);
    CHK_PRECONDITION(BSL_SecParam_IsConsistent(self));

    return BSL_Data_InitView(result, self->_bytelen, (uint8_t *)self->_bytes);
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
    CHK_AS_BOOL(self->_type > BSL_SECPARAM_TYPE_UNKNOWN && self->_type <= BSL_SECPARAM_TYPE_STR);

    if (self->_type == BSL_SECPARAM_TYPE_INT64)
    {
        CHK_AS_BOOL(self->_bytelen == 0);
    }
    else
    {
        CHK_AS_BOOL(self->_bytelen > 0);
        CHK_AS_BOOL(self->_bytelen <= sizeof(self->_bytes));
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
