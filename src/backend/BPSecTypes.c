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
 * Implementation of the Security structures such as parameters, results, outcomes, etc.
 */

#include <BPSecTypes.h>
#include <PolicyProvider.h>

bool BSL_SecParam_IsConsistent(const BSL_SecParam_t *self)
{
    assert(self != NULL);
    assert(self->param_id > 0);
    assert(self->_type > BSL_SECPARAM_TYPE_UNKNOWN && self->_type <= BSL_SECPARAM_TYPE_BYTESTR);

    if (self->_type == BSL_SECPARAM_TYPE_INT64)
    {
        assert(self->_bytelen == 0);
    }
    else
    {
        assert(self->_bytelen > 0);
        assert(self->_bytelen <= sizeof(self->_bytes));
        assert(self->_uint_value == 0);
    }
    return true;
}

bool BSL_SecParam_IsParamIDOutput(uint64_t param_id)
{
    // If this index is less than the start index for numbering
    // internal param ids, then it's probably a param_id from the spec.
    return param_id < BSL_SECPARAM_TYPE_INT_STARTINDEX;
}

int BSL_SecResult_Init(BSL_SecResult_t *self, uint64_t result_id, uint64_t context_id, uint64_t target_block_num,
                       BSL_Data_t content)
{
    assert(self != NULL);
    assert(content.len > 0);
    assert(content.ptr != NULL);

    memset(self, 0, sizeof(*self));
    self->result_id        = result_id;
    self->context_id       = context_id;
    self->target_block_num = target_block_num;
    assert(content.len < sizeof(self->_bytes));
    self->_bytelen = content.len;
    memcpy(self->_bytes, content.ptr, self->_bytelen);
    assert(BSL_SecResult_IsConsistent(self));
    return 0;
}

bool BSL_SecResult_IsConsistent(const BSL_SecResult_t *self)
{
    assert(self != NULL);
    assert(self->context_id > 0);
    assert(self->result_id > 0);
    // Check that the target block num is sane (not junk)
    assert(self->target_block_num < 10000);
    assert(self->_bytelen > 0);
    // TODO (Confirm any bytes in the buffer after _bytelen are all zeroes)
    return true;
}

BSL_Data_t BSL_SecResult_ResultAsData(const BSL_SecResult_t *self)
{
    assert(BSL_SecResult_IsConsistent(self));
    BSL_Data_t data_wrapper = { 0 };
    BSL_Data_InitView(&data_wrapper, self->_bytelen, (uint8_t *)self->_bytes);
    return data_wrapper;
}

int BSL_SecParam_InitBytestr(BSL_SecParam_t *self, uint64_t param_id, BSL_Data_t value)
{
    memset(self, 0, sizeof(*self));
    assert(value.ptr != NULL);
    assert(value.len > 0);
    assert(value.len < sizeof(self->_bytes) - 1);
    self->param_id = param_id;
    self->_type    = BSL_SECPARAM_TYPE_BYTESTR;
    self->_bytelen = value.len;
    memcpy(self->_bytes, value.ptr, self->_bytelen);
    return 0;
}

int BSL_SecParam_InitInt64(BSL_SecParam_t *self, uint64_t param_id, uint64_t value)
{
    memset(self, 0, sizeof(*self));
    self->param_id    = param_id;
    self->_type       = BSL_SECPARAM_TYPE_INT64;
    self->_uint_value = value;
    return 0;
}

int BSL_SecParam_IsInt64(const BSL_SecParam_t *self)
{
    assert(self != NULL);
    return (self->_type == BSL_SECPARAM_TYPE_INT64);
}

uint64_t BSL_SecParam_GetAsUInt64(const BSL_SecParam_t *self)
{
    assert(self != NULL);
    assert(self->_type == BSL_SECPARAM_TYPE_INT64);
    return self->_uint_value;
}

int BSL_SecParam_GetAsBytestr(const BSL_SecParam_t *self, BSL_Data_t *result)
{
    assert(result != NULL);
    assert(BSL_SecParam_IsConsistent(self));
    return BSL_Data_InitView(result, self->_bytelen, (uint8_t *)self->_bytes);
}

void BSL_SecOper_Init(BSL_SecOper_t *self, uint64_t context_id, uint64_t target_block_num, uint64_t sec_block_num,
                      BSL_SecBlockType_e sec_type, BSL_SecRole_e sec_role)
{
    assert(self != NULL);
    memset(self, 0, sizeof(*self));
    BSL_SecParamList_init(self->_param_list);
    self->context_id       = context_id;
    self->target_block_num = target_block_num;
    self->sec_block_num    = sec_block_num;
    self->_service_type    = sec_type;
    self->_role            = sec_role;
    BSL_SecOper_IsConsistent(self);
}

void BSL_SecOper_Deinit(BSL_SecOper_t *self)
{
    BSL_SecOper_IsConsistent(self);
    BSL_SecParamList_clear(self->_param_list);
    memset(self, 0, sizeof(*self));
}

bool BSL_SecOper_IsConsistent(const BSL_SecOper_t *self)
{
    // NOLINTBEGIN
    assert(self != NULL);
    assert(self->context_id > 0);
    assert(self->target_block_num < 10000);
    assert(self->sec_block_num > 0);
    assert(self->_service_type == BSL_SECBLOCKTYPE_BCB || self->_service_type == BSL_SECBLOCKTYPE_BIB);
    assert(self->_role == BSL_SECROLE_ACCEPTOR || self->_role == BSL_SECROLE_VERIFIER || self->_role == BSL_SECROLE_SOURCE);
    assert(BSL_SecParamList_size(self->_param_list) < 1000);
    // NOLINTEND
    return true;
}

void BSL_SecOper_AppendParam(BSL_SecOper_t *self, const BSL_SecParam_t *param)
{
    BSL_SecOper_IsConsistent(self);
    BSL_SecParam_IsConsistent(param);

    BSL_SecParamList_push_back(self->_param_list, *param);
    
    BSL_SecOper_IsConsistent(self);
}

const BSL_SecParam_t *BSL_SecOper_GetParamAt(const BSL_SecOper_t *self, size_t index)
{
    assert(BSL_SecOper_IsConsistent(self));

    assert(index < BSL_SecParamList_size(self->_param_list));
    return BSL_SecParamList_cget(self->_param_list, index);
}

size_t BSL_SecOper_GetParamLen(const BSL_SecOper_t *self)
{
    assert(self != NULL);

    return BSL_SecParamList_size(self->_param_list);
}

bool BSL_SecOper_IsRoleSource(const BSL_SecOper_t *self)
{
    assert(self != NULL);
    return self->_role == BSL_SECROLE_SOURCE;
}

bool BSL_SecOper_IsRoleAccepter(const BSL_SecOper_t *self)
{
    assert(self != NULL);
    return self->_role == BSL_SECROLE_ACCEPTOR;
}

bool BSL_SecOper_IsBIB(const BSL_SecOper_t *self)
{
    assert(self != NULL);
    return self->_service_type == BSL_SECBLOCKTYPE_BIB;
}
