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
/**
 * @file
 * @ingroup backend_dyn
 * @brief Defines a security operation.
 */
#include "SecOperation.h"
#include "SecParam.h"

size_t BSL_SecOper_Sizeof(void)
{
    return sizeof(BSL_SecOper_t);
}

void BSL_SecOper_Init(BSL_SecOper_t *self)
{
    ASSERT_ARG_NONNULL(self);

    memset(self, 0, sizeof(*self));
    BSLB_SecParamList_init(self->_param_list);

    ASSERT_POSTCONDITION(BSL_SecOper_IsConsistent(self));
}

void BSL_SecOper_InitSet(BSL_SecOper_t *self, const BSL_SecOper_t *src)
{
    ASSERT_ARG_NONNULL(self);
    ASSERT_ARG_NONNULL(src);

    memset(self, 0, sizeof(*self));
    self->context_id       = src->context_id;
    self->target_block_num = src->target_block_num;
    self->sec_block_num    = src->sec_block_num;
    self->failure_code     = src->failure_code;
    self->conclusion       = src->conclusion;
    self->_role            = src->_role;
    self->_service_type    = src->_service_type;
    BSLB_SecParamList_init_set(self->_param_list, src->_param_list);

    ASSERT_POSTCONDITION(BSL_SecOper_IsConsistent(self));
}

void BSL_SecOper_Deinit(BSL_SecOper_t *self)
{
    ASSERT_PRECONDITION(BSL_SecOper_IsConsistent(self));
    BSLB_SecParamList_clear(self->_param_list);
}

void BSL_SecOper_Set(BSL_SecOper_t *self, const BSL_SecOper_t *src)
{
    ASSERT_PRECONDITION(BSL_SecOper_IsConsistent(self));

    self->context_id       = src->context_id;
    self->target_block_num = src->target_block_num;
    self->sec_block_num    = src->sec_block_num;
    self->failure_code     = src->failure_code;
    self->conclusion       = src->conclusion;
    self->_role            = src->_role;
    self->_service_type    = src->_service_type;
    BSLB_SecParamList_set(self->_param_list, src->_param_list);
}

void BSL_SecOper_Populate(BSL_SecOper_t *self, int64_t context_id, uint64_t target_block_num, uint64_t sec_block_num,
                          BSL_SecBlockType_e sec_type, BSL_SecRole_e sec_role, BSL_PolicyAction_e failure_code)
{
    ASSERT_ARG_NONNULL(self);
    self->context_id       = context_id;
    self->target_block_num = target_block_num;
    self->sec_block_num    = sec_block_num;
    self->failure_code     = failure_code;
    self->_service_type    = sec_type;
    self->_role            = sec_role;
    self->conclusion       = BSL_SECOP_CONCLUSION_PENDING;

    ASSERT_POSTCONDITION(BSL_SecOper_IsConsistent(self));
}

size_t BSL_SecOper_CountParams(const BSL_SecOper_t *self)
{
    ASSERT_PRECONDITION(BSL_SecOper_IsConsistent(self));

    return BSLB_SecParamList_size(self->_param_list);
}

bool BSL_SecOper_IsConsistent(const BSL_SecOper_t *self)
{
    // NOLINTBEGIN
    CHK_AS_BOOL(self != NULL);
    CHK_AS_BOOL(self->context_id > 0);
    CHK_AS_BOOL(self->target_block_num < 10000);
    // CHK_AS_BOOL(self->sec_block_num > 0);
    CHK_AS_BOOL(self->_service_type == BSL_SECBLOCKTYPE_BCB || self->_service_type == BSL_SECBLOCKTYPE_BIB);
    CHK_AS_BOOL(self->_role == BSL_SECROLE_ACCEPTOR || self->_role == BSL_SECROLE_VERIFIER
                || self->_role == BSL_SECROLE_SOURCE);
    CHK_AS_BOOL(BSLB_SecParamList_size(self->_param_list) < 1000);
    CHK_AS_BOOL(self->conclusion >= BSL_SECOP_CONCLUSION_PENDING && self->conclusion <= BSL_SECOP_CONCLUSION_FAILURE);
    // NOLINTEND
    return true;
}

void BSL_SecOper_AppendParam(BSL_SecOper_t *self, const BSL_SecParam_t *param)
{
    ASSERT_ARG_EXPR(BSL_SecParam_IsConsistent(param));
    ASSERT_PRECONDITION(BSL_SecOper_IsConsistent(self));

    BSLB_SecParamList_push_back(self->_param_list, *param);

    ASSERT_POSTCONDITION(BSL_SecOper_IsConsistent(self));
}

uint64_t BSL_SecOper_GetSecurityBlockNum(const BSL_SecOper_t *self)
{
    ASSERT_PRECONDITION(BSL_SecOper_IsConsistent(self));

    return self->sec_block_num;
}

uint64_t BSL_SecOper_GetTargetBlockNum(const BSL_SecOper_t *self)
{
    ASSERT_PRECONDITION(BSL_SecOper_IsConsistent(self));

    return self->target_block_num;
}

const BSL_SecParam_t *BSL_SecOper_GetParamAt(const BSL_SecOper_t *self, size_t index)
{
    ASSERT_PRECONDITION(BSL_SecOper_IsConsistent(self));
    ASSERT_PRECONDITION(index < BSLB_SecParamList_size(self->_param_list));

    return BSLB_SecParamList_cget(self->_param_list, index);
}

bool BSL_SecOper_IsRoleSource(const BSL_SecOper_t *self)
{
    ASSERT_PRECONDITION(BSL_SecOper_IsConsistent(self));
    return self->_role == BSL_SECROLE_SOURCE;
}

bool BSL_SecOper_IsRoleAcceptor(const BSL_SecOper_t *self)
{
    ASSERT_PRECONDITION(BSL_SecOper_IsConsistent(self));
    return self->_role == BSL_SECROLE_ACCEPTOR;
}

bool BSL_SecOper_IsRoleVerifier(const BSL_SecOper_t *self)
{
    ASSERT_PRECONDITION(BSL_SecOper_IsConsistent(self));
    return self->_role == BSL_SECROLE_VERIFIER;
}

bool BSL_SecOper_IsBIB(const BSL_SecOper_t *self)
{
    ASSERT_PRECONDITION(BSL_SecOper_IsConsistent(self));
    return self->_service_type == BSL_SECBLOCKTYPE_BIB;
}

BSL_SecOper_ConclusionState_e BSL_SecOper_GetConclusion(const BSL_SecOper_t *self)
{
    ASSERT_PRECONDITION(BSL_SecOper_IsConsistent(self));
    return self->conclusion;
}

void BSL_SecOper_SetConclusion(BSL_SecOper_t *self, BSL_SecOper_ConclusionState_e new_conclusion)
{
    ASSERT_PRECONDITION(BSL_SecOper_IsConsistent(self));
    self->conclusion = new_conclusion;
    ASSERT_POSTCONDITION(BSL_SecOper_IsConsistent(self));
}
