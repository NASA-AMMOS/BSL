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
/**
 * @file
 * @ingroup backend_dyn
 * @brief Defines a security operation.
 */
#include "SecOperation.h"
#include "IdValPair.h"

size_t BSL_SecOper_Sizeof(void)
{
    return sizeof(BSL_SecOper_t);
}

void BSL_SecOper_Init(BSL_SecOper_t *self)
{
    ASSERT_ARG_NONNULL(self);

    memset(self, 0, sizeof(*self));
    BSLB_IdValPairPtrMap_init(self->_options);
    BSLB_IdValPairPtrMap_init(self->_params);
    BSLB_IdValPairPtrMap_init(self->_results);
}

void BSL_SecOper_InitSet(BSL_SecOper_t *self, const BSL_SecOper_t *src)
{
    ASSERT_ARG_NONNULL(self);
    ASSERT_ARG_NONNULL(src);

    memset(self, 0, sizeof(*self));
    self->context_id       = src->context_id;
    self->target_block_num = src->target_block_num;
    self->sec_block_num    = src->sec_block_num;
    self->sec_src_eid      = src->sec_src_eid;
    self->policy_action    = src->policy_action;
    self->conclusion       = src->conclusion;
    self->reason_code      = src->reason_code;
    self->_role            = src->_role;
    self->_service_type    = src->_service_type;
    BSLB_IdValPairPtrMap_init_set(self->_options, src->_options);
    BSLB_IdValPairPtrMap_init_set(self->_params, src->_params);
    BSLB_IdValPairPtrMap_init_set(self->_results, src->_results);

    ASSERT_POSTCONDITION(BSL_SecOper_IsConsistent(self));
}

void BSL_SecOper_Deinit(BSL_SecOper_t *self)
{
    ASSERT_ARG_NONNULL(self);
    BSLB_IdValPairPtrMap_clear(self->_results);
    BSLB_IdValPairPtrMap_clear(self->_params);
    BSLB_IdValPairPtrMap_clear(self->_options);
}

void BSL_SecOper_Set(BSL_SecOper_t *self, const BSL_SecOper_t *src)
{
    ASSERT_PRECONDITION(BSL_SecOper_IsConsistent(self));

    self->context_id       = src->context_id;
    self->target_block_num = src->target_block_num;
    self->sec_block_num    = src->sec_block_num;
    self->sec_src_eid      = src->sec_src_eid;
    self->policy_action    = src->policy_action;
    self->conclusion       = src->conclusion;
    self->reason_code      = src->reason_code;
    self->_role            = src->_role;
    self->_service_type    = src->_service_type;
    BSLB_IdValPairPtrMap_set(self->_options, src->_options);
    BSLB_IdValPairPtrMap_set(self->_params, src->_params);
    BSLB_IdValPairPtrMap_set(self->_results, src->_results);

    ASSERT_POSTCONDITION(BSL_SecOper_IsConsistent(self));
}

void BSL_SecOper_Populate(BSL_SecOper_t *self, int64_t context_id, uint64_t target_block_num, uint64_t sec_block_num,
                          BSL_SecBlockType_e sec_type, BSL_SecRole_e sec_role, BSL_PolicyAction_e policy_action)
{
    ASSERT_ARG_NONNULL(self);
    self->context_id       = context_id;
    self->target_block_num = target_block_num;
    self->sec_block_num    = sec_block_num;
    self->policy_action    = policy_action;
    self->_service_type    = sec_type;
    self->_role            = sec_role;
    self->conclusion       = BSL_SECOP_CONCLUSION_PENDING;
    self->reason_code      = BSL_REASONCODE_NO_ADDITIONAL_INFO;

    ASSERT_POSTCONDITION(BSL_SecOper_IsConsistent(self));
}

size_t BSL_SecOper_CountOptions(const BSL_SecOper_t *self)
{
    ASSERT_PRECONDITION(BSL_SecOper_IsConsistent(self));

    return BSLB_IdValPairPtrMap_size(self->_options);
}

bool BSL_SecOper_IsConsistent(const BSL_SecOper_t *self)
{
    // NOLINTBEGIN
    CHK_AS_BOOL(self != NULL);
    CHK_AS_BOOL(self->_service_type == BSL_SECBLOCKTYPE_BCB || self->_service_type == BSL_SECBLOCKTYPE_BIB);
    CHK_AS_BOOL(self->_role == BSL_SECROLE_ACCEPTOR || self->_role == BSL_SECROLE_VERIFIER
                || self->_role == BSL_SECROLE_SOURCE);
    CHK_AS_BOOL(self->conclusion >= BSL_SECOP_CONCLUSION_PENDING && self->conclusion <= BSL_SECOP_CONCLUSION_FAILURE);
    // NOLINTEND
    return true;
}

void BSL_SecOper_AppendOption(BSL_SecOper_t *self, const BSL_IdValPair_t *option)
{
    ASSERT_ARG_EXPR(BSL_IdValPair_IsConsistent(option));
    ASSERT_PRECONDITION(BSL_SecOper_IsConsistent(self));

    BSLB_IdValPairPtr_t *item_ptr = BSLB_IdValPairPtr_new_from(*option);

    BSLB_IdValPairPtrMap_set_at(self->_options, option->id, item_ptr);
    BSLB_IdValPairPtr_release(item_ptr);

    ASSERT_POSTCONDITION(BSL_SecOper_IsConsistent(self));
}

void BSL_SecOper_AppendParam(BSL_SecOper_t *self, const BSL_IdValPair_t *param)
{
    ASSERT_ARG_EXPR(BSL_IdValPair_IsConsistent(param));
    ASSERT_PRECONDITION(BSL_SecOper_IsConsistent(self));

    BSLB_IdValPairPtr_t *item_ptr = BSLB_IdValPairPtr_new_from(*param);

    BSLB_IdValPairPtrMap_set_at(self->_params, param->id, item_ptr);
    BSLB_IdValPairPtr_release(item_ptr);

    ASSERT_POSTCONDITION(BSL_SecOper_IsConsistent(self));
}

BSL_IdValPair_t *BSL_SecOper_AddParam(BSL_SecOper_t *self, int64_t param_id)
{
    ASSERT_PRECONDITION(BSL_SecOper_IsConsistent(self));
    return BSLB_IdValPairPtrMap_add(self->_params, param_id);
}

BSL_IdValPair_t *BSL_SecOper_AddResult(BSL_SecOper_t *self, int64_t result_id)
{
    ASSERT_PRECONDITION(BSL_SecOper_IsConsistent(self));
    return BSLB_IdValPairPtrMap_add(self->_results, result_id);
}

size_t BSL_SecOper_CountParams(const BSL_SecOper_t *self)
{
    ASSERT_PRECONDITION(BSL_SecOper_IsConsistent(self));
    return BSLB_IdValPairPtrMap_size(self->_params);
}

size_t BSL_SecOper_CountResults(const BSL_SecOper_t *self)
{
    ASSERT_PRECONDITION(BSL_SecOper_IsConsistent(self));
    return BSLB_IdValPairPtrMap_size(self->_results);
}

void BSL_SecOper_ClearParamsAndResults(BSL_SecOper_t *self)
{
    ASSERT_PRECONDITION(BSL_SecOper_IsConsistent(self));
    BSLB_IdValPairPtrMap_reset(self->_params);
    BSLB_IdValPairPtrMap_reset(self->_results);
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

const BSL_HostEID_t *BSL_SecOper_GetSecuritySource(const BSL_SecOper_t *self)
{
    ASSERT_PRECONDITION(BSL_SecOper_IsConsistent(self));

    return self->sec_src_eid;
}

const BSL_IdValPair_t *BSL_SecOper_FindOption(const BSL_SecOper_t *self, int64_t option_id)
{
    ASSERT_PRECONDITION(BSL_SecOper_IsConsistent(self));

    BSLB_IdValPairPtr_t *const *found = BSLB_IdValPairPtrMap_cget(self->_options, option_id);
    return found ? BSLB_IdValPairPtr_cref(*found) : NULL;
}

const BSL_IdValPair_t *BSL_SecOper_FindParam(const BSL_SecOper_t *self, int64_t param_id)
{
    ASSERT_PRECONDITION(BSL_SecOper_IsConsistent(self));

    BSLB_IdValPairPtr_t *const *found = BSLB_IdValPairPtrMap_cget(self->_params, param_id);
    return found ? BSLB_IdValPairPtr_cref(*found) : NULL;
}

size_t BSL_SecOper_ResultCount(const BSL_SecOper_t *self)
{
    ASSERT_PRECONDITION(BSL_SecOper_IsConsistent(self));

    return BSLB_IdValPairPtrMap_size(self->_results);
}
const BSL_IdValPair_t *BSL_SecOper_FindResult(const BSL_SecOper_t *self, int64_t result_id)
{
    ASSERT_PRECONDITION(BSL_SecOper_IsConsistent(self));

    BSLB_IdValPairPtr_t *const *found = BSLB_IdValPairPtrMap_cget(self->_results, result_id);
    return found ? BSLB_IdValPairPtr_cref(*found) : NULL;
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

BSL_PolicyAction_e BSL_SecOper_GetPolicyAction(const BSL_SecOper_t *self)
{
    ASSERT_PRECONDITION(BSL_SecOper_IsConsistent(self));
    return self->policy_action;
}

BSL_ReasonCode_t BSL_SecOper_GetReasonCode(const BSL_SecOper_t *self)
{
    ASSERT_PRECONDITION(BSL_SecOper_IsConsistent(self));
    return self->reason_code;
}

void BSL_SecOper_SetReasonCode(BSL_SecOper_t *self, BSL_ReasonCode_t new_reason_code)
{
    ASSERT_PRECONDITION(BSL_SecOper_IsConsistent(self));
    self->reason_code = new_reason_code;
    ASSERT_POSTCONDITION(BSL_SecOper_IsConsistent(self));
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
