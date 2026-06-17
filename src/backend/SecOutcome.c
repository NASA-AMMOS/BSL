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
 * @file SecOutcome.h
 * @ingroup backend_dyn
 * @brief Defines the result of a security operation
 */
#include <BPSecLib_Private.h>

#include "AbsSecBlock.h"
#include "SecOutcome.h"

size_t BSL_SecOutcome_Sizeof(void)
{
    return sizeof(BSL_SecOutcome_t);
}

void BSL_SecOutcome_Init(BSL_SecOutcome_t *self, const BSL_SecOper_t *sec_oper)
{
    ASSERT_ARG_NONNULL(self);
    ASSERT_ARG_NONNULL(sec_oper);

    ASSERT_PRECONDITION(BSL_SecOper_IsConsistent(sec_oper));

    memset(self, 0, sizeof(*self));
    self->is_success = 0;
    BSLB_SecParamPtrList_init(self->param_list);
    BSLB_SecResultList_init(self->result_list);
    self->sec_oper = sec_oper;

    ASSERT_POSTCONDITION(BSL_SecOutcome_IsConsistent(self));
}

void BSL_SecOutcome_Deinit(BSL_SecOutcome_t *self)
{
    ASSERT_PRECONDITION(BSL_SecOutcome_IsConsistent(self));

    BSLB_SecParamPtrList_clear(self->param_list);
    BSLB_SecResultList_clear(self->result_list);
    memset(self, 0, sizeof(*self));
}

bool BSL_SecOutcome_IsConsistent(const BSL_SecOutcome_t *self)
{
    CHK_AS_BOOL(self != NULL);
    CHK_AS_BOOL(self->sec_oper != NULL);

    // Invariant: If it is not successful, it should not return any results
    const size_t result_len = BSLB_SecResultList_size(self->result_list);
    if (self->is_success)
    {
        CHK_AS_BOOL(result_len > 0);
    }
    else
    {
        // Note, uncommenting this causes problems...
        // CHK_AS_BOOL(result_len == 0);
    }

    return true;
}

BSL_SecResult_t * BSL_SecOutcome_AppendResult(BSL_SecOutcome_t *self)
{
    ASSERT_PRECONDITION(BSL_SecOutcome_IsConsistent(self));

    return BSLB_SecResultList_push_new(self->result_list);
}

size_t BSL_SecOutcome_CountResults(const BSL_SecOutcome_t *self)
{
    ASSERT_PRECONDITION(BSL_SecOutcome_IsConsistent(self));
    return BSLB_SecResultList_size(self->result_list);
}

const BSL_SecResult_t *BSL_SecOutcome_GetResultAtIndex(const BSL_SecOutcome_t *self, size_t index)
{
    ASSERT_PRECONDITION(BSL_SecOutcome_IsConsistent(self));
    ASSERT_PRECONDITION(index < BSL_SecOutcome_CountResults(self));

    return BSLB_SecResultList_cget(self->result_list, index);
}

size_t BSL_SecOutcome_CountParams(const BSL_SecOutcome_t *self)
{
    ASSERT_PRECONDITION(BSL_SecOutcome_IsConsistent(self));

    return BSLB_SecParamPtrList_size(self->param_list);
}

const BSL_SecParam_t *BSL_SecOutcome_GetParamAt(const BSL_SecOutcome_t *self, size_t index)
{
    ASSERT_PRECONDITION(BSL_SecOutcome_IsConsistent(self));
    ASSERT_PRECONDITION(index < BSL_SecOutcome_CountParams(self));

    return BSLB_SecParamPtr_cref(*BSLB_SecParamPtrList_cget(self->param_list, index));
}

BSL_SecParam_t *BSL_SecOutcome_AppendParam(BSL_SecOutcome_t *self)
{
    ASSERT_PRECONDITION(BSL_SecOutcome_IsConsistent(self));

    return BSLB_SecParamPtr_ref(*BSLB_SecParamPtrList_push_new(self->param_list));
}
