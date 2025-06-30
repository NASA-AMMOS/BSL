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
 * @brief Implementation of construct holding details of security operations for a bundle
 * @ingroup backend_dyn
 */
#include "SecurityActionSet.h"

bool BSL_SecurityActionSet_IsConsistent(const BSL_SecurityActionSet_t *self)
{
    CHK_AS_BOOL(self != NULL);
    CHK_AS_BOOL(self->sec_operations_count <= self->arrays_capacity);
    if (self->arrays_capacity > 0)
    {
        CHK_AS_BOOL(self->arrays_capacity == sizeof(self->sec_operations) / sizeof(BSL_SecOper_t));
    }

    // Make sure the arrays are in sync (have equal lengths)
    // 0 means unused.
    for (size_t i = 0; i < self->arrays_capacity; i++)
    {
        if (self->new_block_ids[i] == 0)
        {
            CHK_AS_BOOL(self->new_block_types[i] == 0);
        }
    }
    // TODO, make sure every element in the array that
    // is not a sec oper is set to all zeros.
    return true;
}

size_t BSL_SecurityActionSet_Sizeof(void)
{
    return sizeof(BSL_SecurityActionSet_t);
}

void BSL_SecurityActionSet_Init(BSL_SecurityActionSet_t *self)
{
    ASSERT_ARG_NONNULL(self);

    memset(self, 0, sizeof(*self));
    self->arrays_capacity = sizeof(self->sec_operations) / sizeof(BSL_SecOper_t);

    ASSERT_POSTCONDITION(BSL_SecurityActionSet_IsConsistent(self));
}

void BSL_SecurityActionSet_IncrError(BSL_SecurityActionSet_t *self)
{
    ASSERT_PRECONDITION(BSL_SecurityActionSet_IsConsistent(self));
    self->err_code++;
}

size_t BSL_SecurityActionSet_CountErrors(const BSL_SecurityActionSet_t *self)
{
    ASSERT_PRECONDITION(BSL_SecurityActionSet_IsConsistent(self));

    return self->err_code;
}

void BSL_SecurityActionSet_Deinit(BSL_SecurityActionSet_t *self)
{
    ASSERT_PRECONDITION(BSL_SecurityActionSet_IsConsistent(self));

    for (size_t operation_index = 0; operation_index < self->arrays_capacity; operation_index++)
    {
        BSL_SecOper_Deinit(&(self->sec_operations[operation_index]));
    }
    memset(self, 0, sizeof(*self));
}

int BSL_SecurityActionSet_AppendSecOper(BSL_SecurityActionSet_t *self, const BSL_SecOper_t *sec_oper)
{
    CHK_PRECONDITION(BSL_SecurityActionSet_IsConsistent(self));
    CHK_PRECONDITION(BSL_SecOper_IsConsistent(sec_oper));
    CHK_PRECONDITION(self->sec_operations_count < self->arrays_capacity - 1);

    self->sec_operations[self->sec_operations_count++] = *sec_oper;

    CHK_POSTCONDITION(BSL_SecurityActionSet_IsConsistent(self));
    return BSL_SUCCESS;
}

size_t BSL_SecurityActionSet_CountSecOpers(const BSL_SecurityActionSet_t *self)
{
    ASSERT_PRECONDITION(BSL_SecurityActionSet_IsConsistent(self));
    return self->sec_operations_count;
}

const BSL_SecOper_t *BSL_SecurityActionSet_GetSecOperAtIndex(const BSL_SecurityActionSet_t *self, size_t index)
{
    ASSERT_PRECONDITION(BSL_SecurityActionSet_IsConsistent(self));
    ASSERT_PRECONDITION(index < BSL_SecurityActionSet_CountSecOpers(self));
    ASSERT_PRECONDITION(index < self->arrays_capacity);

    const BSL_SecOper_t *sec_oper = &self->sec_operations[index];

    // The return security operation should be valid
    ASSERT_POSTCONDITION(BSL_SecOper_IsConsistent(sec_oper));
    return sec_oper;
}

int BSL_SecurityActionSet_GetErrCode(const BSL_SecurityActionSet_t *self)
{
    CHK_PRECONDITION(BSL_SecurityActionSet_IsConsistent(self));
    return self->err_code;
}
