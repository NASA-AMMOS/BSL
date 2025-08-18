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
#include "SecurityAction.h"

size_t BSL_SecurityAction_Sizeof(void)
{
    return sizeof(BSL_SecurityAction_t);
}

bool BSL_SecurityAction_IsConsistent(const BSL_SecurityAction_t *self)
{
    (void)self;
    return true;
}

void BSL_SecurityAction_Init(BSL_SecurityAction_t *self)
{
    ASSERT_ARG_NONNULL(self);

    BSL_SecOperList_init(self->sec_op_list);
    self->err_ct = 0;
    self->pp_id  = 0;
}

void BSL_SecurityAction_InitSet(BSL_SecurityAction_t *self, const BSL_SecurityAction_t *src)
{
    ASSERT_ARG_NONNULL(self);

    BSL_SecOperList_init_set(self->sec_op_list, src->sec_op_list);
    self->err_ct = src->err_ct;
    self->pp_id  = src->pp_id;
}

void BSL_SecurityAction_Deinit(BSL_SecurityAction_t *self)
{
    ASSERT_ARG_NONNULL(self);

    BSL_SecOperList_clear(self->sec_op_list);
}

void BSL_SecurityAction_IncrError(BSL_SecurityAction_t *self)
{
    ASSERT_ARG_NONNULL(self);
    self->err_ct++;
}

size_t BSL_SecurityAction_CountErrors(const BSL_SecurityAction_t *self)
{
    ASSERT_ARG_NONNULL(self);
    return self->err_ct;
}

int BSL_SecurityAction_AppendSecOper(BSL_SecurityAction_t *self, BSL_SecOper_t *sec_oper)
{
    ASSERT_ARG_NONNULL(self);
    ASSERT_ARG_NONNULL(sec_oper);

    BSL_SecOperList_push_move(self->sec_op_list, sec_oper);

    return BSL_SUCCESS;
}

size_t BSL_SecurityAction_CountSecOpers(const BSL_SecurityAction_t *self)
{
    ASSERT_ARG_NONNULL(self);
    ASSERT_ARG_NONNULL(self->sec_op_list);
    return BSL_SecOperList_size(self->sec_op_list);
}

BSL_SecOper_t *BSL_SecurityAction_GetSecOperAtIndex(const BSL_SecurityAction_t *self, size_t index)
{
    ASSERT_ARG_NONNULL(self);
    ASSERT_ARG_NONNULL(self->sec_op_list);
    return BSL_SecOperList_get(self->sec_op_list, index);
}

uint64_t BSL_SecurityAction_GetPPID(const BSL_SecurityAction_t *self)
{
    ASSERT_ARG_NONNULL(self);
    return self->pp_id;
}
