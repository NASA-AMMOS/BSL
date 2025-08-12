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
    (void) self;
    return true;
}

size_t BSL_SecurityActionSet_Sizeof(void)
{
    return sizeof(BSL_SecurityActionSet_t);
}

void BSL_SecurityActionSet_Init(BSL_SecurityActionSet_t *self)
{
    ASSERT_ARG_NONNULL(self);
    BSL_SecActionList_init(self->actions);
    self->action_count = 0;
    self->err_count = 0;
}

void BSL_SecurityActionSet_Deinit(BSL_SecurityActionSet_t *self)
{
    ASSERT_ARG_NONNULL(self);
    BSL_SecActionList_clear(self->actions);
    self->err_count = 0;
    self->action_count = 0;
    self->operation_count = 0;
}

int BSL_SecurityActionSet_AppendAction(BSL_SecurityActionSet_t *self, const BSL_SecurityAction_t *action)
{
    ASSERT_ARG_NONNULL(self);
    BSL_SecActionList_push_back(self->actions, *action);
    self->err_count += action->err_ct;
    self->action_count++;
    self->operation_count += BSL_SecurityAction_CountSecOpers(action);

    return BSL_SUCCESS;
}

size_t BSL_SecurityActionSet_CountActions(const BSL_SecurityActionSet_t *self)
{
    ASSERT_ARG_NONNULL(self);
    return self->action_count;
}

size_t BSL_SecurityActionSet_CountOperations(const BSL_SecurityActionSet_t *self)
{
    ASSERT_ARG_NONNULL(self);
    return self->operation_count;
}

const BSL_SecurityAction_t *BSL_SecurityActionSet_GetActionAtIndex(const BSL_SecurityActionSet_t *self, size_t index)
{
    ASSERT_ARG_NONNULL(self);
    return BSL_SecActionList_cget(self->actions, index);
}

size_t BSL_SecurityActionSet_CountErrors(const BSL_SecurityActionSet_t *self)
{
    ASSERT_ARG_NONNULL(self);
    return self->err_count;
}