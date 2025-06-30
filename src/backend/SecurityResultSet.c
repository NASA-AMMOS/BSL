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
 * @brief SecurityResultSet implementation for result after application of security operations.
 * @ingroup backend_dyn
 */
#include "SecurityResultSet.h"

size_t BSL_SecurityResponseSet_Sizeof()
{
    return sizeof(BSL_SecurityResponseSet_t);
}

bool BSL_SecurityResponseSet_IsConsistent(const BSL_SecurityResponseSet_t *self)
{
    CHK_AS_BOOL(self != NULL);
    CHK_AS_BOOL(self->err_msg[sizeof(self->err_msg) - 1] == '\0');
    CHK_AS_BOOL(strlen(self->err_msg) < sizeof(self->err_msg));
    return true;
}

void BSL_SecurityResponseSet_Init(BSL_SecurityResponseSet_t *self, size_t noperations, size_t nfailed)
{
    ASSERT_ARG_NONNULL(self);
    self->failure_count    = nfailed;
    self->total_operations = noperations;
    self->err_code         = (nfailed == 0 && noperations > 1) ? 0 : 1;
}

void BSL_SecurityResponseSet_Deinit(BSL_SecurityResponseSet_t *self)
{
    ASSERT_PRECONDITION(BSL_SecurityResponseSet_IsConsistent(self));
    memset(self, 0, sizeof(*self));
}

size_t BSL_SecurityResponseSet_CountResponses(const BSL_SecurityResponseSet_t *self)
{
    ASSERT_PRECONDITION(BSL_SecurityResponseSet_IsConsistent(self));
    return self->total_operations;
}
