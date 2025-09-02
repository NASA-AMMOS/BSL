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
 * @brief Implementation of a RFC9172 Result
 * @ingroup backend_dyn
 */
#include "SecResult.h"

int BSL_SecResult_Init(BSL_SecResult_t *self, uint64_t result_id, int64_t context_id, uint64_t target_block_num,
                       const BSL_Data_t *content)
{
    CHK_ARG_NONNULL(self);
    // TODO relax these
    CHK_ARG_EXPR(content->len > 0);
    CHK_ARG_NONNULL(content->ptr);

    memset(self, 0, sizeof(*self));
    self->result_id        = result_id;
    self->context_id       = context_id;
    self->target_block_num = target_block_num;
    ASSERT_PROPERTY(content->len < sizeof(self->_bytes));
    self->_bytelen = content->len;
    memcpy(self->_bytes, content->ptr, self->_bytelen);

    CHK_POSTCONDITION(BSL_SecResult_IsConsistent(self));
    return BSL_SUCCESS;
}

bool BSL_SecResult_IsConsistent(const BSL_SecResult_t *self)
{
    CHK_AS_BOOL(self != NULL);
    CHK_AS_BOOL(self->context_id != 0);
    CHK_AS_BOOL(self->result_id > 0);
    // Check that the target block num is sane (not junk)
    CHK_AS_BOOL(self->target_block_num < 10000);
    CHK_AS_BOOL(self->_bytelen > 0);
    // TODO (Confirm any bytes in the buffer after _bytelen are all zeroes)
    return true;
}

size_t BSL_SecResult_Sizeof(void)
{
    return sizeof(BSL_SecResult_t);
}
