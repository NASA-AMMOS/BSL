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

void BSL_SecResult_Init(BSL_SecResult_t *self)
{
    ASSERT_ARG_NONNULL(self);

    memset(self, 0, sizeof(*self));
    m_bstring_init(self->_bytes);
}

void BSL_SecResult_InitSet(BSL_SecResult_t *self, const BSL_SecResult_t *src)
{
    BSL_SecResult_Init(self);
    BSL_SecResult_Set(self, src);
}

void BSL_SecResult_Deinit(BSL_SecResult_t *self)
{
    ASSERT_ARG_NONNULL(self);
    m_bstring_clear(self->_bytes);
}

int BSL_SecResult_InitFull(BSL_SecResult_t *self, uint64_t result_id, uint64_t context_id, uint64_t target_block_num,
                           const BSL_Data_t *content)
{
    ASSERT_ARG_NONNULL(self);

    memset(self, 0, sizeof(*self));
    self->result_id        = result_id;
    self->context_id       = context_id;
    self->target_block_num = target_block_num;

    m_bstring_init(self->_bytes);
    if (content->len)
    {
        m_bstring_push_back_bytes(self->_bytes, content->len, content->ptr);
    }

    CHK_POSTCONDITION(BSL_SecResult_IsConsistent(self));
    return BSL_SUCCESS;
}

void BSL_SecResult_Set(BSL_SecResult_t *self, const BSL_SecResult_t *src)
{
    ASSERT_ARG_NONNULL(self);
    ASSERT_ARG_NONNULL(src);
    self->result_id        = src->result_id;
    self->context_id       = src->context_id;
    self->target_block_num = src->target_block_num;

    // workaround m_bstring issue https://github.com/P-p-H-d/mlib/issues/142
    if (m_bstring_empty_p(src->_bytes))
    {
        m_bstring_reset(self->_bytes);
    }
    else
    {
        m_bstring_set(self->_bytes, src->_bytes);
    }
}

bool BSL_SecResult_IsConsistent(const BSL_SecResult_t *self)
{
    CHK_AS_BOOL(self != NULL);
    CHK_AS_BOOL(self->context_id != 0);
    CHK_AS_BOOL(self->result_id > 0);
    return true;
}

int BSL_SecResult_GetAsBytestr(const BSL_SecResult_t *self, BSL_Data_t *out)
{
    CHK_ARG_NONNULL(out);
    CHK_PRECONDITION(BSL_SecResult_IsConsistent(self));

    const size_t   size = m_bstring_size(self->_bytes);
    const uint8_t *ptr  = m_bstring_view(self->_bytes, 0, size);
    return BSL_Data_InitView(out, size, (uint8_t *)ptr);
}

size_t BSL_SecResult_Sizeof(void)
{
    return sizeof(BSL_SecResult_t);
}
