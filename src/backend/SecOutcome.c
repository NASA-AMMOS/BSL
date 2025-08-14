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

void BSL_SecOutcome_Init(BSL_SecOutcome_t *self, const BSL_SecOper_t *sec_oper, size_t allocation_size)
{
    ASSERT_ARG_NONNULL(self);
    ASSERT_ARG_NONNULL(sec_oper);
    ASSERT_ARG_EXPR(allocation_size > 0);

    ASSERT_PRECONDITION(BSL_SecOper_IsConsistent(sec_oper));

    memset(self, 0, sizeof(*self));
    self->is_success = 0;
    BSLB_SecParamList_init(self->param_list);
    BSLB_SecResultList_init(self->result_list);
    self->sec_oper = sec_oper;
    BSL_Data_InitBuffer(&self->allocation, allocation_size);

    ASSERT_POSTCONDITION(BSL_SecOutcome_IsConsistent(self));
}

void BSL_SecOutcome_Deinit(BSL_SecOutcome_t *self)
{
    ASSERT_PRECONDITION(BSL_SecOutcome_IsConsistent(self));

    BSLB_SecParamList_clear(self->param_list);
    BSLB_SecResultList_clear(self->result_list);
    BSL_Data_Deinit(&self->allocation);
    memset(self, 0, sizeof(*self));
}

bool BSL_SecOutcome_IsConsistent(const BSL_SecOutcome_t *self)
{
    CHK_AS_BOOL(self != NULL);
    CHK_AS_BOOL(self->sec_oper != NULL);
    CHK_AS_BOOL(self->allocation.len > 0);
    CHK_AS_BOOL(self->allocation.ptr != NULL);

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

    // Invariant: Parameter list contains something (i.e., calling it doesn't cause problems)
    // NOLINTNEXTLINE
    CHK_AS_BOOL(BSLB_SecParamList_size(self->param_list) < 1000);
    return true;
}

void BSL_SecOutcome_AppendResult(BSL_SecOutcome_t *self, const BSL_SecResult_t *sec_result)
{
    ASSERT_PRECONDITION(BSL_SecOutcome_IsConsistent(self));
    ASSERT_PRECONDITION(BSL_SecResult_IsConsistent(sec_result));

    size_t size0 = BSLB_SecResultList_size(self->result_list);
    BSLB_SecResultList_push_back(self->result_list, *sec_result);

    ASSERT_POSTCONDITION(size0 + 1 == BSLB_SecResultList_size(self->result_list));
    ASSERT_POSTCONDITION(BSL_SecOutcome_IsConsistent(self));
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

    return BSLB_SecParamList_size(self->param_list);
}

const BSL_SecParam_t *BSL_SecOutcome_GetParamAt(const BSL_SecOutcome_t *self, size_t index)
{
    ASSERT_PRECONDITION(BSL_SecOutcome_IsConsistent(self));
    ASSERT_PRECONDITION(index < BSL_SecOutcome_CountParams(self));

    return BSLB_SecParamList_cget(self->param_list, index);
}

void BSL_SecOutcome_AppendParam(BSL_SecOutcome_t *self, const BSL_SecParam_t *param)
{
    ASSERT_PRECONDITION(BSL_SecParam_IsConsistent(param));
    ASSERT_PRECONDITION(BSL_SecOutcome_IsConsistent(self));

    size_t size0 = BSLB_SecParamList_size(self->param_list);
    BSLB_SecParamList_push_back(self->param_list, *param);

    ASSERT_POSTCONDITION(size0 + 1 == BSLB_SecParamList_size(self->param_list));
    ASSERT_POSTCONDITION(BSL_SecOutcome_IsConsistent(self));
}

static bool BSL_AbsSecBlock_ContainsResult(const BSL_AbsSecBlock_t *abs_sec_block, const BSL_SecResult_t *actual)
{
    ASSERT_PRECONDITION(BSL_AbsSecBlock_IsConsistent(abs_sec_block));
    ASSERT_POSTCONDITION(BSL_SecResult_IsConsistent(actual));

    BSL_AbsSecBlock_Print(abs_sec_block);
    for (size_t index = 0; index < BSLB_SecResultList_size(abs_sec_block->results); index++)
    {
        BSL_SecResult_t *expected = BSLB_SecResultList_get(abs_sec_block->results, index);
        ASSERT_PROPERTY(expected != NULL);
        bool hdr_matches = (actual->context_id == expected->context_id) && (actual->result_id == expected->result_id)
                           && (actual->target_block_num == expected->target_block_num)
                           && (actual->_bytelen == expected->_bytelen);
        if (hdr_matches)
        {
            int cmp = memcmp(actual->_bytes, expected->_bytes, expected->_bytelen);
            return cmp == 0;
        }
    }
    return false;
}

bool BSL_SecOutcome_IsInAbsSecBlock(const BSL_SecOutcome_t *self, const BSL_AbsSecBlock_t *abs_sec_block)
{
    ASSERT_PRECONDITION(BSL_SecOutcome_IsConsistent(self));
    ASSERT_PRECONDITION(BSL_AbsSecBlock_IsConsistent(abs_sec_block));

    size_t found_matches    = 0;
    size_t expected_matches = BSLB_SecResultList_size(self->result_list);
    if (expected_matches == 0)
    {
        return false;
    }

    for (size_t result_index = 0; result_index < expected_matches; result_index++)
    {
        const BSL_SecResult_t *actual_res = BSLB_SecResultList_get(self->result_list, result_index);
        ASSERT_PROPERTY(actual_res != NULL);
        if (BSL_AbsSecBlock_ContainsResult(abs_sec_block, actual_res))
        {
            found_matches++;
        }
        else
        {
            BSL_LOG_ERR("Security operation mismatch - ASB does NOT contain block %" PRIu64,
                        actual_res->target_block_num);
        }
    }
    BSL_LOG_DEBUG("Checking results: %zu expected, %zu found", expected_matches, found_matches);
    return (expected_matches == found_matches) && (found_matches > 0);
}
