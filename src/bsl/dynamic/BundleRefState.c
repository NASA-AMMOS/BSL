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
/** @file
 * @ingroup backend_dyn
 * @brief Definition of bundle reference state.
 */
#include "BundleRefState.h"

#include "bsl/BPSecLib_Private.h"

void BSL_BundleRefState_Init(BSL_BundleRefState_t *obj)
{
    // GCOV_EXCL_START
    ASSERT_ARG_NONNULL(obj);
    // GCOV_EXCL_STOP
    BSLB_AsbPtrMap_init(obj->bibs);
    BSLB_AsbPtrMap_init(obj->bcbs);
    BSLB_AsbPtrSetMap_init(obj->bib_tgts);
    BSLB_AsbPtrSetMap_init(obj->bcb_tgts);
}

void BSL_BundleRefState_Deinit(BSL_BundleRefState_t *obj)
{
    // GCOV_EXCL_START
    ASSERT_ARG_NONNULL(obj);
    // GCOV_EXCL_STOP
    BSLB_AsbPtrSetMap_clear(obj->bcb_tgts);
    BSLB_AsbPtrSetMap_clear(obj->bib_tgts);
    BSLB_AsbPtrMap_clear(obj->bcbs);
    BSLB_AsbPtrMap_clear(obj->bibs);
}

int BSL_BundleRefState_CacheASB(BSL_BundleRefState_t *obj, const struct BSL_BundleRef_s *bundle,
                                const BSL_CanonicalBlock_t *block)
{
    BSLB_AsbPtrMap_t    *asbmap;
    BSLB_AsbPtrSetMap_t *tgtmap;
    switch (block->type_code)
    {
        case BSL_SECBLOCKTYPE_BIB:
            asbmap = &obj->bibs;
            tgtmap = &obj->bib_tgts;
            break;
        case BSL_SECBLOCKTYPE_BCB:
            asbmap = &obj->bcbs;
            tgtmap = &obj->bcb_tgts;
            break;
        default:
            // only handle security here
            return BSL_ERR_FAILURE;
    }

    BSL_Data_t btsd_copy;
    // ASB decoder needs the whole BTSD now
    int res = BSL_Data_InitBuffer(&btsd_copy, block->btsd_len);
    if (BSL_SUCCESS != res)
    {
        return BSL_ERR_FAILURE;
    }
    // GCOV_EXCL_STOP

    BSL_SeqReader_t *btsd_read = BSL_BundleCtx_ReadBTSD(bundle, block->block_num);
    // GCOV_EXCL_START
    if (!btsd_read)
    {
        BSL_Data_Deinit(&btsd_copy);
        return BSL_ERR_FAILURE;
    }
    // GCOV_EXCL_STOP
    BSL_SeqReader_Get(btsd_read, btsd_copy.ptr, &btsd_copy.len);
    BSL_SeqReader_Destroy(btsd_read);
    // GCOV_EXCL_START
    if (block->btsd_len != btsd_copy.len)
    {
        BSL_LOG_ERR("Failed to read all %zu BTSD, got only %zu", block->btsd_len, btsd_copy.len);
        BSL_Data_Deinit(&btsd_copy);
        return BSL_ERR_FAILURE;
    }
    // GCOV_EXCL_STOP

    BSL_AbsSecBlockPtr_t *asb_ptr = BSL_AbsSecBlockPtr_new();
    // valid as long as the shared pointer
    BSL_AbsSecBlock_t *asb = BSL_AbsSecBlockPtr_ref(asb_ptr);
    // record this state
    asb->sec_block_num = block->block_num;

    int retval = BSL_SUCCESS;

    res = BSL_CBOR_Decode(&btsd_copy, (BSL_CBOR_Decode_f)&BSL_AbsSecBlock_Decode, asb);
    if (BSL_SUCCESS != res)
    {
        BSL_LOG_ERR("Failed to parse ASB from BTSD");
        retval = BSL_ERR_FAILURE;
    }
    else
    {
        BSL_LOG_DEBUG("Caching ASB for block number %" PRIu64 " with block type %" PRIu64, block->block_num,
                      block->type_code);
        BSLB_AsbPtrMap_set_at(*asbmap, block->block_num, asb_ptr);
        BSL_BundleRefState_RepopulateTgts(*tgtmap, asb_ptr);
    }
    BSL_AbsSecBlockPtr_release(asb_ptr);

    BSL_Data_Deinit(&btsd_copy);
    return retval;
}

void BSL_BundleRefState_RepopulateTgts(BSLB_AsbPtrSetMap_t tgtmap, BSL_AbsSecBlockPtr_t *asb_ptr)
{
    // remove any existing references
    BSLB_AsbPtrSetMap_it_t map_it;
    for (BSLB_AsbPtrSetMap_it(map_it, tgtmap); !BSLB_AsbPtrSetMap_end_p(map_it); BSLB_AsbPtrSetMap_next(map_it))
    {
        // do not care if if was there or not
        BSLB_AsbPtrSet_pop_at(NULL, BSLB_AsbPtrSetMap_ref(map_it)->value, asb_ptr);
    }

    const BSL_AbsSecBlock_t *asb = BSL_AbsSecBlockPtr_cref(asb_ptr);
    // add new references
    BSL_AbsSecBlock_TargetList_it_t tgt_iter;
    for (BSL_AbsSecBlock_TargetList_it(tgt_iter, asb->target_results); !BSL_AbsSecBlock_TargetList_end_p(tgt_iter);
         BSL_AbsSecBlock_TargetList_next(tgt_iter))
    {
        const BSL_AbsSecBlock_Target_t *tgt = BSL_AbsSecBlock_TargetPtr_cref(*BSL_AbsSecBlock_TargetList_ref(tgt_iter));

        BSLB_AsbPtrSet_t *ptrs = BSLB_AsbPtrSetMap_safe_get(tgtmap, tgt->target_block_num);
        BSLB_AsbPtrSet_push(*ptrs, asb_ptr);
    }
}
