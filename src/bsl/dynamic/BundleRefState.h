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
 * @brief Declaration of BSL state within bundle references.
 */
#ifndef BSLB_BUNDLEREFSTATE_H_
#define BSLB_BUNDLEREFSTATE_H_

#include "AbsSecBlock.h"

#include <m-dict.h>
#include <m-rbtree.h>
#include <m-shared-ptr.h>

#ifdef __cplusplus
extern "C" {
#endif

/** @struct BSL_AbsSecBlockPtr_t
 * Shared pointer to ::BSL_AbsSecBlock_s instance.
 */
/** @struct BSLB_AsbPtrMap_t
 * Map from number (uint64_t) to shared pointer to ::BSL_AbsSecBlock_s for its content.
 * Used to map security block numbers and correlation IDs to ASBs
 */
/** @struct BSLB_AsbPtrSetMap_t
 * Map from target block number (uint64_t) to set of shared pointer to ::BSL_AbsSecBlock_s for security ops on the
 * target.
 */
/** @struct BSLB_AsbPtrSet_t
 * Set of shared pointers to ::BSL_AbsSecBlock_s instances.
 */
/// @cond Doxygen_Suppress
// NOLINTBEGIN
// GCOV_EXCL_START
#define M_OPL_BSL_AbsSecBlock_t() \
    (INIT(API_2(BSL_AbsSecBlock_Init)), CLEAR(API_2(BSL_AbsSecBlock_Deinit)), INIT_SET(0), SET(0))
M_SHARED_WEAK_PTR_DEF(BSL_AbsSecBlockPtr, BSL_AbsSecBlock_t, M_OPL_BSL_AbsSecBlock_t())
#define M_OPL_BSL_AbsSecBlockPtr_t() M_SHARED_PTR_OPLIST(BSL_AbsSecBlockPtr, M_OPL_BSL_AbsSecBlock_t())

M_DICT_DEF2(BSLB_AsbPtrMap, uint64_t, M_BASIC_OPLIST, BSL_AbsSecBlockPtr_t *, M_OPL_BSL_AbsSecBlockPtr_t())

M_RBTREE_DEF(BSLB_AsbPtrSet, BSL_AbsSecBlockPtr_t *, M_OPL_BSL_AbsSecBlockPtr_t())
#define M_OPL_BSLB_AsbPtrSet_t() M_ARRAY_OPLIST(BSLB_AsbPtrSet, M_OPL_BSL_AbsSecBlockPtr_t())
M_DICT_DEF2(BSLB_AsbPtrSetMap, uint64_t, M_BASIC_OPLIST, BSLB_AsbPtrSet_t, M_OPL_BSLB_AsbPtrSet_t())
// GCOV_EXCL_STOP
// NOLINTEND
/// @endcond

/** Internal BSL state associated with each bundle at each
 * interaction point.
 */
typedef struct BSL_BundleRefState_s
{
    /// Cache of decoded BIB content for policy query and operation execution
    BSLB_AsbPtrMap_t bibs;
    /// Cache of decoded BCB content
    BSLB_AsbPtrMap_t bcbs;

    /// Map from target block number to associated BIB ASB
    BSLB_AsbPtrSetMap_t bib_tgts;
    /// Map from target block number to associated BCB ASB
    BSLB_AsbPtrSetMap_t bcb_tgts;

    /// Map from correlation ID to associated ASB
    BSLB_AsbPtrMap_t correlations;
} BSL_BundleRefState_t;

/** Initialize an empty reference state.
 * @param[out] obj The struct to initialize.
 */
void BSL_BundleRefState_Init(BSL_BundleRefState_t *obj);

/** De-initialize an empty reference state.
 * @param[in] obj The struct to de-initialize.
 */
void BSL_BundleRefState_Deinit(BSL_BundleRefState_t *obj);

/** Decode and cache an existing ASB.
 *
 * @param[in] obj The state to cache into.
 * @param[in] bundle The BTSD reading context..
 * @param[in] block The block info to read from.
 */
int BSL_BundleRefState_CacheASB(BSL_BundleRefState_t *obj, const BSL_BundleRef_t *bundle,
                                const BSL_CanonicalBlock_t *block);

/** Re-populate a target map for an existing ASB.
 */
void BSL_BundleRefState_RepopulateTgts(BSLB_AsbPtrSetMap_t map, BSL_AbsSecBlockPtr_t *asb_ptr);

#ifdef __cplusplus
} // extern C
#endif

#endif /* BSLB_BUNDLEREFSTATE_H_ */
