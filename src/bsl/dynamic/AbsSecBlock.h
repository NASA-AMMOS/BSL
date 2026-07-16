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

/** @file AbsSecBlock.h
 * @brief Concrete implementation of ASB and its functionality
 * @details Forthcoming
 *
 * See https://www.rfc-editor.org/rfc/rfc9172.html#name-abstract-security-block
 * @ingroup backend_dyn
 */

#ifndef BSLB_ABSSECBLOCK_IMPL_H_
#define BSLB_ABSSECBLOCK_IMPL_H_

#include <stddef.h>
#include <stdint.h>

#include <m-shared-ptr.h>
#include <m-array.h>
#include <qcbor/qcbor_encode.h>
#include <qcbor/qcbor_decode.h>

#include "bsl/BPSecLib_Public.h"

#include "IdValPair.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct
{
    /// Reference to the unique target
    uint64_t target_block_num;

    /// Results for just this target
    BSLB_IdValPairPtrList_t results;
} BSL_AbsSecBlock_Target_t;

/// Initialize a new target structure
void BSL_AbsSecBlock_Target_Init(BSL_AbsSecBlock_Target_t *self);
/// Deinitialize a target structure
void BSL_AbsSecBlock_Target_Deinit(BSL_AbsSecBlock_Target_t *self);

/// M*LIB OPLIST for ::BSL_AbsSecBlock_Target_t
#define M_OPL_BSL_AbsSecBlock_Target_t() \
    (INIT(API_2(BSL_AbsSecBlock_Target_Init)), INIT_SET(0), SET(0), CLEAR(API_2(BSL_AbsSecBlock_Target_Deinit)))

/**
 * @struct BSL_AbsSecBlock_TargetList_t
 * @brief Container for an array of shared pointer to ::BSL_AbsSecBlock_Target_t
 * @cite lib:mlib.
 */
// NOLINTBEGIN
/// @cond Doxygen_Suppress
// GCOV_EXCL_START
M_SHARED_WEAK_PTR_DEF(BSL_AbsSecBlock_TargetPtr, BSL_AbsSecBlock_Target_t)
#define M_OPL_BSL_AbsSecBlock_TargetPtr_t() \
    M_SHARED_PTR_OPLIST(BSL_AbsSecBlock_TargetPtr, M_OPL_BSL_AbsSecBlock_Target_t())

M_ARRAY_DEF(BSL_AbsSecBlock_TargetList, BSL_AbsSecBlock_TargetPtr_t *, M_OPL_BSL_AbsSecBlock_TargetPtr_t())
// GCOV_EXCL_STOP
/// @endcond
// NOLINTEND

enum BSL_AbsSecBlock_Flags_e
{
    BSL_ABSSECBLOCK_FLAG_HAS_PARAM = 0x1,
};

/** Represents the Abstract Security Block as defined in RFC9172
 */
struct BSL_AbsSecBlock_s
{
    /// @brief Security context id
    int64_t sec_context_id;

    /// @brief Source EID native representation, BSL host must take care of encoding/decoding.
    BSL_HostEID_t source_eid;

    /// @brief List of pointers to security parameters
    BSLB_IdValPairPtrList_t params;

    /** @brief List of targets and their parameters.
     * This is stored together internally for consistency.
     * The ASB encoded form uses separate items.
     */
    BSL_AbsSecBlock_TargetList_t target_results;
};

/** Adds a given block ID as a security target covered by this ASB
 *
 * @param[in,out] self This ASB.
 * @param[in] target_block_num ID of a block, 0 indicates primary block as usual.
 * @return The new target and its results.
 */
BSL_AbsSecBlock_Target_t *BSL_AbsSecBlock_AddTarget(BSL_AbsSecBlock_t *self, uint64_t target_block_num);

/** Remove the target and its security results from this ASB
 *
 * @param[in,out] self This ASB
 * @param[in] target_block_num Block number of the target to remove
 * @return Negative on error, otherwise count of things removed.
 */
int BSL_AbsSecBlock_StripResults(BSL_AbsSecBlock_t *self, uint64_t target_block_num);

/** Encodes this ASB into a CBOR string into the space pre-allocated indicated by the argument.
 * Matches the ::BSL_CBOR_Encode_f signature.
 *
 * @param enc The encoder to write to.
 * @param[in,out] self The initialized ASB to populate.
 */
int BSL_AbsSecBlock_Encode(QCBOREncodeContext *enc, const BSL_AbsSecBlock_t *obj);

/** Decodes and populates this ASB from a CBOR string.
 * Matches the ::BSL_CBOR_Decode_f signature.
 *
 * @param[in,out] self This allocated, but uninitialized ASB to populate.
 * @param[in] buf A buffer containing a CBOR string representing the ASB
 * @return Negative on error
 */
int BSL_AbsSecBlock_Decode(QCBORDecodeContext *dec, BSL_AbsSecBlock_t *self);

#ifdef __cplusplus
} // extern C
#endif

#endif /* BSLB_ABSSECBLOCK_IMPL_H_ */
