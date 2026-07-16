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
/**
 * @file IdValPair.h
 * @ingroup backend_dyn
 * @brief Defines the RFC 9172 Security Parameter of the Abstract Security Block
 *
 * @details
 *
 * The details from the RFC Section 3.6 @cite rfc9172 are as follows:
 *
 * <blockquote>
 * This field captures one or more security context parameters that should be used
 * when processing the security service described by this security block. This field
 * SHALL be represented by a CBOR array. Each entry in this array is a single security
 * context parameter. A single parameter SHALL also be represented as a CBOR array
 * comprising a 2-tuple of the Id and value of the parameter, as follows.
 *
 * **Parameter Id:**
 *  * This field identifies which parameter is being specified.
 *  * This field SHALL be represented as a CBOR unsigned integer.
 *  * Parameter Ids are selected as described in Section 3.10.
 *
 * **Parameter Value:**
 *  * This field captures the value associated with this parameter.
 *  * This field SHALL be represented by the applicable CBOR representation of the parameter, in accordance with
 * Section 3.10.
 *
 * </blockquote>
 *
 * @author Bill.Van.Besien@jhuapl.edu
 */
/** @file
 * @ingroup backend_dyn
 * @brief Declaration of an (id, value) pair container.
 */
#ifndef BSLB_IDVALPAIR_H_
#define BSLB_IDVALPAIR_H_

#include <stdint.h>

#include <m-bstring.h>
#include <m-shared-ptr.h>
#include <m-array.h>
#include <m-bptree.h>

#include "bsl/BPSecLib_Private.h"
#include "bsl/dynamic/CBOR.h"

#ifdef __cplusplus
extern "C" {
#endif

/** @brief Types of values in ::BSL_IdValPair_s.
 * Security options, parameters, and results defined in RFC9173 may be unsigned integers or bytestrings.
 */
enum BSL_IdValPair_Type_e
{
    BSL_IDVALPAIR_TYPE_UNKNOWN = 0, ///< Indicates parsed value not of expected type.
    BSL_IDVALPAIR_TYPE_INT64,       ///< Indicates value type is a signed integer.
    BSL_IDVALPAIR_TYPE_BYTESTR,     ///< Indicates the value is a byte string.
    BSL_IDVALPAIR_TYPE_TEXTSTR,     ///< Indicates the value is a text string.
    BSL_IDVALPAIR_TYPE_RAW,         ///< Indicates the value is raw encoded bytes.
};

struct BSL_IdValPair_s
{
    /// @brief Identifier for the pair
    int64_t id;

    /// @brief Indicates how #_val needs to be used.
    enum BSL_IdValPair_Type_e _type;
    /// The value storage based on #_type
    union
    {
        /// Valid when #_type is ::BSL_IDVALPAIR_TYPE_INT64
        int64_t as_int;
        /** Valid when #_type is ::BSL_IDVALPAIR_TYPE_BYTESTR or ::BSL_IDVALPAIR_TYPE_TEXTSTR
         * or ::BSL_IDVALPAIR_TYPE_RAW
         */
        m_bstring_t as_bytes;
    } _val;
};

/// OPLIST for ::BSL_IdValPair_s
#define M_OPL_BSL_IdValPair_t()                                                             \
    (INIT(API_2(BSL_IdValPair_Init)), INIT_SET(API_6(BSL_IdValPair_InitSet)), INIT_MOVE(0), \
     CLEAR(API_2(BSL_IdValPair_Deinit)), SET(API_6(BSL_IdValPair_Set)), MOVE(API_6(BSL_IdValPair_Move)))

/** Decode from CBOR, as a pair of items either in an array or from
 * a map key-value.
 * Matches the ::BSL_CBOR_Decode_f signature.
 */
int BSL_IdValPair_Decode(QCBORDecodeContext *dec, BSL_IdValPair_t *pair);

/** Encode to CBOR, as a pair of items either in an array or a map key-value.
 * Matches the ::BSL_CBOR_Encode_f signature.
 */
void BSL_IdValPair_Encode(QCBOREncodeContext *enc, const BSL_IdValPair_t *pair);

/** @struct BSLB_IdValPairPtr_t
 * Thread safe shared pointers to ::BSL_IdValPair_s instances.
 */
/** @struct BSLB_IdValPairPtrList_t
 * Defines an internal list of ::BSLB_IdValPairPtr_t pointers.
 */
/** @struct BSLB_IdValPairPtrMap_t
 * Defines an internal lookup dictionary for ::BSLB_IdValPairPtr_t pointers
 * by integer keys.
 */
// NOLINTBEGIN
/// @cond Doxygen_Suppress
// GCOV_EXCL_START
M_SHARED_PTR_DEF(BSLB_IdValPairPtr, BSL_IdValPair_t, M_OPL_BSL_IdValPair_t())
#define M_OPL_BSLB_IdValPairPtr_t() M_SHARED_PTR_OPLIST(BSLB_IdValPairPtr, M_OPL_BSL_IdValPair_t())

M_ARRAY_DEF(BSLB_IdValPairPtrList, BSLB_IdValPairPtr_t *, M_OPL_BSLB_IdValPairPtr_t())
M_BPTREE_DEF2(BSLB_IdValPairPtrMap, 4, int64_t, M_BASIC_OPLIST, BSLB_IdValPairPtr_t *, M_OPL_BSLB_IdValPairPtr_t())
// GCOV_EXCL_STOP
/// @endcond
// NOLINTEND

/** Workaround default shared-ptr INIT being a NULL pointer.
 */
static inline BSL_IdValPair_t *BSLB_IdValPairPtrMap_add(BSLB_IdValPairPtrMap_t map, int64_t key)
{
    BSLB_IdValPairPtr_t *item_ptr = BSLB_IdValPairPtr_new();

    BSL_IdValPair_t *item = BSLB_IdValPairPtr_ref(item_ptr);

    BSLB_IdValPairPtrMap_set_at(map, key, item_ptr);
    BSLB_IdValPairPtr_release(item_ptr);

    return item;
}

#ifdef __cplusplus
} // extern C
#endif

#endif /* BSLB_IDVALPAIR_H_ */
