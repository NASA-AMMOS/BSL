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
 * @file SecResult.h
 * @ingroup backend_dyn
 * @brief Defines the RFC 9172 Security Result
 *
 * @details
 * This represents the Security Result field of the Abstract Security Block. As
 * defined in RFC 9172.
 *
 * <blockquote>
 * An individual result is represented as a CBOR array comprising a 2-tuple of a result
 * Id and a result value, defined as follows.
 *
 * Result Id:
 *
 *   * This field identifies which security result is being specified.
 *   * Some security results capture the primary output of a cipher suite.
 *   * Other security results contain additional annotative information from cipher suite processing.
 *   * This field SHALL be represented as a CBOR unsigned integer.
 *   * Security result Ids will be as specified in Section 3.10.
 *
 * Result Value:
 *
 *   * This field captures the value associated with the result.
 *   * This field SHALL be represented by the applicable CBOR representation of the result value, in accordance with
 * Section 3.10.
 * </blockquote>
 *
 * RFC 9172 **Section 3.10**
 * <blockquote>
 *  * Each security context MUST define its own context parameters and results.
 *  * Each defined parameter and result is represented as the tuple of an identifier and a value.
 *  * Identifiers are always represented as a CBOR unsigned integer.
 *  * The CBOR encoding of values is as defined by the security context specification.
 *  * Identifiers MUST be unique for a given security context but do not need to be unique amongst all security
 * contexts.
 * </blockquote>
 *
 * https://www.rfc-editor.org/rfc/rfc9172.html#section-3.6-3.12.1
 *
 * @author Bill.Van.Besien@jhuapl.edu
 */
/** @file
 * @brief Implementation of a RFC9172 Result
 * @ingroup backend_dyn
 */
#ifndef BSLB_SECRESULT_H_
#define BSLB_SECRESULT_H_

#include <stdint.h>

#include <m-array.h>

#include <BPSecLib_Private.h>

struct BSL_SecResult_s
{
    /// @brief Result ID, which is context dependent, based on security context.
    uint64_t result_id;

    /// @brief Context ID, put in here for convenience.
    int64_t context_id;

    /// @brief Target block id, put in here for convenience.
    uint64_t target_block_num;

    /// @brief Result as byte array, up to a given maximum
    uint8_t _bytes[BSL_DEFAULT_BYTESTR_LEN + 1];

    /// @brief Length of data (in bytes) of the contained bytestring. Always less than BSL_DEFAULT_BYTESTR_LEN.
    size_t _bytelen;
};

/** @struct BSLB_SecResultList_t
 * Defines a basic list of Security Results (::BSL_SecResult_t).
 */
// NOLINTBEGIN
/// @cond Doxygen_Suppress
M_ARRAY_DEF(BSLB_SecResultList, BSL_SecResult_t, M_POD_OPLIST)
/// @endcond
// NOLINTEND

#endif /* BSLB_SECRESULT_H_ */
