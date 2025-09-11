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
#include <m-array.h>

#include <BPSecLib_Public.h>

#include "SecParam.h"
#include "SecResult.h"

/**
 * @struct uint64_list_t
 * @brief Container for an MLib array of uint64_t
 * @cite lib:mlib.
 */
// NOLINTBEGIN
/// @cond Doxygen_Suppress
// GCOV_EXCL_START
M_ARRAY_DEF(uint64_list, uint64_t)
// GCOV_EXCL_STOP
/// @endcond
// NOLINTEND

/** Represents the Abstract Security Block as defined in RFC9172
 *
 */
struct BSL_AbsSecBlock_s
{
    /// @brief List of target block ids.
    uint64_list_t targets;

    /// @brief Security context id
    int64_t sec_context_id;

    /// @brief Source EID native representation, BSL host must take care of encoding/decoding.
    BSL_HostEID_t source_eid;

    /// @brief List of pointers to security parameters
    BSLB_SecParamList_t params;

    /// @brief List of pointers to security results.
    BSLB_SecResultList_t results;
};

#endif /* BSLB_ABSSECBLOCK_IMPL_H_ */
