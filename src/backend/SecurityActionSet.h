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
 * @brief Implementation of construct holding details of security operations for a bundle
 * @ingroup backend_dyn
 */
#ifndef BSLB_SECACTIONSET_H_
#define BSLB_SECACTIONSET_H_

#include <BPSecLib_Private.h>
#include "SecurityAction.h"

/** @struct BSL_SecActionList_t
 * Defines a basic list of ::BSL_SecurityAction_t.
 */
/// @cond Doxygen_Suppress
// NOLINTBEGIN
// GCOV_EXCL_START
M_ARRAY_DEF(BSL_SecActionList, BSL_SecurityAction_t,
            (INIT(API_2(BSL_SecurityAction_Init)), INIT_SET(API_6(BSL_SecurityAction_InitSet)), SET(0),
             CLEAR(API_2(BSL_SecurityAction_Deinit))))
// GCOV_EXCL_STOP
// NOLINTEND
/// @endcond

/// @brief Contains the populated security operations for this bundle.
/// @note This is intended to be a write-once, read-only struct
struct BSL_SecurityActionSet_s
{
    BSL_SecActionList_t actions;
    size_t              action_count;
    size_t              err_count;
    size_t              operation_count;
};

#endif /* BSLB_SECACTIONSET_H_ */
