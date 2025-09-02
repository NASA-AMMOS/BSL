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
 * @brief Security Result Set implementation for result after application of security operations.
 * @ingroup backend_dyn
 */
#ifndef BSLB_SECURITYRESULTSET_H_
#define BSLB_SECURITYRESULTSET_H_

#include <BPSecLib_Private.h>

#include <m-array.h>

// NOLINTBEGIN
/// @cond Doxygen_Suppress
M_ARRAY_DEF(BSL_SecResultSet_ResultCodes, int64_t, M_POD_OPLIST)
M_ARRAY_DEF(BSL_SecResultSet_ErrorActionCodes, BSL_PolicyAction_e, M_POD_OPLIST)
/// @endcond
// NOLINTEND

/// @brief Contains the results and outcomes after performing the security operations.
/// @note This struct is still in-concept
struct BSL_SecurityResponseSet_s
{
    /// @brief This maps to the Security Action sec_op_list,
    ///        and contains the result code of that security operation.
    BSL_SecResultSet_ResultCodes_t      results;
    BSL_SecResultSet_ErrorActionCodes_t err_action_codes;
    size_t                              total_operations;
    size_t                              failure_count;
};

#endif /* BSLB_SECURITYRESULTSET_H_ */
