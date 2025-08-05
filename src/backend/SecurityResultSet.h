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
 * @brief SecurityResultSet implementation for result after application of security operations.
 * @ingroup backend_dyn
 */
#ifndef BSLB_SECURITYRESULTSET_H_
#define BSLB_SECURITYRESULTSET_H_

#include <BPSecLib_Private.h>

#define BSL_SECURITYRESPONSESET_ARRAYLEN (10)
#define BSL_SECURITYRESPONSESET_STRLEN   (256)

/// @brief Contains the results and outcomes after performing the security operations.
/// @note This struct is still in-concept
struct BSL_SecurityResponseSet_s
{
    /// @brief This maps to the sec_operations in BSL_SecurityActionSet,
    ///        and contains the result code of that security operation.
    int    results[BSL_SECURITYRESPONSESET_ARRAYLEN];
    char   err_msg[BSL_SECURITYRESPONSESET_STRLEN];
    BSL_PolicyAction_e err_action_codes[BSL_SECURITYRESPONSESET_ARRAYLEN];
    int    err_code;
    size_t total_operations;
    size_t failure_count;
};

#endif /* BSLB_SECURITYRESULTSET_H_ */
