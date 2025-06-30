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
 *
 * @details
 *
 * Forthcoming.
 *
 * @author Bill.Van.Besien@jhuapl.edu
 */
#ifndef BSLB_SECOUTCOME_H_
#define BSLB_SECOUTCOME_H_

#include <BPSecLib_Private.h>

#include "SecParam.h"
#include "SecResult.h"

struct BSL_SecOutcome_s
{
    /// @brief Boolean indicating true when successful
    bool is_success;

    /// @brief Pre-allocated memory pool, lifetimes of all results and parameters are tied to this.
    BSL_Data_t allocation;

    /// @brief Non-NULL pointer to Security Operation that provided the input.
    const BSL_SecOper_t *sec_oper;

    /// @brief List of security parameters with metadata for receiver. Must be encoded into the BTSD.
    BSLB_SecParamList_t param_list;

    /// @brief List of security results with metadata for receiver. Must be encoded into BTSD.
    BSLB_SecResultList_t result_list;
};

#endif /* BSLB_SECOUTCOME_H_ */
