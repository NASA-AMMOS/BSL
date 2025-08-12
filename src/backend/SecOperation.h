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
 * @file
 * @ingroup backend_dyn
 * @brief Defines a security operation.
 */
#ifndef BSLB_SECOPERATIONS_H_
#define BSLB_SECOPERATIONS_H_

#include <stdint.h>

#include <m-i-list.h>

#include <BPSecLib_Private.h>

#include "SecParam.h"

struct BSL_SecOper_s
{
    /// @brief Security context ID
    uint64_t context_id;

    /// @brief Bundle's block ID over which the security operation is applied.
    uint64_t target_block_num;

    /// @brief Bundle's block ID which contains the security parameters and results for this operation.
    uint64_t sec_block_num;

    /// @brief Code for handing what to do to the block or bundle if security processing fails.
    BSL_PolicyAction_e failure_code;

    /// @brief Conclusion state of security operation processing
    BSL_SecOper_ConclusionState_e conclusion;

    /// @brief Private enumeration indicating the role (e.g., acceptor vs verifier)
    BSL_SecRole_e       _role;
    BSL_SecBlockType_e  _service_type;
    BSLB_SecParamList_t _param_list;

    ILIST_INTERFACE (BSL_SecOperList, struct BSL_SecOper_s);
};

#endif /* BSLB_SECOPERATIONS_H_ */
