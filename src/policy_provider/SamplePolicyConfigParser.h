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
#include <inttypes.h>
#include <stdio.h>
#include <jansson.h>

#include <BPSecLib_Private.h>
#include <CryptoInterface.h>
#include <security_context/rfc9173.h>

#include "SamplePolicyProvider.h"

typedef struct BSLP_InitParams_s
{
    // Params related to BIB
    BSL_SecParam_t *param_integ_scope_flag;
    BSL_SecParam_t *param_sha_variant;

    // Params related to BCB
    BSL_SecParam_t *param_aad_scope_flag;
    BSL_SecParam_t *param_init_vector;
    BSL_SecParam_t *param_aes_variant;
    BSL_SecParam_t *param_use_wrapped_key;

    // Params agnostic to BIB vs BCB
    BSL_SecParam_t *param_test_key;
} BSLP_InitParams_t;

/**
 * Initialize local policy provider parameters
 * @param[in,out] params structure to initialize
 */
int BSLP_InitParams_Init(BSLP_InitParams_t *params);

/**
 * Deinitialize local policy provider parameters
 * @param[in] params structure to deinitialize
 */
void BSLP_InitParams_Deinit(BSLP_InitParams_t *params);

/**
 * Initialize local policy provider from JSON file
 * @param[in] policy_cfg_path path to JSON file containing policy configuration
 * @param[in,out] policy policy provider to configure. Must be initialize/allocated
 */
int BSLP_RegisterPolicyFromJSON(const char *policy_cfg_path, BSLP_PolicyProvider_t *policy);

/** Bitwise Diagram of the mock bpa config data structure:
 * @code{.unparsed}
 *                      uint32_t : bsl_mock_policy_configuration_t
 *
 *             [  x   x   x   x  |  x   x   x   x  |  x   x   x   x  |  x   x   x   x ]
 *             [ --------- unused -------]  |   |     [---]   [---]     [---]   |   |
 *                                          |   |       |       |         |     |   |
 *           "Don't care": set EIDs s.t.   -|   |       |       |         |     |   |
 *           bundle doens't match any rule -|   |       |       |         |     |   |
 *                                              |       |       |         |     |   |
 *                     Use Wrapped Key for BCB -|       |       |         |     |   |
 *                                                      |       |         |     |   |
 *              BSL Role: 00 - source, 01 - verifier,  -|       |         |     |   |
 *                        10 - acceptor, 11: undefined -|       |         |     |   |
 *                                                              |         |     |   |
 *              Policy Action: 00 - nothing, 01 - drop block,  -|         |     |   |
 *                             10 - drop bundle, 11: undefined -|         |     |   |
 *                                                                        |     |   |
 *                       Target Block Type: 00 - primary, 01 - payload,  -|     |   |
 *                      10 - private/experimental (192), 11 - bundle age -|     |   |
 *                                                                              |   |
 *                                                    Target Block Type: -|     |   |
 *                                        Policy Location: 0 - CLOUT, 1 - CLIN -|   |
 *                                                                                  |
 *                                                Sec Block Type: 0 - BIB, 1 - BCB -|
 *
 *
 * @endcode
 */
typedef uint32_t BSLP_BitstringPolicyConfiguration_t;

/**
 * Initialize local policy provider from list of bit strings
 * @param[in] policies comma separated policy bit strings as described by @ref BSLP_BitstringPolicyConfiguration_t
 * @param[in,out] policy policy provider to configure. Must be initialize/allocated
 */
int BSLP_RegisterPolicyFromBitstringList(const char *policies, BSLP_PolicyProvider_t *policy);
