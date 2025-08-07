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
 * Definitions for permutations of policy configurations.
 * @ingroup mock_bpa
 */

#ifndef BSL_MOCK_BPA_POLICY_CONFIG_H_
#define BSL_MOCK_BPA_POLICY_CONFIG_H_

#include <inttypes.h>
#include <stdio.h>
#include <jansson.h>

#include <BPSecLib_Private.h>
#include <policy_provider/SamplePolicyProvider.h>
#include <security_context/rfc9173.h>
#include <CryptoInterface.h>

#include "mock_bpa_policy_registry.h"

#ifdef __cplusplus
extern "C" {
#endif

/// -----------------    Bitwise Diagram of the mock bpa config data structure    --------------------
/*
 *                      uint32_t : bsl_mock_policy_configuration_t
 *
 *             [  x   x   x   x  |  x   x   x   x  |  x   x   x   x  |  x   x   x   x ]
 *             [ ------------- unused -------]  |     [---]   [---]     [---]   |   |
 *                                              |       |       |         |     |   |
 *                     Use Wrapped Key for BCB -|       |       |         |     |   |
 *              BSL Role: 00 - source, 01 - verifier,  -|       |         |     |   |
 *                        10 - acceptor, 11: undefined -|       |         |     |   |
 *              Policy Action: 00 - nothing, 01 - drop block,  -|         |     |   |
 *                             10 - drop bundle, 11: undefined -|         |     |   |
 *                                                    Target Block Type: -|     |   |
 *                                        Policy Location: 0 - CLOUT, 1 - CLIN -|   |
 *                                                Sec Block Type: 0 - BIB, 1 - BCB -|
 *
 *
*/
typedef uint32_t bsl_mock_policy_configuration_t;

void mock_bpa_handle_policy_config(char *policies, BSLP_PolicyProvider_t *policy, mock_bpa_policy_registry_t *reg);

void mock_bpa_handle_policy_config_from_json(const char *pp_cfg_file_path, BSLP_PolicyProvider_t *policy);

int mock_bpa_key_registry_init(const char *pp_cfg_file_path);

int mock_bpa_hexchar_to_int(char c);

int mock_bpa_hexstring_to_bytes(const char *hexstr, uint8_t *out, size_t out_size);

#ifdef __cplusplus
} // extern C
#endif

#endif // BSL_MOCK_BPA_POLICY_CONFIG_H_
