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
 * @file
 * @ingroup sample_pp
 * Configuration file readers for the sample policy provider of the BSL.
 */
#ifndef BSLP_POLICY_PARSER_H_
#define BSLP_POLICY_PARSER_H_

#include "SamplePolicyProvider.h"

#include "bsl/BPSecLib_Private.h"
#include "bsl/default_sc/rfc9173.h"

#include <inttypes.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

/// @brief Rule update behavior to use when loading a policy config file
typedef enum
{
    /// @brief Add new rules and replace matching IDs, retaining all other rules
    BSLP_POLICY_LOAD_ADDITIVE = 0,
    /// @brief Remove all rules before loading the file
    BSLP_POLICY_LOAD_CLEAN,
    /// @brief Add or replace file rules, then remove rules whose IDs are absent from the file
    BSLP_POLICY_LOAD_FULL_SPEC
} BSLP_PolicyParser_LoadMode_e;

/**
 * Initialize local policy provider from JSON file.
 * @param[in] file_path File path to open and read JSON containing policy configuration.
 * @param[in,out] policy Policy provider to configure. Must be initialize/allocated before calling.
 * This is equivalent to calling ::BSLP_PolicyParser_LoadFileWithMode with ::BSLP_POLICY_LOAD_ADDITIVE.
 * @return BSL_SUCCESS if successful.
 */
int BSLP_PolicyParser_LoadFile(const char *file_path, BSLP_PolicyProvider_t *policy);

/** Load policy configuration from a JSON file with explicit rule-set behavior.
 * @param[in] file_path File path to open and read.
 * @param[in,out] policy Policy provider to configure.
 * @param mode Rule-set loading behavior.
 * @return BSL_SUCCESS if successful.
 */
int BSLP_PolicyParser_LoadFileWithMode(const char *file_path, BSLP_PolicyProvider_t *policy,
                                       BSLP_PolicyParser_LoadMode_e mode);

/** Read policy from a file descriptor using ::BSLP_POLICY_LOAD_ADDITIVE.
 * @overload
 */
int BSLP_PolicyParser_LoadFd(int infd, BSLP_PolicyProvider_t *policy);

/** Read policy from a file descriptor with explicit rule-set behavior. */
int BSLP_PolicyParser_LoadFdWithMode(int infd, BSLP_PolicyProvider_t *policy, BSLP_PolicyParser_LoadMode_e mode);

/** Bitwise Diagram of the mock bpa config data structure:
 * @code{.unparsed}
 *                      uint32_t : BSLP_PolicyParser_BitstringConfig_t
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
typedef uint32_t BSLP_PolicyParser_BitstringConfig_t;

/**
 * Initialize local policy provider from list of bit strings
 * @param[in] policies comma separated policy bit strings as described by @ref BSLP_PolicyParser_BitstringConfig_t
 * @param[in,out] policy policy provider to configure. Must be initialize/allocated
 */
int BSLP_PolicyParser_FromBitstringList(const char *policies, BSLP_PolicyProvider_t *policy);

#ifdef __cplusplus
} // extern C
#endif

#endif /* BSLP_POLICY_PARSER_H_ */
