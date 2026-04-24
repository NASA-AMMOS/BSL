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

/** @file
 * @ingroup mock_bpa
 */

#ifndef BSL_MOCK_BPA_KEY_REGISTRY_H_
#define BSL_MOCK_BPA_KEY_REGISTRY_H_

#include <inttypes.h>
#include <stdio.h>
#include <jansson.h>

#include <CryptoInterface.h>

#ifdef __cplusplus
extern "C" {
#endif

/// @brief Initialize JWKs
/// @param pp_cfg_file_path path to JSON file with JWKs
/// @return 0 if successful
int mock_bpa_key_registry_init(const char *pp_cfg_file_path);

/**
 * Custom RNG function for BCB testing
 */
int mock_bpa_rfc9173_bcb_cek(unsigned char *buf, int len);

#ifdef __cplusplus
} // extern C
#endif

#endif
