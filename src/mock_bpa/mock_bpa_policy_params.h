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
 * Data structure and calls for the mock bpa policy params
 * @ingroup mock_bpa
 */

#ifndef MOCK_BPA_POLICY_PARAMS_H_
#define MOCK_BPA_POLICY_PARAMS_H_

#include <BPSecLib_Private.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct mock_bpa_policy_params
{
    // Params related to BIB
    BSL_SecParam_t *param_integ_scope_flag;
    BSL_SecParam_t *param_sha_variant;

    // Params related to BCB
    BSL_SecParam_t *param_aad_scope_flag;
    BSL_SecParam_t *param_init_vector;
    BSL_SecParam_t *param_aes_variant;
    BSL_SecParam_t *param_key_enc_key;

    // Params agnostic to BIB vs BCB
    BSL_SecParam_t *param_test_key;

    bool active;
} mock_bpa_policy_params_t;

void mock_bpa_policy_params_init(mock_bpa_policy_params_t *params, int policy_num);

void mock_bpa_policy_params_deinit(mock_bpa_policy_params_t *params, int policy_num);

#ifdef __cplusplus
} // extern C
#endif

#endif // MOCK_BPA_POLICY_PARAMS_H_