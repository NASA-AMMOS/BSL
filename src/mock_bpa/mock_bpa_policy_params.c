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

#include "mock_bpa_policy_params.h"


void mock_bpa_policy_params_init(mock_bpa_policy_params_t *params, int policy_num)
{
    params->param_integ_scope_flag = calloc(BSL_SecParam_Sizeof(), 1);
    params->param_sha_variant = calloc(BSL_SecParam_Sizeof(), 1);
    params->param_aad_scope_flag = calloc(BSL_SecParam_Sizeof(), 1);
    params->param_init_vector = calloc(BSL_SecParam_Sizeof(), 1);
    params->param_aes_variant = calloc(BSL_SecParam_Sizeof(), 1);
    params->param_test_key = calloc(BSL_SecParam_Sizeof(), 1);
    params->param_use_wrapped_key = calloc(BSL_SecParam_Sizeof(), 1);

    params->active = true;

    BSL_LOG_DEBUG("Successfully Init policy number %d in registry\n", policy_num);
}

void mock_bpa_policy_params_deinit(mock_bpa_policy_params_t *params, int policy_num)
{
    free(params->param_integ_scope_flag);
    free(params->param_sha_variant);
    free(params->param_aad_scope_flag);
    free(params->param_init_vector);
    free(params->param_aes_variant);
    free(params->param_test_key);
    free(params->param_use_wrapped_key);

    params->active = false;

    BSL_LOG_DEBUG("Successfully De-init policy number %d in registry\n", policy_num);
}