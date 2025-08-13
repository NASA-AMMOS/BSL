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
 * Data structure and calls for the mock bpa policy registry memory pool
 * @ingroup mock_bpa
 */

#ifndef MOCK_BPA_POLICY_REGISTRY_H_
#define MOCK_BPA_POLICY_REGISTRY_H_

#include <BPSecLib_Private.h>

#include "policy_params.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MOCK_BPA_MAX_POLICIES 100

typedef struct mock_bpa_policy_registry
{
    mock_bpa_policy_params_t registry_params[MOCK_BPA_MAX_POLICIES];
    bool                     in_use[MOCK_BPA_MAX_POLICIES];
    int                      registry_count;
} mock_bpa_policy_registry_t;

void mock_bpa_policy_registry_init(mock_bpa_policy_registry_t *registry);

int mock_bpa_policy_registry_size(mock_bpa_policy_registry_t *registry);

mock_bpa_policy_params_t *mock_bpa_policy_registry_get(mock_bpa_policy_registry_t *registry);

void mock_bpa_policy_registry_deinit(mock_bpa_policy_registry_t *registry);

#ifdef __cplusplus
} // extern C
#endif

#endif // MOCK_BPA_POLICY_REGISTRY_H_
