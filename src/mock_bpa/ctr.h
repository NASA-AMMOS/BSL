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
#ifndef BSL_MOCK_BPA_CTR_H_
#define BSL_MOCK_BPA_CTR_H_

#include "bundle.h"
#include <BPSecLib_Private.h>
#include <BPSecLib_Public.h>

#include <m-core.h>

/// A container for encoded and decoded bundle data
typedef struct
{
    /// Encoded PDU
    BSL_Data_t encoded;
    /// The decoded bundle
    MockBPA_Bundle_t *bundle;
    /// External reference to #bundle
    BSL_BundleRef_t bundle_ref;
} mock_bpa_ctr_t;

void mock_bpa_ctr_init(mock_bpa_ctr_t *ctr);

void mock_bpa_ctr_init_move(mock_bpa_ctr_t *ctr, mock_bpa_ctr_t *src);

void mock_bpa_ctr_deinit(mock_bpa_ctr_t *ctr);

int mock_bpa_decode(mock_bpa_ctr_t *ctr);

int mock_bpa_encode(mock_bpa_ctr_t *ctr);

#define M_OPL_mock_bpa_ctr_t() \
    (INIT(API_2(mock_bpa_ctr_init)), INIT_MOVE(API_6(mock_bpa_ctr_init_move)), CLEAR(API_2(mock_bpa_ctr_deinit)))

#endif /* BSL_MOCK_BPA_CTR_H_ */
