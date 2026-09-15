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
 * @ingroup backend_dyn
 * @brief Declaration of BSL state within bundle references.
 */
#ifndef BSLB_BUNDLEREFSTATE_H_
#define BSLB_BUNDLEREFSTATE_H_

#include "AbsSecBlock.h"

#include <m-dict.h>
#include <m-shared-ptr.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct BSL_BundleRefState_s
{
    /// unused placeholder state
    int _placeholder;
} BSL_BundleRefState_t;

/** Initialize an empty reference state.
 * @param[out] obj The struct to initialize.
 */
void BSL_BundleRefState_Init(BSL_BundleRefState_t *obj);

/** De-initialize an empty reference state.
 * @param[in] obj The struct to de-initialize.
 */
void BSL_BundleRefState_Deinit(BSL_BundleRefState_t *obj);

#ifdef __cplusplus
} // extern C
#endif

#endif /* BSLB_BUNDLEREFSTATE_H_ */
