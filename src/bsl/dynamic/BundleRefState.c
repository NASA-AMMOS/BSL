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
 * @brief Definition of bundle reference state.
 */
#include "BundleRefState.h"

#include "bsl/BPSecLib_Private.h"

void BSL_BundleRefState_Init(BSL_BundleRefState_t *obj)
{
    // GCOV_EXCL_START
    ASSERT_ARG_NONNULL(obj);
    // GCOV_EXCL_STOP
    obj->_placeholder = 1;
}

void BSL_BundleRefState_Deinit(BSL_BundleRefState_t *obj)
{
    // GCOV_EXCL_START
    ASSERT_ARG_NONNULL(obj);
    // GCOV_EXCL_STOP
}
