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
/**
 * @file
 * @ingroup backend_dyn
 * @brief Defines interactions with an external Telemetry Handler.
 */
#include <BPSecLib_Private.h>

#include "PublicInterfaceImpl.h"


size_t BSL_TlmHandler_ResetCounters(const BSL_LibCtx_t *bsl)
{
    CHK_ARG_NONNULL(bsl);
    bsl->tlm_handler.reset_fn();
    return BSL_SUCCESS;
}

size_t BSL_TlmHandler_RetrieveCounter(const BSL_LibCtx_t *bsl, BSL_TelemetryType_e tlm_type)
{
    CHK_ARG_NONNULL(bsl);
    return bsl->tlm_handler.retrieve_fn(tlm_type);
}

size_t BSL_TlmHandler_IncrementCounter(const BSL_LibCtx_t *bsl, BSL_TelemetryType_e tlm_type)
{
    CHK_ARG_NONNULL(bsl);
    bsl->tlm_handler.increment_fn(tlm_type);
    return BSL_SUCCESS;
}
