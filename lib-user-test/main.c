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
 * A do-nothing executable which builds and links with the BSL and its dependencies
 */

#include <bsl/BPSecLib_Public.h>
#include <bsl/BPSecLib_Private.h>
#include <bsl/default_sc/DefaultSecContext.h>
#include <bsl/cose_sc/CoseContext.h>
#include <bsl/sample_pp/SamplePolicyProvider.h>
#include <bsl/sample_pp/PolicyParser.h>

int main(int argc, char *argv[])
{
    BSL_LibCtx_t *bsl = BSL_malloc(BSL_LibCtx_Sizeof());

    if (BSL_API_InitLib(bsl))
    {
        BSL_LOG_ERR("Failed BSL_API_InitLib()");
        return 2;
    }
    else
    {
        BSL_LOG_INFO("Succeeded BSL_API_InitLib()");
    }

    if (BSL_API_DeinitLib(bsl))
    {
        BSL_LOG_ERR("Failed BSL_API_DeinitLib()");
    }
    else
    {
        BSL_LOG_INFO("Succeeded BSL_API_DeinitLib()");
    }
    BSL_free(bsl);

    return 0;
}
