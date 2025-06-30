/*
 * Copyright (c) 2024 The Johns Hopkins University Applied Physics
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
 * Implementation of the dynamic backend library context.
 */
#include <inttypes.h>

#include <BPSecTypes.h>
#include <AdapterTypes.h>
#include <Logging.h>
#include <SecurityContext.h>
#include <TypeDefintions.h>

#include "DeprecatedLibContext.h"
#include "DynBundleContext.h"

// FIXME TODO - This is covering too much ground.

int BSL_LibCtx_Init(BSL_LibCtx_t *lib)
{
    BSL_PolicyDescList_init(lib->pp_reg);
    BSL_SecCtxDict_init(lib->sc_reg);
    BSL_PolicyActionPool_init(lib->action_pool);
    return 0;
}

int BSL_LibCtx_Deinit(BSL_LibCtx_t *lib)
{
    BSL_PolicyActionPool_clear(lib->action_pool);
    if (lib->policy_provider != NULL)
    {
        BSL_PolicyProvider_Deinit(lib->policy_provider);
        free(lib->policy_provider);
    }
    BSL_PolicyDescList_clear(lib->pp_reg);
    BSL_SecCtxDict_clear(lib->sc_reg);
    return 0;
}

int BSL_LibCtx_AddPolicyProvider(BSL_LibCtx_t *lib, BSL_PolicyDesc_t desc)
{
    if (!lib)
    {
        return 1;
    }
    if (!desc.inspect)
    {
        return 1;
    }
    BSL_PolicyDescList_push_back(lib->pp_reg, desc);
    return 0;
}

int BSL_LibCtx_AddSecurityContext(BSL_LibCtx_t *lib, uint64_t sec_ctx_id, BSL_SecCtxDesc_t desc)
{
    if (!lib)
    {
        return 1;
    }
    if (!desc.validate)
    {
        return 1;
    }
    if (!desc.execute)
    {
        return 1;
    }

    BSL_SecCtxDict_set_at(lib->sc_reg, sec_ctx_id, desc);
    return 0;
}