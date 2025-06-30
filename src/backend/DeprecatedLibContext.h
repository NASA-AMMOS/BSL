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
 * Private interface for the dynamic backend library context.
 * @ingroup backend_dyn
 */
#ifndef BSL_CTX_DYN_H_
#define BSL_CTX_DYN_H_

#include "DynCrypto.h"

#include <AdapterTypes.h>
#include <BPSecTypes.h>
#include <BundleContext.h>
#include <DeprecatedTypes.h>
#include <PolicyProvider.h>
#include <SecurityContext.h>

#include <m-bptree.h>
#include <m-dict.h>
#include <m-list.h>
#include <m-mempool.h>
#include <m-shared.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Policy Provider descriptor.
 */
typedef struct
{
    /// User data pointer for callbacks
    void *user_data;
    /// Callback to inspect a specific bundle for actions.
    BSL_PolicyInspect_f inspect;
    /// Callback to finalize actions from this PP
    BSL_PolicyFinalize_f finalize;
} BSL_PolicyDesc_t;

/** Security Context descriptor.
 */
typedef struct BSL_SecCtxDesc_s
{
    /// User data pointer for callbacks
    void *user_data;

    /// Callback to validate a sec op within a given bundle
    BSL_SecCtx_Validate_f validate;
    /// Callback to execute a sec op within a given bundle
    BSL_SecCtx_Execute_f execute;
} BSL_SecCtxDesc_t;

// NOLINTBEGIN
/// @cond Doxygen_Suppress
/// Stable list of PP descriptors
LIST_DEF(BSL_PolicyDescList, BSL_PolicyDesc_t, M_POD_OPLIST)
/// Stable dict of security context descriptors (key: context id | value: descriptor struct)
DICT_DEF2(BSL_SecCtxDict, uint64_t, M_BASIC_OPLIST, BSL_SecCtxDesc_t, M_POD_OPLIST)
/// Pool of BSL_PolicyActionDeprecated_t
MEMPOOL_DEF(BSL_PolicyActionPool, BSL_PolicyActionDeprecated_t)
/// @endcond
// NOLINTEND

/** Concrete definition of library context.
 */
struct BSL_LibCtx_s
{
    /// Policy Provider registry
    BSL_PolicyDescList_t pp_reg;

    BSL_PolicyProvider_t *policy_provider;
    /// Sec Context registry
    BSL_SecCtxDict_t sc_reg;
    /// PP Action memory pool
    BSL_PolicyActionPool_t action_pool;
};

/** Add a Policy Provider descriptor to the registry.
 *
 * @param lib The library instance to add to.
 * @param desc The descriptor to add.
 * @return Zero if successful.
 */
int BSL_LibCtx_AddPolicyProvider(BSL_LibCtx_t *lib, BSL_PolicyDesc_t desc);

/** Add a Security Context descriptor to the registry.
 *
 * @param lib The library instance to add to.
 * @param sec_ctx_id Security context ID corresponding to descriptor
 * @param desc The descriptor to add.
 * @return Zero if successful.
 */
int BSL_LibCtx_AddSecurityContext(BSL_LibCtx_t *lib, uint64_t sec_ctx_id, BSL_SecCtxDesc_t desc);
#ifdef __cplusplus
} // extern C
#endif

#endif // BSL_CTX_DYN_H_
