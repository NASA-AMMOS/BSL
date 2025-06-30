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
 * @ingroup frontend
 * Abstract interface for Security Context and associated Registry.
 */
#ifndef BSL_SC_REG_H
#define BSL_SC_REG_H

#include "AdapterTypes.h"
#include "BPSecTypes.h"
#include "BundleContext.h"
#include "LibContext.h"
#include "PolicyProvider.h"

int BSL_SecCtx_ExecutePolicyActionSet(BSL_LibCtx_t *lib, const BSL_BundleCtx_t *bundle, BSL_PolicyActionSet_t *action_set);

int BSL_SecCtx_ExecutePolicyActionSetNew(BSL_LibCtx_t *lib, BSL_PolicyResponseSet_t *output_response, BSL_BundleCtx_t *bundle, const BSL_PolicyActionSet_t *action_set);

/** Signature for Security Context validator for a sec OP.
 *
 * @param[in] lib The library context.
 * @param[in] bundle The bundle to inspect.
 * @param[in] sec_oper The security operation to perform.
 * @return True if security operation is deemed valid.
 */
typedef bool (*BSL_SecCtx_Validate_f)(BSL_LibCtx_t *lib, const BSL_BundleCtx_t *bundle, const BSL_SecOper_t *sec_oper);

/** Signature for Security Context executor for a sec OP.
 *
 * @param[in] lib The library context.
 * @param[in,out] bundle The bundle to modify.
 * @param[in] sec_oper The security operation to perform.
 * @param[in, out] sec_outcome The pre-allocated outcome to populate
 * @return 0 if security operation performed successfully.
 */
typedef int (*BSL_SecCtx_Execute_f)(BSL_LibCtx_t *lib, const BSL_BundleCtx_t *bundle, const BSL_SecOper_t *sec_oper,
                                    BSL_SecOutcome_t *sec_outcome);



#endif
