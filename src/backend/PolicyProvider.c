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
 * @brief Defines interactions with an external Policy Provider.
 */
#include <BPSecLib_Private.h>

#include "PublicInterfaceImpl.h"

int BSL_PolicyRegistry_InspectActions(const BSL_LibCtx_t *bsl, BSL_SecurityActionSet_t *output_action_set,
                                      const BSL_BundleRef_t *bundle, BSL_PolicyLocation_e location)
{
    // TODO - this should just check the policy_registry to see what is there,.
    // and if it's present then just call the callbacks and pass through the arguments.
    CHK_ARG_NONNULL(bsl);
    CHK_ARG_NONNULL(output_action_set);
    CHK_ARG_NONNULL(bundle);
    CHK_PRECONDITION(bsl->policy_registry.query_fn != NULL);
    return bsl->policy_registry.query_fn(bsl->policy_registry.user_data, output_action_set, bundle, location);
}
