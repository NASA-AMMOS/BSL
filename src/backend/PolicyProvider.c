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
#include "SecurityActionSet.h"

int BSL_PolicyRegistry_InspectActions(const BSL_LibCtx_t *bsl, BSL_SecurityActionSet_t *output_action_set,
                                      const BSL_BundleRef_t *bundle, BSL_PolicyLocation_e location)
{
    CHK_ARG_NONNULL(bsl);
    CHK_ARG_NONNULL(bsl->policy_reg);
    CHK_ARG_NONNULL(output_action_set);
    CHK_ARG_NONNULL(bundle);

    BSL_PolicyDict_it_t policy_reg_it;
    for (BSL_PolicyDict_it(policy_reg_it, bsl->policy_reg); !BSL_PolicyDict_end_p(policy_reg_it);
         BSL_PolicyDict_next(policy_reg_it))
    {
        size_t act_ct = BSL_SecurityActionSet_CountActions(output_action_set);

        const BSL_PolicyDesc_t *policy = BSL_PolicyDict_cref(policy_reg_it)->value_ptr;
        BSL_LOG_INFO("Inspecting PP (id %" PRIu64 ")", *BSL_PolicyDict_cref(policy_reg_it)->key_ptr);
        if (BSL_SUCCESS != policy->query_fn(policy->user_data, output_action_set, bundle, location))
        {
            return BSL_ERR_POLICY_FINAL;
        }

        size_t new_act_ct = BSL_SecurityActionSet_CountActions(output_action_set);
        for (size_t i = act_ct; i < new_act_ct; i++)
        {
            BSL_SecurityAction_t *act = BSL_SecActionList_get(output_action_set->actions, i);
            act->pp_id                = *BSL_PolicyDict_cref(policy_reg_it)->key_ptr;
        }
    }

    return BSL_SUCCESS;
}

int BSL_PolicyRegistry_FinalizeActions(const BSL_LibCtx_t *bsl, const BSL_SecurityActionSet_t *policy_actions,
                                       const BSL_BundleRef_t *bundle, const BSL_SecurityResponseSet_t *response_output)
{
    CHK_ARG_NONNULL(bsl);
    CHK_ARG_NONNULL(bsl->policy_reg);
    CHK_ARG_NONNULL(policy_actions);
    CHK_ARG_NONNULL(response_output);
    CHK_ARG_NONNULL(bundle);

    BSL_LOG_DEBUG("BEGINNING OF BACKEND POLICY FINALIZE FUNCTION");

    size_t act_ct = BSL_SecurityActionSet_CountActions(policy_actions);
    BSL_LOG_DEBUG("NUMBER OF ACTIONS: %d", act_ct);
    for (size_t i = 0; i < act_ct; i++)
    {
        BSL_LOG_DEBUG("GETTING ACTION FROM LIST: %d", i);
        BSL_SecurityAction_t *act = BSL_SecActionList_get(policy_actions->actions, i);

        BSL_LOG_DEBUG("RETRIEVING POLICY FOR ACTION POLICY: %d", act->pp_id);
        const BSL_PolicyDesc_t *policy = BSL_PolicyDict_get(bsl->policy_reg, act->pp_id);
        BSL_LOG_DEBUG("SUCCESSFULLY RETREIVED THE POLICY");
        if (BSL_SUCCESS != policy->finalize_fn(policy->user_data, policy_actions, bundle, response_output))
        {
            return BSL_ERR_POLICY_FINAL;
        }
    }

    return BSL_SUCCESS;
}
