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
 *
 * Interface of Policy Provider actions and other structures.
 *
 * The key API functions exposed here are as followed
 * * <pre>BSL_PolicyProvider_InspectActions</pre> 
 *   This queries the policy provider to populate an ActionSet containing the security operations
 *   to perform on this bundle.
 *   **Note!** This function function is effectively **const**. It does not mutate the bundle in any way.
 * * <pre>BSL_PolicyProvider_FinalizeActions</pre> 
 *   This performs the security operations from the ActionSet parameter to manipulate the bundle, such
 *   as mutating the ASB to add or remove results and parameters, or even add or remove blocks.
 * 
 * Inspect: (Bundle, Location) -> PolicyActionSet
 * Finalize: (Bundle, PolicyResponseSet) -> Bundle`
 * 
 * Sec Context Verify: (Bundle, PolicyActionSet) -> bool
 * Sec Context Execute: (Bundle, PolicyActionSet) -> PolicyResponseSet, Bundle`
 */
#ifndef BSL_PP_ACTION_H_
#define BSL_PP_ACTION_H_

#include "BundleContext.h"
#include "BPSecTypes.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Indicates where in the lifecycle of the BPA the bundle is querying for security policy. */
typedef enum
{
    /// Bundle source at creation
    BSL_POLICYLOCATION_APPIN = 101,
    /// Bundle destination at delivery
    BSL_POLICYLOCATION_APPOUT,
    /// Bundle ingress from CLA
    BSL_POLICYLOCATION_CLIN,
    /// Bundle egress to CLA
    BSL_POLICYLOCATION_CLOUT
} BSL_PolicyLocation_e;


/// @brief Forward declaration of PolicyActionSet
typedef struct BSL_PolicyActionSet_s BSL_PolicyActionSet_t;

size_t BSL_PolicyActionSet_StructSizeBytes(void);

/** Zeroize, clear, and release itself and any owned resources.
 * 
 * @param self This action set.
 */
void BSL_PolicyActionSet_Deinit(BSL_PolicyActionSet_t *self);

/** Return true if internal sanity and consistency checks pass
 * 
 * @param[in] self This action set.
 */
bool BSL_PolicyActionSet_IsConsistent(const BSL_PolicyActionSet_t *self);

/** Count number of security operations present in this policy action set.
 * 
 * @param self This action set.
 * @return Number of operations, 0 indicates no policy matched.
 */
size_t BSL_PolicyActionSet_CountSecOpers(const BSL_PolicyActionSet_t *self);

/** Returns the Security Operation at the given index.
 * 
 * @param self This action set
 * @param index index
 * @return pointer to security operation at given index, asserting false if not in bound
 */
const BSL_SecOper_t *BSL_PolicyActionSet_GetSecOperAtIndex(const BSL_PolicyActionSet_t *self, size_t index);

/** Get the error code after querying (inspecting) policy actions. Non-zero indicates error
 * 
 * @param[in] self this action set
 * @return Anomaly on non-zero
 */
size_t BSL_PolicyActionSet_GetErrCode(const BSL_PolicyActionSet_t *self);

/// @brief Forward declaration of policy response (populated set of security operations)
typedef struct BSL_PolicyResponseSet_s BSL_PolicyResponseSet_t;

void BSL_PolicyResponseSet_Init(BSL_PolicyResponseSet_t *self, size_t noperations, size_t nfailed);

/** Zeroize itself and release any owned resources
 * 
 * @param self This response set.
 */
void BSL_PolicyResponseSet_Deinit(BSL_PolicyResponseSet_t *self);

/** Return true if internal consistency checks pass.
 * 
 * @param self This response set.
 */
bool BSL_PolicyResponseSet_IsConsistent(const BSL_PolicyResponseSet_t *self);

/** Return number of responses (operations acted upon)
 * 
 * @param self This response set.
 */
size_t BSL_PolicyResponseSet_CountResponses(const BSL_PolicyResponseSet_t *self);

/// @brief Forward declaration of the policy provider
typedef struct BSL_PolicyProvider_s BSL_PolicyProvider_t;

/** Zeroize itself and clear and release any owned resources
 * 
 * @param self[in] This policy provider.
 */
void BSL_PolicyProvider_Deinit(BSL_PolicyProvider_t *self);

/** Return true if internal sanity and consistency checks pass
 * 
 * 
 * @param[in] self This policy provider.
 * @return true if consistent
 */
bool BSL_PolicyProvider_IsConsistent(const BSL_PolicyProvider_t *self);

/** Queries the policy provider for any security operations to take on the bundle.
 *
 * @note The caller is obligated to allocate space for the policy_action_set output.
 * This memory must be zeroed before being passed, doing otherwise will raise an assertion.
 * 
 * @param[in] self This policy provider.
 * @param[out] output_action_set @preallocated Caller-allocated, zeroed space for action set
 * @param[in,out] bundle Bundle seeking security operations
 * @param[in] location Where in the BPA lifecycle this query arises from
 * 
 * @return A policy action set, which may contain error codes and other info
 */
int BSL_PolicyProvider_InspectActions(const BSL_PolicyProvider_t *self, BSL_PolicyActionSet_t *output_action_set, const BSL_BundleCtx_t *bundle, BSL_PolicyLocation_e location);

/** Performs the security action upon the bundle.
 * 
 * @note This is one of the essential BSL API functions.
 * 
 * This takes the PolicyActionSet returned from the InspectActions call.
 * 
 * @todo Question: Sipos - Does this add/remove the bundle or blocks, or is that part of the BPA?
 *
 * @param[in]     self This policy provider
 * @param[out]    response_output @preallocated Caller-allocated space for a policy resonse object.
 * @param[in,out] bundle Bundle to have the given security actions acted upon (will be manipulated)
 * @param[out]    policy_actions @preallocated Pointer to policy actions struct that contains security operations to be executed on the bundle
 *
 * @return Policy response set indicating success/failure and status for each security operation.
 */
int BSL_PolicyProvider_FinalizeActions(const BSL_PolicyProvider_t *self, BSL_PolicyResponseSet_t *response_output, BSL_BundleCtx_t *bundle, const BSL_PolicyActionSet_t *policy_actions);

#ifdef __cplusplus
} // extern C
#endif

#endif // BSL_PP_ACTION_H_
