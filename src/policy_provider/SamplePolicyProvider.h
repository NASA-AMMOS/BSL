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
 * @brief Spec of locally-defined data structures.
 * @ingroup example_pp
 */
#ifndef BSLP_SAMPLE_POLICY_PROVIDER_H
#define BSLP_SAMPLE_POLICY_PROVIDER_H

#include <stdint.h>
#include <BPSecLib_Private.h>
#include <backend/SecParam.h>

/**
 * THE key function that matches a bundle against a rule to provide the output action and specific parameters to use for
 * the security operation.
 *
 * E.g., it'll give parameters like which key to use, but also parameters for target block, security block, sec context,
 * etc.
 */
typedef struct
{
    BSL_PolicyLocation_e location;
    BSL_HostEIDPattern_t src_eid_pattern;
    BSL_HostEIDPattern_t secsrc_eid_pattern;
    BSL_HostEIDPattern_t dst_eid_pattern;
} BSLP_PolicyPredicate_t;

/**
 * @brief Initialize this policy predicate
 *
 * A policy predicate represents a way to match whether a rule applies to a bundle.
 *
 * @param[in] self This predicate
 * @param[in] location The ::BSL_PolicyLocation_e location in the BPA
 * @param[in] src_eid_pattern Host-defined EID pattern to match for
 * @param[in] srcsrc_eid_pattern Host-defined EID pattern for SECURITY SOURCE in security block
 * @param[in] dst_eid_pattern Host-defined EID pattern for DESTINATION EID
 *
 * @returns Nothing
 */
void BSLP_PolicyPredicate_Init(BSLP_PolicyPredicate_t *self, BSL_PolicyLocation_e location,
                               BSL_HostEIDPattern_t src_eid_pattern, BSL_HostEIDPattern_t secsrc_eid_pattern,
                               BSL_HostEIDPattern_t dst_eid_pattern);

void BSLP_PolicyPredicate_Deinit(BSLP_PolicyPredicate_t *self);

/**
 * @brief Returns true if the given predicate matches the arguments
 *
 * @param[in] self This predicate
 * @param[in] location Location in the BPA
 * @param[in] src_eid Source EID
 * @param[in] dst_eid Destination EID
 */
bool BSLP_PolicyPredicate_IsMatch(const BSLP_PolicyPredicate_t *self, BSL_PolicyLocation_e location,
                                  BSL_HostEID_t src_eid, BSL_HostEID_t dst_eid);


#define POLICY_RULE_DESCRIPTION_MAX_STRLEN 100

/**
 * @brief Represents a policy rule
 *
 * A policy rule contains parameters and other metadata
 * necessary to create populated Security Operations for
 * a given bundle.
 *
 * It first contains a predicate, which is used to identify
 * whether this rule applies to a given bundle.
 *
 * It then uses the other fields to create and populate security
 * operations with details (type, role, parameter values, etc.)
 */
typedef struct BSLP_PolicyRule_s
{
    char                     *description;
    BSLP_PolicyPredicate_t   *predicate;
    BSL_SecRole_e             role;
    BSL_BundleBlockTypeCode_e target_block_type;
    BSL_SecBlockType_e        sec_block_type;
    int64_t                   context_id;
    BSLB_SecParamList_t       params;
    BSL_PolicyAction_e        failure_action_code;
} BSLP_PolicyRule_t;

/**
 * @brief Initialize this policy rule
 *
 * @param[in] self This policy rule
 * @param[in] dest Description of this rule (C-string)
 * @param[in] predicate Predicate used to identify which bundles apply
 * @param[in] context_id Security context ID
 * @param[in] role Such as source, acceptor, etc
 * @param[in] sec_block_type Block type (BIB or BCB)
 * @param[in] target_block_type Target block type (anything, such as primary or payload)
 * @param[in] failure_action_code Code to indicate fate of security block/bundle if error occurs
 *
 * @returns Zero on success
 */
int BSLP_PolicyRule_Init(BSLP_PolicyRule_t *self, const char *desc, BSLP_PolicyPredicate_t *predicate,
                         int64_t context_id, BSL_SecRole_e role, BSL_SecBlockType_e sec_block_type,
                         BSL_BundleBlockTypeCode_e target_block_type, BSL_PolicyAction_e failure_action_code);

/**
 * @brief De-initialize, release any resources, and zero this struct.
 *
 * @param[in] self This rule
 */
void BSLP_PolicyRule_Deinit(BSLP_PolicyRule_t *self);

/**
 * @brief Include a BPSec parameter to this rule. Used immediately after Init.
 *
 * @param[in] self This rule
 * @param[in,out] param Pointer to the Parameter to move from.
 */
void BSLP_PolicyRule_CopyParam(BSLP_PolicyRule_t *self, const BSL_SecParam_t *param);

/**
 * @brief Include a BPSec parameter to this rule. Used immediately after Init.
 *
 * @param[in] self This rule
 * @param[in,out] param Pointer to the Parameter to move from.
 */
void BSLP_PolicyRule_MoveParam(BSLP_PolicyRule_t *self, BSL_SecParam_t *param);

/**
 * @brief Critical function creating a security operation from a bundle and location.
 *
 * @param[in] self This policy rule
 * @param[in] sec_oper @preallocated Caller-allocated space for the output security action.
 * @param[in] bundle Bundle to test match against
 * @param[in] location Location in the BPA
 *
 * @return Zero on success, negative on failure.
 */
int BSLP_PolicyRule_EvaluateAsSecOper(const BSLP_PolicyRule_t *self, BSL_SecOper_t *sec_oper,
                                      const BSL_BundleRef_t *bundle, BSL_PolicyLocation_e location);

#define BSLP_POLICYPREDICATE_ARRAY_CAPACITY (100)
/// @brief Concrete definition of a policy provider
typedef struct BSLP_PolicyProvider_s
{
    BSLP_PolicyPredicate_t predicates[BSLP_POLICYPREDICATE_ARRAY_CAPACITY];
    size_t                 predicate_count;
    BSLP_PolicyRule_t      rules[BSLP_POLICYPREDICATE_ARRAY_CAPACITY];
    size_t                 rule_count;
    uint64_t               pp_id;
} BSLP_PolicyProvider_t;

void BSLP_Deinit(void *user_data);

int BSLP_QueryPolicy(const void *user_data, BSL_SecurityActionSet_t *output_action_set, const BSL_BundleRef_t *bundle,
                     BSL_PolicyLocation_e location);

int BSLP_FinalizePolicy(const void *user_data, const BSL_SecurityActionSet_t *output_action_set,
                        const BSL_BundleRef_t *bundle, const BSL_SecurityResponseSet_t *response_output);

#endif // BSLP_SAMPLE_POLICY_PROVIDER_H
