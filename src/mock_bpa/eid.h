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

/** @file
 * @ingroup mock_bpa
 * Declarations for EID handling.
 */
#ifndef BSL_MOCK_BPA_EID_H_
#define BSL_MOCK_BPA_EID_H_

#include <inttypes.h>

#include <BPSecLib_Private.h>

#ifdef __cplusplus
extern "C" {
#endif

/// Scheme-specific part for IPN scheme
typedef struct
{
    /// The number of components when encoded, either 2 or 3
    int ncomp;
    /// The authority number component
    uint64_t auth_num;
    /// The node number component
    uint64_t node_num;
    /// The service number component
    uint64_t svc_num;
} bsl_eid_ipn_ssp_t;

/// Decodeable schemes
enum bsl_mock_eid_scheme_e
{
    /// The "ipn" scheme
    BSL_MOCK_EID_IPN = 2,
};

/// Struct to be used as a BSL_HostEID_t::handle
typedef struct
{
    /// Code point for EID schemes from @cite iana:bundle
    uint64_t scheme;

    /// Interpreted according to #scheme code
    union
    {
        /// Used when #scheme is ::BSL_MOCK_EID_IPN
        bsl_eid_ipn_ssp_t as_ipn;
        /// Used in all other cases, copied from source
        BSL_Data_t as_raw;
    } ssp;
} bsl_mock_eid_t;

/// Internal struct initializer
void bsl_mock_eid_init(bsl_mock_eid_t *eid);

/// Internal struct de-initializer
void bsl_mock_eid_deinit(bsl_mock_eid_t *eid);

/// Interface for BSL_HostDescriptors_t::eid_init
int MockBPA_EID_Init(void *user_data, BSL_HostEID_t *eid);

/// Interface for BSL_HostDescriptors_t::eid_deinit
void MockBPA_EID_Deinit(void *user_data, BSL_HostEID_t *eid);

/// Interface for BSL_HostDescriptors_t::eid_from_text
int mock_bpa_eid_from_text(BSL_HostEID_t *eid, const char *text, void *user_data);

/// Interface for BSL_HostDescriptors_t::eid_to_text
// int mock_bpa_eid_to_text(string_t out, const BSL_HostEID_t *eid, void *user_data);

#ifdef __cplusplus
} // extern C
#endif

#endif // BSL_MOCK_BPA_EID_H_
