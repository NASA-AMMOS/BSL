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
 * Declarations for Agent initialization.
 * @ingroup mock_bpa
 */
#ifndef BSL_MOCK_BPA_H_
#define BSL_MOCK_BPA_H_

#include <HostBPA.h>
#include <BundleContext.h>

#include <m-deque.h>
#include <m-dict.h>
#include <m-string.h>

#include <inttypes.h>

#ifdef __cplusplus
extern "C" {
#endif

/// @cond Doxygen_Suppress
DEQUE_DEF(bsl_mock_bpa_label_item, string_t)
DICT_DEF2(bsl_mock_bpa_label_dict, const char *, M_CSTR_OPLIST, string_t *, M_PTR_OPLIST)
/// @endcond

/** Struct to be used as BSL_HostDescriptors_t::user_data
 */
typedef struct
{
    /// Instances with stable addresses
    bsl_mock_bpa_label_item_t label_item;
    /// Map from label name to stable instances
    bsl_mock_bpa_label_dict_t label_dict;
} bsl_mock_bpa_state_t;

/** Register this mock BPA for the current process.
 * @return Zero if successful.
 */
int bsl_mock_bpa_init(void);

/** Clean up the mock BPA for the current process.
 */
void bsl_mock_bpa_deinit(void);

#ifdef __cplusplus
} // extern C
#endif

#endif // BSL_MOCK_BPA_H_
