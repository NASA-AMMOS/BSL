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
 * @ingroup mock_bpa
 * Declarations for EID handling.
 */
#ifndef BSL_MOCK_BPA_LABEL_H_
#define BSL_MOCK_BPA_LABEL_H_

#include <HostBPA.h>
#include <DataContainers.h>

#include <inttypes.h>

#ifdef __cplusplus
extern "C" {
#endif

/// Interface for BSL_HostDescriptors_t::label_init
int mock_bpa_label_init(BSL_HostLabel_t *label, void *user_data);

/// Interface for BSL_HostDescriptors_t::label_deinit
void mock_bpa_label_deinit(BSL_HostLabel_t *label, void *user_data);

/// Interface for BSL_HostDescriptors_t::label_from_text
int mock_bpa_label_from_text(BSL_HostLabel_t *label, const char *text, void *user_data);

/// Interface for BSL_HostDescriptors_t::label_to_text
int mock_bpa_label_to_text(string_t out, const BSL_HostLabel_t *label, void *user_data);

#ifdef __cplusplus
} // extern C
#endif

#endif // BSL_MOCK_BPA_LABEL_H_
