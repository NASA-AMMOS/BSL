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
 * Definitions for Agent initialization.
 * @ingroup mock_bpa
 */
#include <BundleContext.h>
#include "bsl_mock_bpa.h"
#include "bsl_mock_bpa_eid.h"
#include "bsl_mock_bpa_eidpat.h"
#include "bsl_mock_bpa_encode.h"
#include "bsl_mock_bpa_decode.h"
#include "bsl_mock_bpa_label.h"
#include <backend/DynHostBPA.h>

int bsl_mock_bpa_init(void)
{
    bsl_mock_bpa_state_t *state = BSL_MALLOC(sizeof(bsl_mock_bpa_state_t));
    bsl_mock_bpa_label_item_init(state->label_item);
    bsl_mock_bpa_label_dict_init(state->label_dict);

    BSL_HostDescriptors_t bpa = {
        .user_data        = state,
        .eid_init         = mock_bpa_eid_init,
        .eid_deinit       = mock_bpa_eid_deinit,
        .get_secsrc       = mock_bpa_get_secsrc,
        .eid_to_cbor      = (int (*)(void *, const BSL_HostEID_t *))bsl_mock_encode_eid,
        .eid_from_cbor    = (int (*)(void *, BSL_HostEID_t *))bsl_mock_decode_eid,
        .eid_from_text    = mock_bpa_eid_from_text,
        .eid_to_text      = mock_bpa_eid_to_text,
        .eidpat_init      = mock_bpa_eidpat_init,
        .eidpat_deinit    = mock_bpa_eidpat_deinit,
        .eidpat_from_text = mock_bpa_eidpat_from_text,
        .eidpat_match     = mock_bpa_eidpat_match,
        .label_init       = mock_bpa_label_init,
        .label_deinit     = mock_bpa_label_deinit,
        .label_from_text  = mock_bpa_label_from_text,
        .label_to_text    = mock_bpa_label_to_text,
    };
    return BSL_HostDescriptors_Set(bpa);
}

void bsl_mock_bpa_deinit(void)
{
    BSL_HostDescriptors_t bpa;
    BSL_HostDescriptors_Get(&bpa);
    if (!bpa.user_data)
    {
        return;
    }

    {
        bsl_mock_bpa_state_t *state = bpa.user_data;
        bsl_mock_bpa_label_dict_clear(state->label_dict);
        bsl_mock_bpa_label_item_clear(state->label_item);
    }
    BSL_FREE(bpa.user_data);

    BSL_HostDescriptors_t nullbpa = { .user_data = NULL };
    BSL_HostDescriptors_Set(nullbpa);
}
