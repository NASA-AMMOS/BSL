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
#include "bsl_mock_bpa_label.h"
#include "bsl_mock_bpa.h"
#include <BSLConfig.h>
#include <TypeDefintions.h>
#include <Logging.h>

#include <m-string.h>

int mock_bpa_label_init(BSL_HostLabel_t *label, void *user_data _U_)
{
    label->handle = NULL;
    return 0;
}

void mock_bpa_label_deinit(BSL_HostLabel_t *label, void *user_data _U_)
{
    // leave any earlier uses of this label in place
    label->handle = NULL;
}

int mock_bpa_label_from_text(BSL_HostLabel_t *label, const char *text, void *user_data)
{
    CHKERR1(text);
    CHKERR1(user_data);
    bsl_mock_bpa_state_t *state = user_data;

    CHKERR1(strlen(text) > 0);

    string_t **found = bsl_mock_bpa_label_dict_get(state->label_dict, text);
    if (found)
    {
        label->handle = *found;
    }
    else
    {
        string_t *item = bsl_mock_bpa_label_item_push_back_new(state->label_item);
        string_set_str(*item, text);
        // self-referenced keys
        bsl_mock_bpa_label_dict_set_at(state->label_dict, string_get_cstr(*item), item);

        label->handle = item;
    }
    return 0;
}

int mock_bpa_label_to_text(string_t out, const BSL_HostLabel_t *label, void *user_data _U_)
{
    CHKERR1(out);
    CHKERR1(label);
    if (!(label->handle))
    {
        return 2;
    }
    const string_t *item = label->handle;
    string_set(out, *item);
    return 0;
}
