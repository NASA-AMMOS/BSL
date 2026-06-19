/*
 * Copyright (c) 2025-2026 The Johns Hopkins University Applied Physics
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
 * Container structs for BPv7 data.
 */
#include <BPSecLib_Private.h>
#include <backend/CBOR.h>

#include "ctr.h"
#include "decode.h"
#include "encode.h"

void mock_bpa_ctr_init(mock_bpa_ctr_t *ctr)
{
    BSL_CHKVOID(ctr);
    memset(ctr, 0, sizeof(*ctr));

    BSL_Data_Init(&(ctr->encoded));

    ctr->bundle = BSL_calloc(1, sizeof(MockBPA_Bundle_t));
    MockBPA_Bundle_Init(ctr->bundle);

    ctr->bundle_ref.data = ctr->bundle;
}

void mock_bpa_ctr_deinit(mock_bpa_ctr_t *ctr)
{
    BSL_CHKVOID(ctr);
    BSL_Data_Deinit(&(ctr->encoded));

    if (ctr->bundle)
    {
        MockBPA_Bundle_Deinit(ctr->bundle);
        BSL_free(ctr->bundle);
    }
}

void mock_bpa_ctr_sort_blocks(mock_bpa_ctr_t *ctr)
{
    BSL_CHKVOID(ctr);
    // normalize block list by block number in descending order
    MockBPA_BlockList_sort(ctr->bundle->blocks);
}

int mock_bpa_ctr_decode(mock_bpa_ctr_t *ctr)
{
    BSL_CHKERR1(ctr);
    MockBPA_Bundle_t *bundle = ctr->bundle_ref.data;

    if (ctr->bundle_ref.data)
    {
        MockBPA_Bundle_Deinit(ctr->bundle_ref.data);
        MockBPA_Bundle_Init(ctr->bundle_ref.data);
    }

    return BSL_CBOR_Decode(&ctr->encoded, (BSL_CBOR_Decode_f)&bsl_mock_decode_bundle, bundle);
}

int mock_bpa_ctr_encode(mock_bpa_ctr_t *ctr)
{
    BSL_CHKERR1(ctr);
    const MockBPA_Bundle_t *bundle = ctr->bundle_ref.data;
    BSL_CHKERR1(bundle);

    return BSL_CBOR_Encode_Twopass(&ctr->encoded, (BSL_CBOR_Encode_f)&bsl_mock_encode_bundle, bundle);
}
