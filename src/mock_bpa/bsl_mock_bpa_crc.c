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
 * Declarations for BPv7 block CRC handling.
 */

#include "bsl_mock_bpa_crc.h"
#include <arpa/inet.h>
#include <inttypes.h>
#include <BPSecLib_Public.h>

static uint16_t bp_crc16(UsefulBufC data)
{
    (void)data;
    return 1234; // FIXME replace
}

static uint32_t bp_crc32(UsefulBufC data)
{
    (void)data;
    return 1234567; // FIXME replace
}

void mock_bpa_crc_apply(UsefulBuf buf, size_t begin, size_t end, BSL_BundleCRCType_e crc_type)
{
    switch (crc_type)
    {
        case BSL_BUNDLECRCTYPE_16:
        case BSL_BUNDLECRCTYPE_32:
            // actually process
            break;
        case BSL_BUNDLECRCTYPE_NONE:
        default:
            return;
    }

    UsefulBufC blk_enc = { (uint8_t *)buf.ptr + begin, end - begin };

    uint8_t *endptr = (uint8_t *)blk_enc.ptr + blk_enc.len;

    switch (crc_type)
    {
        case BSL_BUNDLECRCTYPE_16:
        {
            uint16_t *crc_enc = (uint16_t *)endptr - 1; // less one crc value

            const uint16_t crc_val = bp_crc16(blk_enc);

            *crc_enc = htons(crc_val);
            break;
        }
        case BSL_BUNDLECRCTYPE_32:
        {
            uint32_t *crc_enc = (uint32_t *)endptr - 1; // less one crc value

            const uint32_t crc_val = bp_crc32(blk_enc);

            *crc_enc = htonl(crc_val);
            break;
        }
        default:
            break;
    }
}

bool mock_bpa_crc_check(UsefulBufC buf, size_t begin, size_t end, BSL_BundleCRCType_e crc_type)
{
    switch (crc_type)
    {
        case BSL_BUNDLECRCTYPE_NONE:
            return true;
        case BSL_BUNDLECRCTYPE_16:
        case BSL_BUNDLECRCTYPE_32:
            // actually process
            break;
        default:
            return false;
    }

    UsefulBufC blk_enc = { (uint8_t *)buf.ptr + begin, end - begin };

    const uint8_t *endptr = (uint8_t *)blk_enc.ptr + blk_enc.len;

    bool same = false;
    switch (crc_type)
    {
        case BSL_BUNDLECRCTYPE_16:
        {
            const uint16_t *crc_enc = (uint16_t *)endptr - 1; // less one crc value
            // copy of original for reference
            const uint16_t orig_val = ntohs(*crc_enc);
            const uint16_t crc_val  = bp_crc16(blk_enc);
            same                    = (crc_val == orig_val);
            break;
        }
        case BSL_BUNDLECRCTYPE_32:
        {
            const uint32_t *crc_enc = (uint32_t *)endptr - 1; // less one crc value
            // copy of original for reference
            const uint32_t orig_val = ntohs(*crc_enc);

            const uint16_t crc_val = bp_crc32(blk_enc);
            same                   = (crc_val == orig_val);
            break;
        }
        default:
            break;
    }
    return same;
}
