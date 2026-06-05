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
 * Declarations for BPv7 block CRC handling.
 */

#include "crc.h"
#include <arpa/inet.h>
#include <inttypes.h>
#include <BPSecLib_Private.h>

void mock_bpa_crc_crc16(uint8_t out[MOCK_BPA_CRC_CRC16_LEN], UsefulBufC data)
{
    const uint16_t polynomial = 0x8408;

    uint16_t crc = 0xFFFF;

    const uint8_t *curs   = data.ptr;
    size_t         remain = data.len;
    while (remain--)
    {
        crc ^= *(curs++);

        for (unsigned k = 0; k < 8; k++)
        {
            if (crc & 1)
            {
                crc = (crc >> 1) ^ polynomial;
            }
            else
            {
                crc >>= 1;
            }
        }
    }
    crc = ~crc;

    // Network byte order
    out[0] = (crc >> 8) & 0xFF;
    out[1] = crc & 0xFF;
}

void mock_bpa_crc_crc32c(uint8_t out[MOCK_BPA_CRC_CRC32C_LEN], UsefulBufC data)
{
    // The Castagnoli polynomial reflection (0x1EDC6F41 reversed)
    const uint32_t polynomial = 0x82F63B78;

    uint32_t crc = 0xFFFFFFFF;

    const uint8_t *curs   = data.ptr;
    size_t         remain = data.len;
    while (remain--)
    {
        crc ^= *(curs++);

        // Process each of the 8 bits in the current byte byte
        for (unsigned bit = 0; bit < 8; bit++)
        {
            if (crc & 1)
            {
                crc = (crc >> 1) ^ polynomial;
            }
            else
            {
                crc >>= 1;
            }
        }
    }
    crc = ~crc;

    // Network byte order
    out[0] = (crc >> 24) & 0xFF;
    out[1] = (crc >> 16) & 0xFF;
    out[2] = (crc >> 8) & 0xFF;
    out[3] = crc & 0xFF;
}

struct mock_bpa_crc_desc_s
{
    /// Output size
    size_t size;
    /// Calculation function
    void (*calc)(uint8_t out[], UsefulBufC data);
};
static const struct mock_bpa_crc_desc_s mock_bpa_crc_desc_crc16  = { MOCK_BPA_CRC_CRC16_LEN, &mock_bpa_crc_crc16 };
static const struct mock_bpa_crc_desc_s mock_bpa_crc_desc_crc32c = { MOCK_BPA_CRC_CRC32C_LEN, &mock_bpa_crc_crc32c };


static const uint8_t crc_zero_buffer[] = { 0, 0, 0, 0 };

UsefulBufC mock_bpa_crc_zero(BSL_BundleCRCType_e crc_type)
{
    switch (crc_type)
    {
        case BSL_BUNDLECRCTYPE_16:
            return (UsefulBufC) { crc_zero_buffer, MOCK_BPA_CRC_CRC16_LEN };
        case BSL_BUNDLECRCTYPE_32:
            return (UsefulBufC) { crc_zero_buffer, MOCK_BPA_CRC_CRC32C_LEN };
        case BSL_BUNDLECRCTYPE_NONE:
        default:
            return NULLUsefulBufC;
    }
}


void mock_bpa_crc_apply(UsefulBuf buf, size_t begin, size_t end, BSL_BundleCRCType_e crc_type)
{
    const struct mock_bpa_crc_desc_s *desc;
    switch (crc_type)
    {
        case BSL_BUNDLECRCTYPE_NONE:
            // nothing to do
            return;
        case BSL_BUNDLECRCTYPE_16:
            desc = &mock_bpa_crc_desc_crc16;
            break;
        case BSL_BUNDLECRCTYPE_32:
            desc = &mock_bpa_crc_desc_crc32c;
            break;
        default:
            BSL_LOG_CRIT("Unhandled CRC type %d", crc_type);
            return;
    }

    UsefulBufC blk_enc = { (const uint8_t *)buf.ptr + begin, end - begin };

    uint8_t *crc_pos = (uint8_t *)blk_enc.ptr + blk_enc.len - desc->size; // less one crc value
    (desc->calc)(crc_pos, blk_enc);
}

bool mock_bpa_crc_check(UsefulBufC buf, size_t begin, size_t end, BSL_BundleCRCType_e crc_type, size_t got_len)
{
    const struct mock_bpa_crc_desc_s *desc;
    switch (crc_type)
    {
        case BSL_BUNDLECRCTYPE_NONE:
            // nothing to do
            return true;
        case BSL_BUNDLECRCTYPE_16:
            desc = &mock_bpa_crc_desc_crc16;
            break;
        case BSL_BUNDLECRCTYPE_32:
            desc = &mock_bpa_crc_desc_crc32c;
            break;
        default:
            BSL_LOG_CRIT("Unhandled CRC type %d", crc_type);
            return false;
    }

    if (got_len != desc->size)
    {
        BSL_LOG_ERR("bad CRC length %zu", got_len);
        return false;
    }

    const size_t blk_len = end - begin;
    BSL_LOG_ERR("blk len %zu", blk_len);
    // Working buffer from copy
    UsefulBuf blk_cpy = { .ptr = BSL_malloc(blk_len), .len = blk_len };
    memcpy(blk_cpy.ptr, (const uint8_t *)buf.ptr + begin, blk_len);

    uint8_t *cpy_crc = (uint8_t *)blk_cpy.ptr + blk_cpy.len - desc->size; // less one crc value
    // zero out copy
    memset(cpy_crc, 0, desc->size);

    const uint8_t *blk_crc = (const uint8_t *)buf.ptr + end - desc->size; // less one crc value

    (desc->calc)(cpy_crc, UsefulBuf_Const(blk_cpy));
    bool same = (memcmp(cpy_crc, blk_crc, desc->size) == 0);
    if (!same)
    {
        BSL_LOG_ERR("Failed CRC check, first byte expect %02" PRIx8 " read %02" PRIx8, cpy_crc[0], blk_crc[0]);
    }

    BSL_free(blk_cpy.ptr);
    return same;
}
