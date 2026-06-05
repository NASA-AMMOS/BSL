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

static void mock_bpa_crc_crc16_init(void *state)
{
    uint16_t *crc = state;

    *crc = 0xFFFF;
}

static void mock_bpa_crc_crc16_update(void *state, UsefulBufC data)
{
    static const uint16_t polynomial = 0x8408;

    uint16_t *crc = state;

    const uint8_t *curs   = data.ptr;
    size_t         remain = data.len;
    while (remain--)
    {
        *crc ^= *(curs++);

        for (unsigned k = 0; k < 8; k++)
        {
            if (*crc & 1)
            {
                *crc = (*crc >> 1) ^ polynomial;
            }
            else
            {
                *crc >>= 1;
            }
        }
    }
}

static void mock_bpa_crc_crc16_finalize(void *state, uint8_t out[MOCK_BPA_CRC_CRC16_LEN])
{
    uint16_t *crc = state;

    *crc = ~*crc;

    // Network byte order
    out[0] = (*crc >> 8) & 0xFF;
    out[1] = *crc & 0xFF;
}

static void mock_bpa_crc_crc32c_init(void *state)
{
    uint32_t *crc = state;

    *crc = 0xFFFFFFFF;
}

static void mock_bpa_crc_crc32c_update(void *state, UsefulBufC data)
{
    // The Castagnoli polynomial reflection (0x1EDC6F41 reversed)
    const uint32_t polynomial = 0x82F63B78;

    uint32_t *crc = state;

    const uint8_t *curs   = data.ptr;
    size_t         remain = data.len;
    while (remain--)
    {
        *crc ^= *(curs++);

        // Process each of the 8 bits in the current byte byte
        for (unsigned bit = 0; bit < 8; bit++)
        {
            if (*crc & 1)
            {
                *crc = (*crc >> 1) ^ polynomial;
            }
            else
            {
                *crc >>= 1;
            }
        }
    }
}

static void mock_bpa_crc_crc32c_finalize(void *state, uint8_t out[MOCK_BPA_CRC_CRC32C_LEN])
{
    uint32_t *crc = state;

    *crc = ~*crc;

    // Network byte order
    out[0] = (*crc >> 24) & 0xFF;
    out[1] = (*crc >> 16) & 0xFF;
    out[2] = (*crc >> 8) & 0xFF;
    out[3] = *crc & 0xFF;
}

typedef struct
{
    /// Output size
    size_t out_size;
    /// State size
    size_t state_size;
    /** Init function.
     * @param state The uninitialized state.
     */
    void (*init)(void *state);
    /** Update function.
     * @param state The initialized state.
     */
    void (*update)(void *state, UsefulBufC data);
    /** Finalize function.
     * @param[in] state The initialized state.
     * @param[out] out The output buffer.
     * The buffer must be of size #out_size.
     */
    void (*finalize)(void *state, uint8_t *out);
} mock_bpa_crc_desc_t;

static const mock_bpa_crc_desc_t mock_bpa_crc_desc_crc16  = { .out_size   = MOCK_BPA_CRC_CRC16_LEN,
                                                              .state_size = MOCK_BPA_CRC_CRC16_LEN,
                                                              .init       = &mock_bpa_crc_crc16_init,
                                                              .update     = mock_bpa_crc_crc16_update,
                                                              .finalize   = mock_bpa_crc_crc16_finalize };
static const mock_bpa_crc_desc_t mock_bpa_crc_desc_crc32c = { .out_size   = MOCK_BPA_CRC_CRC32C_LEN,
                                                              .state_size = MOCK_BPA_CRC_CRC32C_LEN,
                                                              .init       = &mock_bpa_crc_crc32c_init,
                                                              .update     = mock_bpa_crc_crc32c_update,
                                                              .finalize   = mock_bpa_crc_crc32c_finalize };

static const mock_bpa_crc_desc_t *get_desc(BSL_BundleCRCType_e crc_type)
{
    switch (crc_type)
    {
        case BSL_BUNDLECRCTYPE_NONE:
            return NULL;
        case BSL_BUNDLECRCTYPE_16:
            return &mock_bpa_crc_desc_crc16;
        case BSL_BUNDLECRCTYPE_32:
            return &mock_bpa_crc_desc_crc32c;
        default:
            BSL_LOG_CRIT("Unhandled CRC type %d", crc_type);
            return NULL;
    }
}

void mock_bpa_crc_oneshot(uint8_t *out, UsefulBufC data, BSL_BundleCRCType_e crc_type)
{
    const mock_bpa_crc_desc_t *desc = get_desc(crc_type);
    if (!desc)
    {
        return;
    }

    uint8_t state[desc->state_size];
    (desc->init)(state);
    (desc->update)(state, data);
    (desc->finalize)(state, out);
}

UsefulBufC mock_bpa_crc_zero(BSL_BundleCRCType_e crc_type)
{
    static const uint8_t crc_zero_buffer[MOCK_BPA_CRC_CRC32C_LEN] = { 0 };

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
    const mock_bpa_crc_desc_t *desc = get_desc(crc_type);
    if (!desc)
    {
        return;
    }

    // block excluding CRC bytes
    UsefulBufC blk_enc = { .ptr = (const uint8_t *)buf.ptr + begin, .len = end - begin - desc->out_size };
    // position of CRC bytes
    uint8_t *crc_pos = (uint8_t *)blk_enc.ptr + blk_enc.len;

    uint8_t state[desc->state_size];
    (desc->init)(state);
    (desc->update)(state, blk_enc);
    (desc->update)(state, mock_bpa_crc_zero(crc_type));
    (desc->finalize)(state, crc_pos);
}

bool mock_bpa_crc_check(UsefulBufC buf, size_t begin, size_t end, BSL_BundleCRCType_e crc_type, size_t got_len)
{
    const mock_bpa_crc_desc_t *desc = get_desc(crc_type);
    if (!desc)
    {
        // nothing to do
        return true;
    }

    if (got_len != desc->out_size)
    {
        BSL_LOG_ERR("bad CRC length %zu", got_len);
        return false;
    }

    // block excluding CRC bytes
    UsefulBufC blk_enc = { .ptr = (const uint8_t *)buf.ptr + begin, .len = end - begin - desc->out_size };
    // position of CRC bytes
    uint8_t *crc_pos = (uint8_t *)blk_enc.ptr + blk_enc.len;

    uint8_t state[desc->state_size];
    (desc->init)(state);
    (desc->update)(state, blk_enc);
    (desc->update)(state, mock_bpa_crc_zero(crc_type));

    uint8_t expect[desc->out_size];
    (desc->finalize)(state, expect);
    bool same = (memcmp(expect, crc_pos, desc->out_size) == 0);
    if (!same)
    {
        BSL_LOG_ERR("Failed CRC check, first byte expect %02" PRIx8 " read %02" PRIx8, expect[0], crc_pos[0]);
    }

    return same;
}
