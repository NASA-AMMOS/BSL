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
 * Implementation of needed helper functions.
 * @ingroup backend_dyn
 */
#include <stdint.h>
#include <time.h>

#include <Logging.h>
#include <TypeDefintions.h>
#include <UtilHelpers.h>

bool BSL_AssertZeroed(const void *construct, size_t bytesize)
{
    uint8_t zeroes [bytesize];
    memset(zeroes, 0, bytesize);
    return memcmp(zeroes, construct, bytesize) == 0;
}

struct timespec BSL_Util_StartTimer(void)
{
    struct timespec start_time;
    clock_gettime(CLOCK_REALTIME, &start_time);
    return start_time;
}

int64_t BSL_Util_GetTimerElapsedMicros(struct timespec start_time)
{
    struct timespec stop_time;
    clock_gettime(CLOCK_REALTIME, &stop_time);
    int64_t elapsed_nanos =
        (1000000000L * (stop_time.tv_sec - start_time.tv_sec)) + stop_time.tv_nsec - start_time.tv_nsec;
    return elapsed_nanos / 1000;
}

int base16_encode(string_t out, const BSL_Data_t *in, bool uppercase)
{
    const char *fmt = uppercase ? "%02X" : "%02x";

    const uint8_t *curs = in->ptr;
    const uint8_t *end  = curs + in->len;
    for (; curs < end; ++curs)
    {
        string_cat_printf(out, fmt, *curs);
    }
    return 0;
}

/// Size of the base16_decode_table
static const size_t base16_decode_lim = 0x80;
// clang-format off
/// Decode table for base16
static const int base16_decode_table[0x80] =
{
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -2, -2, -1, -1, -2, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -2, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
     0,  1,  2,  3,  4,  5,  6,  7,  8,  9, -1, -1, -1, -1, -1, -1,
    -1, 10, 11, 12, 13, 14, 15, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, 10, 11, 12, 13, 14, 15, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
};
// clang-format on

/** Decode a single character.
 *
 * @param chr The character to decode.
 * @return If positive, the decoded value.
 * -1 to indicate error.
 * -2 to indicate whitespace.
 */
static int base16_decode_char(uint8_t chr)
{
    if (chr >= base16_decode_lim)
    {
        return -1;
    }
    return base16_decode_table[chr];
}

int base16_decode(BSL_Data_t *out, const string_t in)
{
    CHKERR1(out);
    CHKERR1(in);

    const size_t in_len = string_size(in);
    if (in_len % 2 != 0)
    {
        return 1;
    }
    const char *curs = string_get_cstr(in);
    const char *end  = curs + in_len;

    if (BSL_Data_Resize(out, in_len / 2))
    {
        return 2;
    }
    uint8_t *out_curs = out->ptr;

    while (curs < end)
    {
        const int high = base16_decode_char(*(curs++));
        const int low  = base16_decode_char(*(curs++));
        if ((high < 0) || (low < 0))
        {
            return 3;
        }

        const uint8_t byte = (high << 4) | low;
        *(out_curs++)      = byte;
    }
    return 0;
}