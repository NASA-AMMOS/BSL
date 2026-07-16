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
#include <bsl/front/TextUtil.h>
#include <bsl/BPSecLib_Private.h>
#include <string.h>
#include <strings.h>
#include <inttypes.h>
#include <stdlib.h>
#include <stdio.h>
#include <math.h>

int BSL_TextUtil_Base16_Encode(BSL_Data_t *out, const BSL_Data_t *in, bool uppercase)
{
    ASSERT_ARG_NONNULL(out);
    ASSERT_ARG_NONNULL(in);

    const uint8_t *in_curs = in->ptr;
    const uint8_t *in_end  = in_curs + in->len;

    BSL_Data_Resize(out, 2 * in->len + 1);
    char  *out_curs = (char *)(out->ptr);
    size_t out_rem  = out->len;

    for (; in_curs < in_end; ++in_curs)
    {
        snprintf(out_curs, out_rem, uppercase ? "%02X" : "%02x", *in_curs);
        out_curs += 2;
        out_rem -= 2;
    }
    *out_curs = '\0';

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

int BSL_TextUtil_Base16_Decode(BSL_Data_t *out, const char *ptr, size_t len)
{
    ASSERT_ARG_NONNULL(out);
    ASSERT_ARG_NONNULL(ptr);

    if (len % 2 != 0)
    {
        return 1;
    }
    const char *curs = ptr;
    const char *end  = curs + len;

    const size_t out_len = len / 2;
    BSL_Data_Resize(out, out_len);
    uint8_t *out_curs = out->ptr;

    int retval = 0;
    while (curs < end)
    {
        const int high = base16_decode_char(*(curs++));
        const int low  = base16_decode_char(*(curs++));
        if ((high < 0) || (low < 0))
        {
            retval = 3;
            break;
        }

        const uint8_t byte = (uint8_t)((high << 4) | low);
        // append
        *(out_curs++) = byte;
    }

    return retval;
}

// clang-format off
static const char *base64_alphabet =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789+/";
static const char *base64url_alphabet =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789-_";
// clang-format on

int BSL_TextUtil_Base64_Encode(BSL_Data_t *out, const BSL_Data_t *in, bool useurl, bool usepad)
{
    ASSERT_ARG_NONNULL(out);
    ASSERT_ARG_NONNULL(in);

    size_t         in_len = in->len;
    const uint8_t *curs   = in->ptr;
    const uint8_t *end    = curs + in_len;

    const char *const abet = useurl ? base64url_alphabet : base64_alphabet;

    // output length is the ceiling of ratio 8/6 plus null terminator
    size_t out_len = ((in_len + 2) / 3) * 4 + 1;
    BSL_Data_Resize(out, out_len);
    uint8_t *out_curs = out->ptr;

    for (; curs < end; curs += 3)
    {
        uint8_t byte = (curs[0] >> 2) & 0x3F;
        char    chr  = abet[byte];
        // append
        *(out_curs++) = chr;
        --in_len;
        if (--out_len == 1)
        {
            break;
        }

        byte = ((curs[0] << 4) | (in_len ? curs[1] >> 4 : 0)) & 0x3F;
        chr  = abet[byte];
        // append
        *(out_curs++) = chr;
        if (--out_len == 1)
        {
            break;
        }

        if (in_len)
        {
            --in_len;
            byte = ((curs[1] << 2) | (in_len ? curs[2] >> 6 : 0)) & 0x3F;
            chr  = abet[byte];
        }
        else
        {
            chr = '=';
        }
        if (usepad || (chr != '='))
        {
            // append
            *(out_curs++) = chr;
        }
        if (--out_len == 1)
        {
            break;
        }

        if (in_len)
        {
            --in_len;
            byte = curs[2] & 0x3F;
            chr  = abet[byte];
        }
        else
        {
            chr = '=';
        }
        if (usepad || (chr != '='))
        {
            // append
            *(out_curs++) = chr;
        }
        if (--out_len == 1)
        {
            break;
        }
    }
    *out_curs = '\0';

    return 0;
}

/// Size of the base16_decode_table
static const size_t base64_decode_lim = 0x80;
// clang-format off
/// Decode table for base64 and base64uri
static const int base64_decode_table[0x80] = {
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -2, -2, -2, -2, -2, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -2, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, 62, -1, 63,
    52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, -1, -1, -1,
    -1,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
    15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, 63,
    -1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
    41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -1,
};
// clang-format on

/** Decode a single character.
 *
 * @param chr The character to decode.
 * @return If positive, the decoded value.
 * -1 to indicate error.
 * -2 to indicate whitespace.
 */
static int base64_decode_char(uint8_t chr)
{
    if (chr >= base64_decode_lim)
    {
        return -1;
    }
    return base64_decode_table[chr];
}

int BSL_TextUtil_Base64_Decode(BSL_Data_t *out, const char *ptr, size_t len)
{
    ASSERT_ARG_NONNULL(out);
    ASSERT_ARG_NONNULL(ptr);

    size_t      in_len = len;
    const char *curs   = ptr;

    // upper bound on storage
    size_t out_rem = (in_len / 4) * 3 + 2;
    BSL_Data_Resize(out, out_rem);
    uint8_t *out_curs = out->ptr;

    int retval = 0;
    for (; in_len >= 2; curs += 4, in_len -= 4)
    {
        // ignoring excess padding
        if (curs[0] == '=')
        {
            break;
        }

        const int seg0 = base64_decode_char(curs[0]);
        const int seg1 = base64_decode_char(curs[1]);
        if ((seg0 < 0) || (seg1 < 0))
        {
            retval = 3;
            break;
        }

        if (out_rem)
        {
            const uint8_t byte = (uint8_t)((seg0 << 2) | (seg1 >> 4));
            // append
            *(out_curs++) = byte;
            --out_rem;
        }

        if (in_len == 2)
        {
            // allow omitted padding
            in_len = 0;
            break;
        }
        else if (curs[2] == '=')
        {
            if (in_len != 4)
            {
                break;
            }
            if (curs[3] != '=')
            {
                break;
            }
        }
        else
        {
            const int seg2 = base64_decode_char(curs[2]);
            if (seg2 < 0)
            {
                retval = 3;
                break;
            }

            if (out_rem)
            {
                const uint8_t byte = (uint8_t)(((seg1 << 4) & 0xF0) | (seg2 >> 2));
                // append
                *(out_curs++) = byte;
                --out_rem;
            }

            if (in_len == 3)
            {
                // allow omitted padding
                in_len = 0;
                break;
            }
            else if (curs[3] == '=')
            {
                if (in_len != 4)
                {
                    break;
                }
            }
            else
            {
                const int seg3 = base64_decode_char(curs[3]);
                if (seg3 < 0)
                {
                    retval = 3;
                    break;
                }

                if (out_rem)
                {
                    const uint8_t byte = (uint8_t)(((seg2 << 6) & 0xC0) | seg3);
                    // append
                    *(out_curs++) = byte;
                    --out_rem;
                }
            }
        }
    }

    // trim if necessary
    if (out_rem > 0)
    {
        BSL_Data_Resize(out, out->len - out_rem);
    }

    if (retval)
    {
        return retval;
    }

    // Per Section 3.3 of RFC 4648, ignoring excess padding
    while ((in_len > 0) && (*curs == '='))
    {
        ++curs;
        --in_len;
    }

    return (in_len > 0) ? 4 : 0;
}
