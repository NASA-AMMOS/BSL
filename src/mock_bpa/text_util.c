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
#include "text_util.h"
#include <BPSecLib_Private.h>
#include <string.h>
#include <strings.h>
#include <inttypes.h>
#include <stdlib.h>
#include <math.h>

static int take_hex_1byte(uint8_t *out, const char **curs, const char *end)
{
    if (*curs + 2 > end)
    {
        return 1;
    }

    char  buf[] = { *((*curs)++), *((*curs)++), 0 };
    char *numend;
    *out = strtoul(buf, &numend, 16);
    if (numend < buf + 2)
    {
        return 2;
    }
    return 0;
}

static int take_hex_2byte(uint16_t *out, const char **curs, const char *end)
{
    if (*curs + 4 > end)
    {
        return 1;
    }

    char  buf[] = { *((*curs)++), *((*curs)++), *((*curs)++), *((*curs)++), 0 };
    char *numend;
    *out = strtoul(buf, &numend, 16);
    if (numend < buf + 4)
    {
        return 2;
    }
    return 0;
}

/** Set of unreserved characters from Section 2.3 of RFC 3986 @cite rfc3986.
 */
static const char *unreserved = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.-~";

int mock_bpa_uri_percent_encode(m_string_t out, const m_string_t in, const char *safe)
{
    CHKERR1(out);
    CHKERR1(in);

    const size_t in_len = m_string_size(in);
    const char  *curs   = m_string_get_cstr(in);
    const char  *end    = curs + in_len;

    m_string_t allsafe;
    m_string_init(allsafe);
    m_string_cat_cstr(allsafe, unreserved);
    if (safe)
    {
        m_string_cat_cstr(allsafe, safe);
    }

    // assume no more than half of the input chars are escaped,
    // which gives total output size of: 0.5 + 0.5 * 3 => 2
    m_string_reserve(out, m_string_size(out) + 2 * in_len);

    int retval = 0;
    while (curs < end)
    {
        const size_t partlen = strspn(curs, m_string_get_cstr(allsafe));

        if (partlen)
        {
            m_string_cat_printf(out, "%.*s", (int)partlen, curs);
        }
        curs += partlen;

        if (curs >= end)
        {
            // no unsafe char and no more text
            break;
        }

        const uint8_t chr = *(curs++);
        m_string_cat_printf(out, "%%%02X", chr);
    }

    m_string_clear(allsafe);
    return retval;
}

int mock_bpa_uri_percent_decode(m_string_t out, const m_string_t in)
{
    CHKERR1(out);
    CHKERR1(in);

    const size_t in_len = m_string_size(in);
    const char  *curs   = m_string_get_cstr(in);
    const char  *end    = curs + in_len;

    // potentially no escaping used
    m_string_reserve(out, m_string_size(out) + in_len);

    while (curs < end)
    {
        const char *partend = strchr(curs, '%');
        if (partend == NULL)
        {
            partend = end;
        }
        const size_t partlen = partend - curs;

        if (partlen)
        {
            m_string_cat_printf(out, "%.*s", (int)partlen, curs);
        }
        curs += partlen + 1;

        if (curs > end)
        {
            // no percent and no more text
            break;
        }

        // cursor is on the percent char
        uint8_t val;
        if (take_hex_1byte(&val, &curs, end))
        {
            return 2;
        }
        m_string_push_back(out, val);
    }

    return 0;
}

int mock_bpa_slash_escape(m_string_t out, const m_string_t in, const char quote)
{
    CHKERR1(out);
    CHKERR1(in);

    // unicode iterator
    m_string_it_t it;
    for (m_string_it(it, in); !m_string_end_p(it); m_string_next(it))
    {
        const m_string_unicode_t *chr = m_string_cref(it);
        if (*chr == (m_string_unicode_t)quote)
        {
            m_string_push_back(out, '\\');
            m_string_push_back(out, quote);
        }
        else if (*chr == 0x08)
        {
            m_string_cat_cstr(out, "\\b");
        }
        else if (*chr == 0x0C)
        {
            m_string_cat_cstr(out, "\\f");
        }
        else if (*chr == 0x0A)
        {
            m_string_cat_cstr(out, "\\n");
        }
        else if (*chr == 0x0D)
        {
            m_string_cat_cstr(out, "\\r");
        }
        else if (*chr == 0x09)
        {
            m_string_cat_cstr(out, "\\t");
        }
        else if ((*chr <= 0xFF) && isprint(*chr))
        {
            m_string_push_u(out, *chr);
        }
        else if ((*chr <= 0xD7FF) || ((*chr >= 0xE000) && (*chr <= 0xFFFF)))
        {
            const uint16_t uprime = *chr;
            m_string_cat_printf(out, "\\u%04" PRIX16, uprime);
        }
        else
        {
            // surrogate pair creation
            const uint32_t uprime = *chr - 0x10000;
            const uint16_t high   = 0xD800 + (uprime >> 10);
            const uint16_t low    = 0xDC00 + (uprime & 0x03FF);
            m_string_cat_printf(out, "\\u%04" PRIX16 "\\u%04" PRIX16, high, low);
        }
    }
    return 0;
}

int mock_bpa_slash_unescape(m_string_t out, const m_string_t in)
{
    CHKERR1(out);
    CHKERR1(in);

    const size_t in_len = m_string_size(in);
    if (in_len == 0)
    {
        return 0;
    }

    // potentially no escaping used
    m_string_reserve(out, m_string_size(out) + in_len);

    const char *curs   = m_string_get_cstr(in);
    const char *end    = curs + in_len;
    int         retval = 0;
    while (curs < end)
    {
        const char *partend = strchr(curs, '\\');
        if (partend == NULL)
        {
            partend = end;
        }
        const size_t partlen = partend - curs;

        if (partlen)
        {
            m_string_cat_printf(out, "%.*s", (int)partlen, curs);
        }
        curs += partlen + 1;

        if (curs > end)
        {
            // no backslash and no more text
            break;
        }
        else if (curs == end)
        {
            // backslash with no trailing character
            retval = 3;
            break;
        }

        if (*curs == 'b')
        {
            m_string_push_back(out, 0x08);
            curs += 1;
        }
        else if (*curs == 'f')
        {
            m_string_push_back(out, 0x0C);
            curs += 1;
        }
        else if (*curs == 'n')
        {
            m_string_push_back(out, 0x0A);
            curs += 1;
        }
        else if (*curs == 'r')
        {
            m_string_push_back(out, 0x0D);
            curs += 1;
        }
        else if (*curs == 't')
        {
            m_string_push_back(out, 0x09);
            curs += 1;
        }
        else if (*curs == 'u')
        {
            ++curs;

            uint16_t val;
            if (take_hex_2byte(&val, &curs, end))
            {
                retval = 5;
                break;
            }

            m_string_unicode_t unival;
            if ((val >= 0xD800) && (val <= 0xDFFF))
            {
                // surrogate pair removal
                unival = (val - 0xD800) << 10;

                if (curs + 2 >= end)
                {
                    retval = 5;
                    break;
                }
                if (*curs != '\\')
                {
                    retval = 5;
                    break;
                }
                ++curs;
                if (*curs != 'u')
                {
                    retval = 5;
                    break;
                }
                ++curs;

                if (take_hex_2byte(&val, &curs, end))
                {
                    retval = 5;
                    break;
                }
                unival |= val - 0xDC00;

                unival += 0x10000;
            }
            else
            {
                unival = val;
            }

            m_string_push_u(out, unival);
        }
        else
        {
            m_string_push_back(out, *curs);
            curs += 1;
        }
    }

    return retval;
}

static void strip_chars(m_string_t out, const char *in, size_t in_len, const char *chars)
{
    const char *curs = in;
    const char *end  = curs + in_len;
    size_t      plen;

    // likely no removal
    m_string_reserve(out, in_len);

    while (curs < end)
    {
        plen = strcspn(curs, chars);
        m_string_cat_printf(out, "%.*s", (int)plen, curs);
        curs += plen;

        plen = strspn(curs, chars);
        curs += plen;
    }
}

void mock_bpa_strip_space(m_string_t out, const char *in, size_t in_len)
{
    strip_chars(out, in, in_len, " \b\f\n\r\t");
}

void mock_bpa_string_tolower(m_string_t out)
{
    CHKVOID(out);
    size_t len = m_string_size(out);
    for (size_t i = 0; i < len; i++)
    {
        m_string_set_char(out, i, tolower(m_string_get_char(out, i)));
    }
}

void mock_bpa_string_toupper(m_string_t out)
{
    CHKVOID(out);
    size_t len = m_string_size(out);
    for (size_t i = 0; i < len; i++)
    {
        m_string_set_char(out, i, toupper(m_string_get_char(out, i)));
    }
}

int mock_bpa_base16_encode(m_string_t out, const m_bstring_t in, bool uppercase)
{
    const char *fmt = uppercase ? "%02X" : "%02x";

    const size_t   in_len = m_bstring_size(in);
    const uint8_t *curs   = m_bstring_view(in, 0, in_len);
    const uint8_t *end    = curs + in_len;
    for (; curs < end; ++curs)
    {
        m_string_cat_printf(out, fmt, *curs);
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

int mock_bpa_base16_decode(m_bstring_t out, const m_string_t in)
{
    CHKERR1(out);
    CHKERR1(in);

    const size_t in_len = m_string_size(in);
    if (in_len % 2 != 0)
    {
        return 1;
    }
    const char *curs = m_string_get_cstr(in);
    const char *end  = curs + in_len;

    const size_t out_len = in_len / 2;
    m_bstring_resize(out, out_len);
    uint8_t *out_curs = m_bstring_acquire_access(out, 0, out_len);
    ;

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

        const uint8_t byte = (high << 4) | low;
        *(out_curs++)      = byte;
    }

    m_bstring_release_access(out);
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

int mock_bpa_base64_encode(m_string_t out, const m_bstring_t in, bool useurl, bool usepad)
{
    size_t         in_len = m_bstring_size(in);
    const uint8_t *curs   = m_bstring_view(in, 0, in_len);
    const uint8_t *end    = curs + in_len;

    const char *const abet = useurl ? base64url_alphabet : base64_alphabet;

    // output length is the ceiling of ratio 8/6
    size_t out_len = ((in_len + 2) / 3) * 4;
    m_string_reserve(out, m_string_size(out) + out_len);

    for (; curs < end; curs += 3)
    {
        uint8_t byte = (curs[0] >> 2) & 0x3F;
        char    chr  = abet[byte];
        m_string_push_back(out, chr);
        --in_len;
        if (--out_len == 0)
        {
            break;
        }

        byte = ((curs[0] << 4) | (in_len ? curs[1] >> 4 : 0)) & 0x3F;
        chr  = abet[byte];
        m_string_push_back(out, chr);
        if (--out_len == 0)
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
            m_string_push_back(out, chr);
        }
        if (--out_len == 0)
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
            m_string_push_back(out, chr);
        }
        if (--out_len == 0)
        {
            break;
        }
    }
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

int mock_bpa_base64_decode(m_bstring_t out, const m_string_t in)
{
    CHKERR1(out);
    CHKERR1(in);

    size_t      in_len = m_string_size(in);
    const char *curs   = m_string_get_cstr(in);

    size_t out_len = (in_len / 4) * 3 + 2;
    m_bstring_resize(out, out_len);
    uint8_t *out_curs = m_bstring_acquire_access(out, 0, out_len);

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

        if (out_len)
        {
            const uint8_t byte = (seg0 << 2) | (seg1 >> 4);
            *(out_curs++)      = byte;
            --out_len;
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

            if (out_len)
            {
                const uint8_t byte = ((seg1 << 4) & 0xF0) | (seg2 >> 2);
                *(out_curs++)      = byte;
                --out_len;
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

                if (out_len)
                {
                    const uint8_t byte = ((seg2 << 6) & 0xC0) | seg3;
                    *(out_curs++)      = byte;
                    --out_len;
                }
            }
        }
    }

    // trim if necessary
    m_bstring_release_access(out);
    m_bstring_resize(out, m_bstring_size(out) - out_len);

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
