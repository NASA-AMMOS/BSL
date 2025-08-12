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
 * This file contains definitions for text CODEC functions.
 */
#ifndef MOCK_BPA_TEXT_UTIL_H_
#define MOCK_BPA_TEXT_UTIL_H_

#include <m-string.h>
#include <m-bstring.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Encode to URI percent-encoding text form.
 * This is defined in Section 2.1 of RFC 3986 @cite rfc3986.
 * The set of unreserved characters are alpha, digits, and _.-~ characters.
 * in accordance with Section 2.3 of RFC 3986 @cite rfc3986.
 *
 * @param[out] out The output buffer, which will be appended to.
 * @param in The input encoded text which is null-terminated.
 * @param safe A set of additional safe characters to not be encoded,
 * which is null-terminated.
 * @return Zero upon success.
 */
int mock_bpa_uri_percent_encode(m_string_t out, const m_string_t in, const char *safe);

/** Decode from URI percent-encoding text form.
 * This is defined in Section 2.1 of RFC 3986 @cite rfc3986.
 *
 * @param[out] out The output buffer, which will be appended to.
 * @param[in] in The input encoded text which may be null-terminated.
 * @return Zero upon success.
 */
int mock_bpa_uri_percent_decode(m_string_t out, const m_string_t in);

/** Escape backslashes in tstr or bstr text form.
 * This is defined in Section G.2 of RFC 8610 @cite rfc8610
 * and Section 7 of RFC 8259 @cite rfc8259.
 *
 * @param[out] out The output buffer, which will be appended to.
 * @param in The input buffer to read, which must be null terminated.
 * @param quote The character used to quote the string.
 * @return Zero upon success.
 */
int mock_bpa_slash_escape(m_string_t out, const m_string_t in, const char quote);

/** Unescape backslashes in tstr/bstr text form.
 * This is defined in Section G.2 of RFC8610 @cite rfc8610.
 *
 * @param[out] out The output buffer, which will be appended to.
 * @param in The input buffer to read, which may be null terminated.
 * @return Zero upon success.
 */
int mock_bpa_slash_unescape(m_string_t out, const m_string_t in);

/** Remove whitespace characters from a text string.
 * This is based on isspace() inspection.
 *
 * @param[out] out The output buffer, which will be replaced.
 * @param[in] in The input text to read.
 * @param in_len The length of text not including null terminator.
 */
void mock_bpa_strip_space(m_string_t out, const char *in, size_t in_len);

/** Convert a text string to lowercase.
 * This is written to work on byte strings, not unicode.
 *
 * @param[out] out The output buffer, which will be replaced.
 */
void mock_bpa_string_tolower(m_string_t out);

/** Convert a text string to uppercase.
 * This is written to work on byte strings, not unicode.
 *
 * @param[out] out The output buffer, which will be replaced.
 */
void mock_bpa_string_toupper(m_string_t out);

/** Encode to base16 text form.
 * This is defined in Section 8 of RFC 4648 @cite rfc4648.
 *
 * @param[out] out The output buffer, which will be appended to.
 * @param[in] in The input buffer to read.
 * @param uppercase True to use upper-case letters, false to use lower-case.
 * @return Zero upon success.
 */
int mock_bpa_base16_encode(m_string_t out, const m_bstring_t in, bool uppercase);

/** Decode base16 text form.
 * This is defined in Section 8 of RFC 4648 @cite rfc4648.
 *
 * @param[out] out The output buffer, which will be sized to its data.
 * @param[in] in The input buffer to read, which must be null terminated.
 * Whitespace in the input must have already been removed with strip_space().
 * @return Zero upon success.
 */
int mock_bpa_base16_decode(m_bstring_t out, const m_string_t in);

/** Encode base64 and base64url text forms.
 * These is defined in Section 4 and 5 of RFC 4648 @cite rfc4648.
 *
 * @param[out] out The output buffer, which will be appended to.
 * @param[in] in The input buffer to read.
 * @param useurl True to use the base64url alphabet, false to use the base64
 * alphabet.
 * @param usepad True to include padding characters (=), false to not
 * use padding.
 * @return Zero upon success.
 */
int mock_bpa_base64_encode(m_string_t out, const m_bstring_t in, bool useurl, bool usepad);

/** Decode base64 and base64url text forms.
 * These is defined in Section 4 and 5 of RFC 4648 @cite rfc4648.
 *
 * @param[out] out The output buffer, which will be sized to its data.
 * @param[in] in The input buffer to read, which must be null terminated.
 * Whitespace in the input must have already been removed with strip_space().
 * @return Zero upon success.
 */
int mock_bpa_base64_decode(m_bstring_t out, const m_string_t in);

#ifdef __cplusplus
}
#endif

#endif /* MOCK_BPA_TEXT_UTIL_H_ */
