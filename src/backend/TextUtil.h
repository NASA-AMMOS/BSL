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
 * This file contains definitions for text CODEC functions.
 * @ingroup mock_bpa
 */
#ifndef BSLB_TEXTUTIL_H_
#define BSLB_TEXTUTIL_H_

#include <Data.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Encode to base16 text form.
 * This is defined in Section 8 of RFC 4648 @cite rfc4648.
 *
 * @param[out] out The output buffer, which will be resized appropriately
 * and null-terminated.
 * @param[in] in The input buffer to read.
 * @param uppercase True to use upper-case letters, false to use lower-case.
 * @return Zero upon success.
 */
int BSLB_TextUtil_Base16_Encode(BSL_Data_t *out, const BSL_Data_t *in, bool uppercase);

/** Decode base16 text form.
 * This is defined in Section 8 of RFC 4648 @cite rfc4648.
 *
 * @param[out] out The output buffer, which will be sized to its data.
 * @param[in] ptr The input buffer to read, which may be null terminated.
 * Whitespace in the input must have already been removed.
 * @param len The length from @c ptr to read, not including null terminator.
 * @return Zero upon success.
 */
int BSLB_TextUtil_Base16_Decode(BSL_Data_t *out, const char *ptr, size_t len);

/** Encode base64 and base64url text forms.
 * These is defined in Section 4 and 5 of RFC 4648 @cite rfc4648.
 *
 * @param[out] out The output buffer, which will be resized appropriately
 * and null-terminated.
 * @param[in] in The input buffer to read.
 * @param useurl True to use the base64url alphabet, false to use the base64
 * alphabet.
 * @param usepad True to include padding characters (=), false to not
 * use padding.
 * @return Zero upon success.
 */
int BSLB_TextUtil_Base64_Encode(BSL_Data_t *out, const BSL_Data_t *in, bool useurl, bool usepad);

/** Decode base64 and base64url text forms.
 * These is defined in Section 4 and 5 of RFC 4648 @cite rfc4648.
 *
 * @param[out] out The output buffer, which will be sized to its data.
 * @param[in] ptr The input buffer to read, which may be null terminated.
 * Whitespace in the input must have already been removed.
 * @param len The length from @c ptr to read, not including null terminator.
 * @return Zero upon success.
 */
int BSLB_TextUtil_Base64_Decode(BSL_Data_t *out, const char *ptr, size_t len);

/** @def BSL_LOG_PLAINTEXT_PTR(title, ctx, ptr, len)
 * Log plaintext as hex for debugging only when enabled by compile option
 * ::BSL_LOG_PLAINTEXT_ENABLE is non-zero.
 *
 * @param title The static C string title.
 * @param ctc A correlating context pointer to log.
 * @param in_ptr The data start pointer.
 * @param in_len The data length.
 */
#if BSL_LOG_PLAINTEXT_ENABLE
#define BSL_LOG_PLAINTEXT_PTR(title, ctx, in_ptr, in_len)                                   \
    do                                                                                \
    {                                                                                 \
        BSL_Data_t val = BSL_DATA_INIT_VIEW((in_ptr), (in_len)); \
        BSL_Data_t hex_str = BSL_DATA_INIT_NULL; \
        BSLB_TextUtil_Base16_Encode(&hex_str, &val, false); \
        BSL_LOG_DEBUG("PLAINTEXT STATE (ctx %p) " title ": %s", (void *)ctx, hex_str.ptr);         \
        BSL_Data_Deinit(&hex_str); \
    }                                                                                 \
    while (false)
#else
#define BSL_LOG_PLAINTEXT_PTR(title, ctx, in_ptr, in_len)
#endif // BSL_LOG_PLAINTEXT_ENABLE

#ifdef __cplusplus
}
#endif

#endif /* BSLB_TEXTUTIL_H_ */
