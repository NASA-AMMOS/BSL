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
 * @ingroup frontend
 * Definitions of miscellaneous functions needed for encoding/decoding and diagnostics.
 */
#ifndef BSL_UTIL_HELPERS_H
#define BSL_UTIL_HELPERS_H

#include <stdint.h>
#include <time.h>

#include <m-string.h>

#include "DataContainers.h"


#ifdef __cplusplus
extern "C" {
#endif

/** Start a timer for profiling functions.
 * 
 */
struct timespec BSL_Util_StartTimer(void);

/** Returns the number of milliseconds since the given start_time timespec
 *
 * @param[in] start_time a `struct timespec` of the start of the event.
 * @return Elapsed time in milliseconds
 */
int64_t BSL_Util_GetTimerElapsedMicros(struct timespec start_time);

/** Encode to base16 text form.
 * This is defined in Section 8 of RFC 4648 @cite rfc4648.
 * @note This function uses heap allocation for its output.
 *
 * @param[out] output The output buffer, which will be appended to.
 * @param[in] input The input buffer to read.
 * @param uppercase True to use upper-case letters, false to use lower-case.
 * @return Zero upon success.
 */
int base16_encode(string_t output, const BSL_Data_t *input, bool uppercase);

/** Decode base16 text form.
 * This is defined in Section 8 of RFC 4648 @cite rfc4648.
 * @note This function uses heap allocation for its output.
 *
 * @param[out] output The output buffer, which will be sized to its data.
 * @param[in] input The input buffer to read, which must be null terminated.
 * Whitespace in the input must have already been removed with strip_space().
 * @return Zero upon success.
 */
int base16_decode(BSL_Data_t *output, const string_t input);

#ifdef __cplusplus
}
#endif

#endif /* BSL_UTIL_HELPERS_H */
