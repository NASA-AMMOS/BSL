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
#ifndef BSL_MOCK_BPA_CRC_H_
#define BSL_MOCK_BPA_CRC_H_

#include "bsl/BPSecLib_Public.h"

#include <qcbor/UsefulBuf.h>

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/// Length of CRC-16
#define MOCK_BPA_CRC_CRC16_LEN 2

/// Length of CRC-32C
#define MOCK_BPA_CRC_CRC32C_LEN 4

/** Direct CRC function for testing.
 *
 * @param[out] out The buffer to write into.
 * Its size must be appropriate for the @c crc_type.
 * The written value will be BPv7-compatible CRC value in network byte order.
 * @param[in] data The data to read.
 * @param crc_type The needed CRC type.
 */
void mock_bpa_crc_oneshot(uint8_t *out, UsefulBufC data, BSL_BundleCRCType_e crc_type);

/** Get an empty placeholder for a CRC value.
 *
 * @param crc_type The needed CRC type.
 * @return A constant buffer to write.
 */
UsefulBufC mock_bpa_crc_zero(BSL_BundleCRCType_e crc_type);

/** Apply a CRC function to an encoded block.
 *
 * @param buf The buffer holding the encoded block.
 * The buffer contents will be modified to hold the correct CRC value.
 * @param begin The start of the block array
 * @param end The end of the block array
 * @param crc_type The needed CRC type.
 */
void mock_bpa_crc_apply(UsefulBuf buf, size_t begin, size_t end, BSL_BundleCRCType_e crc_type);

/** Check the CRC of an encoded block.
 * This will manipulate the block to clear its current value.
 *
 * @param buf The buffer holding the encoded block.
 * @param begin The start of the block array
 * @param end The end of the block array
 * @param crc_type The needed CRC type.
 * @param got_len The actual byte string length decoded.
 * @return True if the CRC value agrees.
 */
bool mock_bpa_crc_check(UsefulBufC buf, size_t begin, size_t end, BSL_BundleCRCType_e crc_type, size_t got_len);

#ifdef __cplusplus
} // extern C
#endif

#endif // BSL_MOCK_BPA_CRC_H_
