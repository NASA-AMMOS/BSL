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
 * @ingroup mock_bpa
 * Declarations for BPv7 block CRC handling.
 */
#ifndef BSL_MOCK_BPA_CRC_H_
#define BSL_MOCK_BPA_CRC_H_

#include <BundleContext.h>
#include <qcbor/UsefulBuf.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

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
 *
 * @param buf The buffer holding the encoded block.
 * @param begin The start of the block array
 * @param end The end of the block array
 * @param crc_type The needed CRC type.
 * @return True if the CRC value agrees.
 */
bool mock_bpa_crc_check(UsefulBufC buf, size_t begin, size_t end, BSL_BundleCRCType_e crc_type);

#ifdef __cplusplus
} // extern C
#endif

#endif // BSL_MOCK_BPA_CRC_H_
