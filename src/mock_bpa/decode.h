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
 * Declarations for bundle and block decoding.
 * @ingroup mock_bpa
 */
#ifndef BSL_MOCK_BPA_DECODE_H_
#define BSL_MOCK_BPA_DECODE_H_

#include "eid.h"
#include "bundle.h"
#include <qcbor/qcbor_decode.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Decode a single EID.
 *
 * @param[in] dec The encoded bytes to be decoded.
 * @param[in,out] eid The EID value.
 * The struct must already be initialized.
 */
int bsl_mock_decode_eid(const BSL_Data_t *encoded_bytes, BSL_HostEID_t *eid);

/** Decode a single EID from a QCBOR Decode Context
 *
 * @param[in] dec QCBOR Decode Context.
 * @param[in,out] eid The EID Value.
 */
int bsl_mock_decode_eid_from_ctx(QCBORDecodeContext *dec, BSL_HostEID_t *eid);

/**
 * Encode primary block to a CBOR bytestring.
 *
 * @param[in] dec The decoder.
 * @param[in,out] blk The primary block structure to decode into.
 * The struct must already be initialized.
 * @returns 0 if successful
 */
int bsl_mock_decode_primary(QCBORDecodeContext *dec, MockBPA_PrimaryBlock_t *blk);

/// @overload
int bsl_mock_decode_canonical(QCBORDecodeContext *dec, MockBPA_CanonicalBlock_t *blk);

/// @overload
int bsl_mock_decode_bundle(QCBORDecodeContext *dec, MockBPA_Bundle_t *bundle);

#ifdef __cplusplus
} // extern C
#endif

#endif // BSL_MOCK_BPA_DECODE_H_
