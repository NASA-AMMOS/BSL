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
 * Declarations for bundle and block encoding.
 * @ingroup mock_bpa
 */
#ifndef BSL_MOCK_BPA_ENCODE_H_
#define BSL_MOCK_BPA_ENCODE_H_

#include "eid.h"
#include "bundle.h"
#include <qcbor/qcbor_encode.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Encode a single EID.
 *
 * @param[in] enc The encoder.
 * @param[in] eid The EID value.
 */
int bsl_mock_encode_eid(QCBOREncodeContext *enc, const BSL_HostEID_t *eid);

/**
 * Encode primary block to a CBOR data.
 *
 * @param[in] enc The encoder.
 * @param[in] blk primary block information to be encoded
 * @returns 0 if successful
 */
int bsl_mock_encode_primary(QCBOREncodeContext *enc, const MockBPA_PrimaryBlock_t *blk);

/// @overload
int bsl_mock_encode_canonical(QCBOREncodeContext *enc, const MockBPA_CanonicalBlock_t *blk);

/// @overload
int bsl_mock_encode_bundle(QCBOREncodeContext *enc, const MockBPA_Bundle_t *bundle);

#ifdef __cplusplus
} // extern C
#endif

#endif // BSL_MOCK_BPA_ENCODE_H_
