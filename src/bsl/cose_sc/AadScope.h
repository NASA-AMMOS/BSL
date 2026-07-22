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
 * @ingroup cose_sc
 * Header for the implementation of the COSE context @cite draft-ietf-dtn-bpsec-cose.
 */

#ifndef BSLX_COSESC_AADSCOPE_H_
#define BSLX_COSESC_AADSCOPE_H_

#include "CoseContext.h"

#include "bsl/dynamic/CBOR.h"

#include <m-bptree.h>

#ifdef __cplusplus
extern "C" {
#endif

/** @struct BSLX_CoseSc_AadScope_t
 * An internal representation of AAD Scope map, with keys sorted in
 * CBOR deterministic order and values as a bit mask of
 * ::BSLX_CoseSc_AadScope_Flag_e flags.
 */
// NOLINTBEGIN
/// @cond Doxygen_Suppress
// GCOV_EXCL_START
M_BPTREE_DEF2(BSLX_CoseSc_AadScope, 4, int64_t, M_OPEXTEND(M_BASIC_OPLIST, CMP(API_6(BSL_CBOR_Compare_Int64))),
              uint64_t, M_BASIC_OPLIST)
// GCOV_EXCL_STOP
/// @endcond
// NOLINTEND

/// Matches ::BSL_CBOR_Encode_f signature.
int BSLX_CoseSc_AadScope_Encode(QCBOREncodeContext *enc, const BSLX_CoseSc_AadScope_t *scope);

/// Matches ::BSL_CBOR_Decode_f signature.
int BSLX_CoseSc_AadScope_Decode(QCBORDecodeContext *dec, BSLX_CoseSc_AadScope_t *scope);

#ifdef __cplusplus
} // extern C
#endif

#endif /* BSLX_COSESC_AADSCOPE_H_ */
