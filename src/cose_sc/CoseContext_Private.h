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

#ifndef BSLX_COSECONTEXT_PRIVATE_H_
#define BSLX_COSECONTEXT_PRIVATE_H_

#include <BPSecLib_Public.h>
#include <backend/CBOR.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct
{
    int64_t alg;
    BSL_Data_t tag;
} BSLX_CoseSc_Mac0_t;

void BSLX_CoseSc_Mac0_Init(BSLX_CoseSc_Mac0_t *obj);
void BSLX_CoseSc_Mac0_Deinit(BSLX_CoseSc_Mac0_t *obj);

/// Match ::BSL_CBOR_Encode_f signature
int BSLX_CoseSc_Mac0_Encode(QCBOREncodeContext *enc, const BSLX_CoseSc_Mac0_t *obj);

/// Match ::BSL_CBOR_Decode_f signature
int BSLX_CoseSc_Mac0_Decode(QCBORDecodeContext *enc, BSLX_CoseSc_Mac0_t *obj);

#ifdef __cplusplus
} // extern C
#endif

#endif /* BSLX_COSECONTEXT_PRIVATE_H_ */
