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
 * @ingroup backend_dyn
 * @brief Declaration of CBOR CODEC wrappers and interfaces.
 */
#ifndef BSLB_CBOR_H_
#define BSLB_CBOR_H_

#include <BPSecLib_Public.h>

#include <qcbor/qcbor_encode.h>
#include <qcbor/qcbor_spiffy_decode.h>

#ifdef __cplusplus
extern "C" {
#endif

#define UsefulBuf_FROM_BSL_Data(obj) \
   ((UsefulBuf) {(obj).ptr, (obj).len})

#define UsefulBufC_FROM_BSL_Data(obj) \
   ((UsefulBufC) {(obj).ptr, (obj).len})

/** Callback to actually perform the encoding.
 *
 * @param enc Non-null pointer to the encoder to use.
 * @param obj Pointer to the user data to encode.
 */
typedef int (*BSL_CBOR_Encode_f)(QCBOREncodeContext *enc, const void *obj);

/** Perform two-pass size-fitted encoding.
 *
 * @param[out] buf The already-initialized buffer to resize and write into.
 * @param func The encoding function which takes the user data.
 * @param obj Pointer to the user data to encode.
 * @return BSL_SUCCESS if successful
 */
int BSL_CBOR_Encode_Twopass(BSL_Data_t *buf, BSL_CBOR_Encode_f func, const void *obj);

/** Callback to actually perform the decoding.
 *
 * @param enc Non-null pointer to the decoder to use.
 * @param obj Pointer to the user data to decode into.
 */
typedef int (*BSL_CBOR_Decode_f)(QCBORDecodeContext *dec, const void *obj);

/** Perform size- and error-checked encoding.
 *
 * @param[in] buf The populated buffer to read from.
 * @param func The decoding function which takes the user data.
 * @param obj Pointer to the user data to encode.
 * @return BSL_SUCCESS if successful
 */
int BSL_CBOR_Decode(const BSL_Data_t *buf, BSL_CBOR_Decode_f func, const void *obj);

#ifdef __cplusplus
} // extern C
#endif

#endif /* BSLB_CBOR_H_ */
