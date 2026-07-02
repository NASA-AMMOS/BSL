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
 * Header for COSE message structures @cite rfc9052.
 */

#ifndef BSLX_COSEMSG_H_
#define BSLX_COSEMSG_H_

#include <BSLMemory.h>
#include <backend/CBOR.h>
#include <backend/IdValPair.h>
#include <m-bptree.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Header parameters managed by IANA.
 * https://www.iana.org/assignments/cose/cose.xhtml#header-parameters
 */
enum BSLX_CoseMsg_Header_e
{
    BSLX_COSEMSG_HDR_ALG  = 1,
    BSLX_COSEMSG_HDR_CRIT = 2, // FIXME handle crit
    BSLX_COSEMSG_HDR_KID  = 4,
    /// IV as value type bytes
    BSLX_COSEMSG_HDR_IV = 5,
    /// Partial IV as value type bytes
    BSLX_COSEMSG_HDR_PARTIALIV = 6,
};

/** Algorithm code points managed by IANA.
 * https://www.iana.org/assignments/cose/cose.xhtml#algorithms
 */
enum BSLX_CoseMsg_Alg_e
{
    BSLX_COSEMSG_ALG_AES_GCM_128      = 1,
    BSLX_COSEMSG_ALG_AES_GCM_192      = 2,
    BSLX_COSEMSG_ALG_AES_GCM_256      = 3,
    BSLX_COSEMSG_ALG_HMAC_SHA_256_256 = 5,
    BSLX_COSEMSG_ALG_HMAC_SHA_384_384 = 6,
    BSLX_COSEMSG_ALG_HMAC_SHA_512_512 = 7,
};

/** Length of generated IV byte strings.
 * From https://www.rfc-editor.org/rfc/rfc9053.html#section-4.1
 * "This document fixes the size of the nonce at 96 bits."
 */
#define BSLX_COSEMSG_AESGCM_IV_LEN (12)

/** Key parameter code points managed by IANA.
 * https://www.iana.org/assignments/cose/cose.xhtml#key-common-parameters
 */
enum BSLX_CoseMsg_KeyParam_e
{
    /// Key type value as @c int64_t
    BSLX_COSEMSG_KEY_PARAM_KTY = 1,
    /// Key ID value as bytes
    BSLX_COSEMSG_KEY_PARAM_KID = 2,
    /// Algorithm value as @c int64_t
    BSLX_COSEMSG_KEY_PARAM_ALG = 3,
    /// Base IV value as bytes
    BSLX_COSEMSG_KEY_PARAM_BASEIV = 5,
};

/** @struct BSLX_CoseMsg_HdrMapTree_t
 * Defines an internal lookup dictionary for ::BSLB_IdValPairPtr_t pointers
 * which is sorted in CBOR deterministic order.
 */
// NOLINTBEGIN
/// @cond Doxygen_Suppress
// GCOV_EXCL_START
M_BPTREE_DEF2(BSLX_CoseMsg_HdrMapTree, 4, int64_t, M_OPEXTEND(M_BASIC_OPLIST, CMP(API_6(BSL_CBOR_Compare_Int64))),
              BSLB_IdValPairPtr_t *, M_OPL_BSLB_IdValPairPtr_t())
// GCOV_EXCL_STOP
/// @endcond
// NOLINTEND

/** Update a base map with an additional map, adding items when the key is not already present.
 *
 */
void BSLX_CoseMsg_HdrMapTree_update(BSLX_CoseMsg_HdrMapTree_t base, const BSLX_CoseMsg_HdrMapTree_t addl);

/** ncode a header parameter map.
 * Matches ::BSL_CBOR_Encode_f signature.
 */
int BSLX_CoseMsg_Headers_Encode_Map(QCBOREncodeContext *enc, const BSLX_CoseMsg_HdrMapTree_t *map);

/** Decode a header parameter map.
 * Matches ::BSL_CBOR_Encode_f signature.
 */
int BSLX_CoseMsg_Headers_Decode_Map(QCBORDecodeContext *dec, BSLX_CoseMsg_HdrMapTree_t *map);

/// Common header storage and logic
typedef struct
{
    /// Protected header bytes (the stable form)
    BSL_Data_t phdr_bstr;
    /// Protected header map, for decoding derived from #phdr_bstr
    BSLX_CoseMsg_HdrMapTree_t phdr;
    /// Unprotected header map
    BSLX_CoseMsg_HdrMapTree_t uhdr;

} BSLX_CoseMsg_Headers_t;
/// Initialize the struct
void BSLX_CoseMsg_Headers_Init(BSLX_CoseMsg_Headers_t *obj);
/// Deinitialize the struct
void BSLX_CoseMsg_Headers_Deinit(BSLX_CoseMsg_Headers_t *obj);
/// Match ::BSL_CBOR_Encode_f signature.
int BSLX_CoseMsg_Headers_Encode(QCBOREncodeContext *enc, const BSLX_CoseMsg_Headers_t *obj);
/// Match ::BSL_CBOR_Decode_f signature.
int BSLX_CoseMsg_Headers_Decode(QCBORDecodeContext *dec, BSLX_CoseMsg_Headers_t *obj);

/** Derive BSLX_CoseMsg_Headers_t::phdr_bstr from protected headers
 * in BSLX_CoseMsg_Headers_t::phdr.
 * This is needed before cryptographic calculation and encoding.
 */
int BSLX_CoseMsg_Headers_DerivePhdr(BSLX_CoseMsg_Headers_t *obj);

/** Get a desired header parameter.
 *
 * @param[in] obj The message to search.
 * @param label The label to search for.
 * @param need_phdr If true the parameter needs to be in the protected map.
 */
const BSL_IdValPair_t *BSLX_CoseMsg_Headers_Get(const BSLX_CoseMsg_Headers_t *obj, int64_t label, bool need_phdr);

/// Decoded COSE_Mac0
typedef struct
{
    /// Common headers
    BSLX_CoseMsg_Headers_t headers;
    /// The MAC tag bytes
    BSL_Data_t tag;
} BSLX_CoseMsg_Mac0_t;
/// Initialize the struct
void BSLX_CoseMsg_Mac0_Init(BSLX_CoseMsg_Mac0_t *obj);
/// Deinitialize the struct
void BSLX_CoseMsg_Mac0_Deinit(BSLX_CoseMsg_Mac0_t *obj);
/// Match ::BSL_CBOR_Encode_f signature.
int BSLX_CoseMsg_Mac0_Encode(QCBOREncodeContext *enc, const BSLX_CoseMsg_Mac0_t *obj);
/// Match ::BSL_CBOR_Decode_f signature.
int BSLX_CoseMsg_Mac0_Decode(QCBORDecodeContext *dec, BSLX_CoseMsg_Mac0_t *obj);

/** Decoded COSE_Encrypt0.
 * The use here is always with detached payload, so no ciphertext.
 */
typedef struct
{
    /// Common headers
    BSLX_CoseMsg_Headers_t headers;
} BSLX_CoseMsg_Encrypt0_t;
/// Initialize the struct
void BSLX_CoseMsg_Encrypt0_Init(BSLX_CoseMsg_Encrypt0_t *obj);
/// Deinitialize the struct
void BSLX_CoseMsg_Encrypt0_Deinit(BSLX_CoseMsg_Encrypt0_t *obj);
/// Match ::BSL_CBOR_Encode_f signature.
int BSLX_CoseMsg_Encrypt0_Encode(QCBOREncodeContext *enc, const BSLX_CoseMsg_Encrypt0_t *obj);
/// Match ::BSL_CBOR_Decode_f signature.
int BSLX_CoseMsg_Encrypt0_Decode(QCBORDecodeContext *dec, BSLX_CoseMsg_Encrypt0_t *obj);

#ifdef __cplusplus
} // extern C
#endif

#endif /* BSLX_COSEMSG_H_ */
