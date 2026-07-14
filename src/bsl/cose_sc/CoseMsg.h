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

#include <bsl/front/BSLMemory.h>
#include <bsl/dynamic/CBOR.h>
#include <bsl/dynamic/IdValPair.h>
#include <m-bptree.h>
#include <m-shared-ptr.h>
#include <m-array.h>

#ifdef __cplusplus
extern "C" {
#endif

/// Artificial limit on number of recipients supported
#define BSLX_COSEMSG_RECIPIENTS_LIMIT 10

/** Header parameters managed by IANA.
 * https://www.iana.org/assignments/cose/cose.xhtml#header-parameters
 */
enum BSLX_CoseMsg_Header_e
{
    /// Algorithm code point with value type int64
    BSLX_COSEMSG_HDR_ALG = 1,
    /// Critical parameters with value type raw (array of int)
    BSLX_COSEMSG_HDR_CRIT = 2,
    /// Content Type not used by BPSec
    BSLX_COSEMSG_HDR_CONTENTTYPE = 3,
    /// Key ID with value type bytes
    BSLX_COSEMSG_HDR_KID = 4,
    /// IV with value type bytes
    BSLX_COSEMSG_HDR_IV = 5,
    /// Partial IV with value type bytes
    BSLX_COSEMSG_HDR_PARTIALIV = 6,
    /// Key ID context with value type bytes
    BSLX_COSEMSG_HDR_KIDCONTEXT = 10,
    /// Salt for KDF with value type bytes
    BSLX_COSEMSG_HDR_SALT = -20,
};

/** Algorithm code points managed by IANA.
 * https://www.iana.org/assignments/cose/cose.xhtml#algorithms
 */
enum BSLX_CoseMsg_Alg_e
{
    /// direct+HKDF-SHA-512
    BSLX_COSEMSG_ALG_DIRECT_HKDF_SHA_512 = -11,
    /// direct+HKDF-SHA-256
    BSLX_COSEMSG_ALG_DIRECT_HKDF_SHA_256 = -10,
    /// direct
    BSLX_COSEMSG_ALG_DIRECT = -6,
    /// A256KW
    BSLX_COSEMSG_ALG_AES_KW_256 = -5,
    /// A256KW
    BSLX_COSEMSG_ALG_AES_KW_192 = -4,
    /// A256KW
    BSLX_COSEMSG_ALG_AES_KW_128 = -3,
    /// A128GCM
    BSLX_COSEMSG_ALG_AES_GCM_128 = 1,
    /// A192GCM
    BSLX_COSEMSG_ALG_AES_GCM_192 = 2,
    /// A256GCM
    BSLX_COSEMSG_ALG_AES_GCM_256 = 3,
    /// HMAC 256/256
    BSLX_COSEMSG_ALG_HMAC_SHA_256_256 = 5,
    /// HMAC 384/384
    BSLX_COSEMSG_ALG_HMAC_SHA_384_384 = 6,
    /// HMAC 512/512
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

/** Encode a header parameter map.
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
 *
 * @param[in,out] obj The headers to encode and store into.
 * @return BSL_SUCCESS if successful.
 */
int BSLX_CoseMsg_Headers_DerivePhdr(BSLX_CoseMsg_Headers_t *obj);

/** Check for the presence of @c crit header referencing unsupported parameters.
 *
 * @param[in] obj The headers to search.
 * @return BSL_SUCCESS if successful.
 */
int BSLX_CoseMsg_Headers_CheckCrit(const BSLX_CoseMsg_Headers_t *obj);

/** Get a desired header parameter.
 *
 * @param[in] obj The headers to search.
 * @param label The label to search for.
 * @param need_phdr If true the parameter needs to be in the protected map
 * when it is present. This does not imply that it needs to be present.
 * @return Non-null pointer when found, or NULL if not found.
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

/** Each recipient of a COSE_Mac or COSE_Encrypt.
 * This implementation does not support recursive recipients.
 */
typedef struct
{
    /// Recipient headers
    BSLX_CoseMsg_Headers_t headers;
    /** Ciphertext in this struct means encrypted content layer key.
     * When this is empty it means absent, encoded as null.
     */
    BSL_Data_t ciphertext;
} BSLX_CoseMsg_Recipient_t;

/// Initialize the struct
void BSLX_CoseMsg_Recipient_Init(BSLX_CoseMsg_Recipient_t *obj);
/// Deinitialize the struct
void BSLX_CoseMsg_Recipient_Deinit(BSLX_CoseMsg_Recipient_t *obj);
/// Match ::BSL_CBOR_Encode_f signature.
int BSLX_CoseMsg_Recipient_Encode(QCBOREncodeContext *enc, const BSLX_CoseMsg_Recipient_t *obj);
/// Match ::BSL_CBOR_Decode_f signature.
int BSLX_CoseMsg_Recipient_Decode(QCBORDecodeContext *dec, BSLX_CoseMsg_Recipient_t *obj);

/** @struct BSLX_CoseMsg_RecipientList_t
 * Defines an ordered list of ::BSLX_CoseMsg_Recipient_t shared pointers
 */
// NOLINTBEGIN
/// @cond Doxygen_Suppress
// GCOV_EXCL_START
#define M_OPL_BSLX_CoseMsg_Recipient_t() \
    (INIT(API_2(BSLX_CoseMsg_Recipient_Init)), CLEAR(API_2(BSLX_CoseMsg_Recipient_Deinit)), INIT_SET(0), SET(0))
M_SHARED_WEAK_PTR_DEF(BSLX_CoseMsg_RecipientPtr, BSLX_CoseMsg_Recipient_t, M_OPL_BSLX_CoseMsg_Recipient_t())
#define M_OPL_BSLX_CoseMsg_RecipientPtr_t() \
    M_SHARED_PTR_OPLIST(BSLX_CoseMsg_RecipientPtr, M_OPL_BSLX_CoseMsg_Recipient_t())
M_ARRAY_DEF(BSLX_CoseMsg_RecipientList, BSLX_CoseMsg_RecipientPtr_t *, M_OPL_BSLX_CoseMsg_RecipientPtr_t())
// GCOV_EXCL_STOP
/// @endcond
// NOLINTEND

/// Resize recipients array, preserving existing if possible
void BSLX_CoseMsg_RecipientList_ResizeNew(BSLX_CoseMsg_RecipientList_t obj, size_t size);

/// Decoded COSE_Mac
typedef struct
{
    /// Common headers
    BSLX_CoseMsg_Headers_t headers;
    /// The MAC tag bytes
    BSL_Data_t tag;
    /** Array of ::BSLX_CoseMsg_Recipient_t instances.
     */
    BSLX_CoseMsg_RecipientList_t recipients;
} BSLX_CoseMsg_Mac_t;
/// Initialize the struct
void BSLX_CoseMsg_Mac_Init(BSLX_CoseMsg_Mac_t *obj);
/// Deinitialize the struct
void BSLX_CoseMsg_Mac_Deinit(BSLX_CoseMsg_Mac_t *obj);
/// Match ::BSL_CBOR_Encode_f signature.
int BSLX_CoseMsg_Mac_Encode(QCBOREncodeContext *enc, const BSLX_CoseMsg_Mac_t *obj);
/// Match ::BSL_CBOR_Decode_f signature.
int BSLX_CoseMsg_Mac_Decode(QCBORDecodeContext *dec, BSLX_CoseMsg_Mac_t *obj);

/** Decoded COSE_Encrypt.
 * The use here is always with detached payload, so no ciphertext.
 */
typedef struct
{
    /// Content headers
    BSLX_CoseMsg_Headers_t headers;
    /** Array of ::BSLX_CoseMsg_Recipient_t instances.
     */
    BSLX_CoseMsg_RecipientList_t recipients;
} BSLX_CoseMsg_Encrypt_t;
/// Initialize the struct
void BSLX_CoseMsg_Encrypt_Init(BSLX_CoseMsg_Encrypt_t *obj);
/// Deinitialize the struct
void BSLX_CoseMsg_Encrypt_Deinit(BSLX_CoseMsg_Encrypt_t *obj);
/// Match ::BSL_CBOR_Encode_f signature.
int BSLX_CoseMsg_Encrypt_Encode(QCBOREncodeContext *enc, const BSLX_CoseMsg_Encrypt_t *obj);
/// Match ::BSL_CBOR_Decode_f signature.
int BSLX_CoseMsg_Encrypt_Decode(QCBORDecodeContext *dec, BSLX_CoseMsg_Encrypt_t *obj);

#ifdef __cplusplus
} // extern C
#endif

#endif /* BSLX_COSEMSG_H_ */
