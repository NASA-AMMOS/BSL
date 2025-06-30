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
 * Private interface for Crypto interface to OpenSSL.
 * @ingroup backend_dyn
 */
#ifndef BSLP_DYNCRYPTO_H
#define BSLP_DYNCRYPTO_H

#include <CryptoInterface.h>
#include <DataContainers.h>

#include <m-dict.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/evperr.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <qcbor/UsefulBuf.h>
#include <qcbor/qcbor_decode.h>
#include <qcbor/qcbor_encode.h>

#ifdef __cplusplus
extern "C" {
#endif

/** @file
 * Backend header for cryptography implementation
 * @ingroup backend_dyn
 */

/**
 * Struct to hold private key information
 */
typedef struct BSL_CryptoKey_s
{
    /// Pointer to OpenSSL PKEY struct (used in hmac ctx)
    EVP_PKEY *pkey;
    /// Pointer to raw key information (used in cipher ctx)
    BSL_Data_t raw;
} BSL_CryptoKey_t;

/**
 * Add a new key to the crypto key registry
 * @param keyid key ID that crypto functions will use to access key
 * @param secret raw key data
 * @param secret_len length of raw key
 * @return Zero upon success.
 */
int BSL_CryptoTools_AddKeyToRegistry(uint64_t keyid, const uint8_t *secret, size_t secret_len);

/** Get pointers to an existing key, if present.
 *
 * @param keyid The key to search for.
 * @param[out] secret Pointer to the stored secret buffer, if successful.
 * @param[out] secret_len Pointer to the stored secret length, if successful.
 * @return Zero upon success.
 */
int BSL_CryptoTools_GetKeyFromRegistry(uint64_t keyid, const uint8_t **secret, size_t *secret_len);

/**
 * Deinitialize a key from dict.
 * Functional called when dict is clear'd
 * @param key key do deinitialize
 */
int BSL_CryptoKey_Deinit(BSL_CryptoKey_t *key);

// NOLINTBEGIN
/// @cond Doxygen_Suppress
#define M_OPL_BSL_CryptoKey_t() M_OPEXTEND(M_POD_OPLIST, CLEAR(API_2(BSL_CryptoKey_Deinit)))
/// Stable dict of crypto keys (key: key ID | value: key)
DICT_DEF2(BSL_CryptoKeyDict, uint64_t, M_BASIC_OPLIST, BSL_CryptoKey_t, M_OPL_BSL_CryptoKey_t())
/// @endcond
// NOLINTEND

#ifdef __cplusplus
} // extern C
#endif

#endif
