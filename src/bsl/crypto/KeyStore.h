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
 * @ingroup crypto
 *
 * There are two forms of managed crypto keys in this interface:
 * 1. Identified keys persisted in a long-term, thread-safe registry.
 *    These keys have byte string names (which can contain UTF8 text) and can
 *    have additional parameters to restrict their use.
 * 2. Anonymous ephemeral keys used for individual operations and then discarded.
 *    These keys do not have names and are typically key-wrapped or the result of a
 *    key derivation function (KDF).
 */
#ifndef BSL_CRYPTO_KEYSTORE_H_
#define BSL_CRYPTO_KEYSTORE_H_

#include <stdint.h>

#include "bsl/front/Data.h"
#include "bsl/BPSecLib_Private.h" // TODO replace with Variant.h

#ifdef __cplusplus
extern "C" {
#endif

/** Opaque handle for key objects in the key store.
 */
typedef void *BSL_Crypto_KeyHandle_t;

/// Indices of telemetry counters in ::BSL_Crypto_KeyStats_t
typedef enum
{
    /// Incremented once per use.
    BSL_CRYPTO_KEYSTATS_TIMES_USED = 0,
    /** Incremented for each byte processed.
     * The specific meaning depends on the algorithm associated with the key.
     */
    BSL_CRYPTO_KEYSTATS_BYTES_PROCESSED,
    /// Not a real index, used to size arrays
    BSL_CRYPTO_KEYSTATS_MAX_INDEX
} BSL_Crypto_KeyStats_CounterIndex_t;

/**
 * Structure containing statistics for individual keys
 */
typedef struct
{
    /// Counters for each ::BSL_Crypto_KeyStats_CounterIndex_t value
    uint64_t stats[BSL_CRYPTO_KEYSTATS_MAX_INDEX];
} BSL_Crypto_KeyStats_t;

typedef struct
{
    /** Construct a new default empty key, outside of a key store.
     * @param[out] key_out The non-null pointer to set.
     * The handle must be released with #release_key when it is done being used.
     * @return BSL_SUCCESS if successful.
     */
    int (*new_key)(BSL_Crypto_KeyHandle_t *key_out);

    /** Acquire a new copy of a handle.
     * @param[in] handle The handle to acquire.
     * If NULL handle this is a do-nothing.
     * @return The copy, or NULL if failure.
     */
    BSL_Crypto_KeyHandle_t (*acquire_key)(BSL_Crypto_KeyHandle_t handle);

    /** Release the use of a handle.
     * @param[in] handle The handle to release.
     * If NULL handle this is a do-nothing.
     */
    void (*release_key)(BSL_Crypto_KeyHandle_t handle);

    int (*find_key)(const BSL_Data_t *key_id, BSL_Crypto_KeyHandle_t *handle);

    int (*set_keymat)(BSL_Crypto_KeyHandle_t handle, const BSL_Data_t *data);

    int (*get_keymat)(BSL_Crypto_KeyHandle_t handle, BSL_Data_t *view);

    const BSL_IdValPair_t *(*get_parameter)(BSL_Crypto_KeyHandle_t handle, int64_t param_id);

    /** @brief Update telemetry counters for a key.
     */
    void (*update_stats)(BSL_Crypto_KeyHandle_t handle, uint64_t use, uint64_t bytes);

    /** @brief Get full counters for a key.
     */
    int (*get_stats)(BSL_Crypto_KeyHandle_t handle, BSL_Crypto_KeyStats_t *stats);

} BSL_KeyStore_Descriptors_t;

/** Initialize the key store subsystem.
 * This must be called once per process.
 *
 * @warning This function is not thread safe and should be used before any
 * ::BSL_LibCtx_s is initialized or other BSL interfaces used.
 *
 * @param desc The descriptor to use for future key store access.
 * @return Zero if successful, negative on error.
 */
int BSL_KeyStore_Init(BSL_KeyStore_Descriptors_t desc);

/** Deinitialize the key store subsystem.
 * This should be called at the end of the process.
 *
 * @warning This function is not thread safe and should be used after any
 * ::BSL_LibCtx_s is deinitialized.
 */
void BSL_KeyStore_Deinit(void);

/**
 * Generate a new cryptographic key.
 * @param[in] key_length length of new key in bytes.
 * @param[out] key_out pointer to pointer for new key handle.
 * The handle must be released with BSL_Crypto_ReleaseKeyHandle() when it is done being used.
 */
int BSL_Crypto_GenKey(size_t key_length, BSL_Crypto_KeyHandle_t *key_out);

/**
 * Load a new cryptographic key.
 * @param[in] secret raw symmetric key.
 * @param secret_len length of @c secret data.
 * @param[out] key_out pointer to pointer for new key handle.
 * The handle must be released with BSL_Crypto_ReleaseKeyHandle() when it is done being used.
 */
int BSL_Crypto_LoadKey(const uint8_t *secret, size_t secret_len, BSL_Crypto_KeyHandle_t *key_out);

/** Release a key handle after it is done being used.
 *
 * @param[in] keyhandle key handle to release.
 * If the handle is null this does nothing.
 * @post If this is the last use of the handle (including the key registry) the key will be destroyed.
 */
void BSL_Crypto_ReleaseKeyHandle(BSL_Crypto_KeyHandle_t keyhandle);

/** Compare two keys in a time-invariant way.
 * This avoids side channel attacks which depend on comparison time.
 *
 * @param[in] hdl1 The first key handle.
 * @param[in] hdl2 The second key handle.
 * @return True if they compare equal.
 */
bool BSL_Crypto_CompareKeys(BSL_Crypto_KeyHandle_t hdl1, BSL_Crypto_KeyHandle_t hdl2);

/** Get pointers to an existing key, if present.
 *
 * @param keyid The key to search for.
 * @param[in, out] handle pointer to pointer for new key handle.
 * The handle must be released with BSL_Crypto_ReleaseKeyHandle() when it is done being used.
 * @return Zero if the key was present.
 */
int BSL_Crypto_GetRegistryKey(const BSL_Data_t *keyid, BSL_Crypto_KeyHandle_t *handle);

/** Get key parameter for read-only access.
 */
const BSL_IdValPair_t *BSL_Crypto_GetKeyParameter(BSL_Crypto_KeyHandle_t handle, int64_t param_id);

/**
 * Retrieve statistics related to a crypto key
 * @param[in] handle The handle of a key in the crypto registry to retrieve the stats of.
 * @param[out] stats struct containing statistics related to the key id
 */
int BSL_Crypto_GetKeyStatistics(BSL_Crypto_KeyHandle_t handle, BSL_Crypto_KeyStats_t *stats);

#ifdef __cplusplus
} // extern C
#endif

#endif /* BSL_CRYPTO_KEYSTORE_H_ */
