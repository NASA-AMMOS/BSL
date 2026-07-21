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
 * @ingroup mock_bpa
 * Provider of a key store via the crypto API ::BSL_KeyStore_Descriptors_t.
 */

#include "KeyStore.h"

#include <bsl/dynamic/IdValPair.h>

#include <m-bstring.h>
#include <m-dict.h>
#include <m-shared-ptr.h>

/**
 * Struct to hold private key information
 */
typedef struct BSL_CryptoKey_s
{
    /// Pointer to raw key information
    BSL_Data_t raw;
    /// Additional parameter dictionary
    BSLB_IdValPairPtrMap_t params;
    /// Statistics related to this key
    BSL_Crypto_KeyStats_t stats;
    /// Mutex for #stats
    pthread_mutex_t stats_mutex;
} BSL_CryptoKey_t;

static void BSL_CryptoKey_Init(BSL_CryptoKey_t *key)
{
    ASSERT_ARG_NONNULL(key);

    BSL_Data_Init(&(key->raw));
    BSLB_IdValPairPtrMap_init(key->params);

    for (uint64_t i = 0; i < BSL_CRYPTO_KEYSTATS_MAX_INDEX; i++)
    {
        key->stats.stats[i] = 0;
    }
    pthread_mutex_init(&key->stats_mutex, NULL);
}

static void BSL_CryptoKey_Deinit(BSL_CryptoKey_t *key)
{
    ASSERT_ARG_NONNULL(key);

    BSL_Data_Deinit(&(key->raw));
    BSLB_IdValPairPtrMap_clear(key->params);

    pthread_mutex_destroy(&key->stats_mutex);
    for (uint64_t i = 0; i < BSL_CRYPTO_KEYSTATS_MAX_INDEX; i++)
    {
        key->stats.stats[i] = 0;
    }
}

/** M*LIB OPLIST for ::BSL_CryptoKey_t
 */
#define M_OPL_BSL_CryptoKey_t() \
    M_OPEXTEND(M_POD_OPLIST, INIT(API_2(BSL_CryptoKey_Init)), INIT_SET(0), SET(0), CLEAR(API_2(BSL_CryptoKey_Deinit)))

/** @struct BSL_CryptoKeyPtr_t
 * Thread-safe shared pointer to memory-stable ::BSL_CryptoKey_t struct.
 */
/** @struct BSL_CryptoKeyDict_t
 * Stable dict of crypto keys (key: key ID | value: BSL_CryptoKeyPtr_t)
 */
/// @cond Doxygen_Suppress
// NOLINTBEGIN
// GCOV_EXCL_START
M_SHARED_PTR_DEF(BSL_CryptoKeyPtr, BSL_CryptoKey_t, M_OPL_BSL_CryptoKey_t())
#define M_OPL_BSL_CryptoKeyPtr() M_SHARED_PTR_OPLIST(BSL_CryptoKeyPtr, M_OPL_BSL_CryptoKey_t())
M_DICT_DEF2(BSL_CryptoKeyDict, m_bstring_t, M_BSTRING_OPLIST, BSL_CryptoKeyPtr_t *, M_OPL_BSL_CryptoKeyPtr())
// GCOV_EXCL_STOP
// NOLINTEND
/// @endcond

/// Crypto key registry
static BSL_CryptoKeyDict_t StaticKeyRegistry;
static pthread_mutex_t     StaticCryptoMutex = PTHREAD_MUTEX_INITIALIZER;

void MockBPA_KeyStore_Init(void)
{
    pthread_mutex_lock(&StaticCryptoMutex);
    BSL_CryptoKeyDict_init(StaticKeyRegistry);
    pthread_mutex_unlock(&StaticCryptoMutex);

    BSL_KeyStore_Init(MockBPA_KeyStore_Descriptors());
}

void MockBPA_KeyStore_Deinit(void)
{
    BSL_KeyStore_Deinit();

    pthread_mutex_lock(&StaticCryptoMutex);
    BSL_CryptoKeyDict_clear(StaticKeyRegistry);
    pthread_mutex_unlock(&StaticCryptoMutex);
}

int MockBPA_KeyStore_AddKey(const BSL_Data_t *keyid, BSL_Crypto_KeyHandle_t handle)
{
    ASSERT_ARG_NONNULL(keyid);
    CHK_ARG_NONNULL(handle);

    BSL_CryptoKeyPtr_t *key_ptr = handle;

    m_bstring_t keyid_str;
    m_bstring_init(keyid_str);
    m_bstring_push_back_bytes(keyid_str, keyid->len, keyid->ptr);

    pthread_mutex_lock(&StaticCryptoMutex);
    BSL_CryptoKeyDict_set_at(StaticKeyRegistry, keyid_str, key_ptr);
    pthread_mutex_unlock(&StaticCryptoMutex);

    m_bstring_clear(keyid_str);
    return 0;
}

int MockBPA_KeyStore_RemoveKey(const BSL_Data_t *keyid)
{
    ASSERT_ARG_NONNULL(keyid);

    m_bstring_t keyid_str;
    m_bstring_init(keyid_str);
    m_bstring_push_back_bytes(keyid_str, keyid->len, keyid->ptr);

    pthread_mutex_lock(&StaticCryptoMutex);
    int res = BSL_CryptoKeyDict_erase(StaticKeyRegistry, keyid_str);
    pthread_mutex_unlock(&StaticCryptoMutex);

    m_bstring_clear(keyid_str);
    return res ? BSL_SUCCESS : -1;
}

BSL_IdValPair_t *MockBPA_KeyStore_SetKeyParameter(BSL_Crypto_KeyHandle_t handle, int64_t param_id)
{
    ASSERT_ARG_NONNULL(handle);
    BSL_CryptoKey_t *key = BSL_CryptoKeyPtr_ref(handle);

    BSL_IdValPair_t *retval = NULL;
    if (key)
    {
        BSLB_IdValPairPtr_t *param_ptr;

        BSLB_IdValPairPtr_t **found = BSLB_IdValPairPtrMap_get(key->params, param_id);
        if (found)
        {
            param_ptr = *found;
            retval    = BSLB_IdValPairPtr_ref(param_ptr);
        }
        else
        {
            param_ptr = BSLB_IdValPairPtr_new();
            BSLB_IdValPairPtrMap_set_at(key->params, param_id, param_ptr);
            retval = BSLB_IdValPairPtr_ref(param_ptr);
            // map keeps a reference so this is safe
            BSLB_IdValPairPtr_release(param_ptr);
        }
    }
    return retval;
}

static int MockBPA_KeyStore_FindKey(const BSL_Data_t *keyid, BSL_Crypto_KeyHandle_t *handle)
{
    CHK_ARG_NONNULL(keyid);
    CHK_ARG_NONNULL(handle);

    m_bstring_t keyid_str;
    m_bstring_init(keyid_str);
    m_bstring_push_back_bytes(keyid_str, keyid->len, keyid->ptr);

    int retval = BSL_SUCCESS;
    pthread_mutex_lock(&StaticCryptoMutex);
    BSL_CryptoKeyPtr_t **found = BSL_CryptoKeyDict_get(StaticKeyRegistry, keyid_str);
    if (!found)
    {
        *handle = NULL;
        retval  = BSL_ERR_NOT_FOUND;
    }
    else
    {
        *handle = BSL_CryptoKeyPtr_acquire(*found);
    }
    pthread_mutex_unlock(&StaticCryptoMutex);

    m_bstring_clear(keyid_str);
    return retval;
}

static const BSL_IdValPair_t *MockBPA_KeyStore_GetKeyParameter(BSL_Crypto_KeyHandle_t handle, int64_t param_id)
{
    if (!handle)
    {
        return NULL;
    }
    BSL_CryptoKey_t *key = BSL_CryptoKeyPtr_ref(handle);

    const BSL_IdValPair_t *retval = NULL;
    if (key)
    {
        BSLB_IdValPairPtr_t **found = BSLB_IdValPairPtrMap_get(key->params, param_id);
        if (found)
        {
            retval = BSLB_IdValPairPtr_ref(*found);
        }
    }
    return retval;
}

static int MockBPA_KeyStore_New(BSL_Crypto_KeyHandle_t *handle)
{
    ASSERT_ARG_NONNULL(handle);
    *handle = BSL_CryptoKeyPtr_new();
    return BSL_SUCCESS;
}

static int MockBPA_KeyStore_SetKeymat(BSL_Crypto_KeyHandle_t handle, const BSL_Data_t *data)
{
    ASSERT_ARG_NONNULL(handle);
    ASSERT_ARG_NONNULL(data);
    BSL_CryptoKey_t *key = BSL_CryptoKeyPtr_ref(handle);
    return BSL_Data_CopyFrom(&key->raw, data->len, data->ptr);
}

static int MockBPA_KeyStore_GetKeymat(BSL_Crypto_KeyHandle_t handle, BSL_Data_t *data)
{
    ASSERT_ARG_NONNULL(handle);
    ASSERT_ARG_NONNULL(data);
    const BSL_CryptoKey_t *key = BSL_CryptoKeyPtr_ref(handle);
    BSL_Data_InitView(data, key->raw.len, key->raw.ptr);
    return BSL_SUCCESS;
}

static BSL_Crypto_KeyHandle_t MockBPA_KeyStore_Acquire(BSL_Crypto_KeyHandle_t handle)
{
    if (!handle)
    {
        return NULL;
    }

    BSL_CryptoKeyPtr_t *ptr = handle;
    return BSL_CryptoKeyPtr_acquire(ptr);
}

static void MockBPA_KeyStore_Release(BSL_Crypto_KeyHandle_t handle)
{
    if (!handle)
    {
        return;
    }

    BSL_CryptoKeyPtr_t *ptr = handle;
    BSL_CryptoKeyPtr_release(ptr);
}

static void MockBPA_KeyStore_UpdateStats(BSL_Crypto_KeyHandle_t handle, uint64_t use, uint64_t bytes)
{
    if (!handle)
    {
        return;
    }
    BSL_CryptoKey_t *key = BSL_CryptoKeyPtr_ref(handle);

    pthread_mutex_lock(&key->stats_mutex);
    key->stats.stats[BSL_CRYPTO_KEYSTATS_TIMES_USED] += use;
    key->stats.stats[BSL_CRYPTO_KEYSTATS_BYTES_PROCESSED] += bytes;
    pthread_mutex_unlock(&key->stats_mutex);
}

static int MockBPA_KeyStore_GetStats(BSL_Crypto_KeyHandle_t handle, BSL_Crypto_KeyStats_t *stats)
{
    CHK_ARG_NONNULL(handle);
    CHK_ARG_NONNULL(stats);

    BSL_CryptoKey_t *key = BSL_CryptoKeyPtr_ref(handle);

    pthread_mutex_lock(&key->stats_mutex);
    // copy as POD
    *stats = key->stats;
    pthread_mutex_unlock(&key->stats_mutex);

    return BSL_SUCCESS;
}

BSL_KeyStore_Descriptors_t MockBPA_KeyStore_Descriptors(void)
{
    BSL_KeyStore_Descriptors_t desc = {
        .new_key       = &MockBPA_KeyStore_New,
        .set_keymat    = &MockBPA_KeyStore_SetKeymat,
        .get_keymat    = &MockBPA_KeyStore_GetKeymat,
        .acquire_key   = &MockBPA_KeyStore_Acquire,
        .release_key   = &MockBPA_KeyStore_Release,
        .find_key      = &MockBPA_KeyStore_FindKey,
        .add_key = &MockBPA_KeyStore_AddKey,
        .get_parameter = &MockBPA_KeyStore_GetKeyParameter,
        .set_parameter = &MockBPA_KeyStore_SetKeyParameter,
        .update_stats  = &MockBPA_KeyStore_UpdateStats,
        .get_stats     = &MockBPA_KeyStore_GetStats,
    };
    return desc;
}
