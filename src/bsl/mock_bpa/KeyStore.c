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

#include <bsl/front/TextUtil.h>
#include <bsl/dynamic/CBOR.h>
#include <bsl/cose_sc/CoseMsg.h>

#include <jansson.h>
#include <m-bstring.h>
#include <m-dict.h>
#include <m-shared-ptr.h>
#include <m-string.h>

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

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
        .get_parameter = &MockBPA_KeyStore_GetKeyParameter,
        .update_stats  = &MockBPA_KeyStore_UpdateStats,
        .get_stats     = &MockBPA_KeyStore_GetStats,
    };
    return desc;
}

int MockBPA_KeyStore_LoadJwk(int fd)
{
    int retval = BSL_SUCCESS;

    json_error_t err;

    json_t *root = json_loadfd(fd, 0, &err);
    if (!root)
    {
        BSL_LOG_ERR("JSON error: line %d: %s", err.line, err.text);
        json_decref(root);
        return 1;
    }

    const json_t *keys = json_object_get(root, "keys");
    if (!keys || !json_is_array(keys))
    {
        BSL_LOG_ERR("Missing \"keys\" ");
        json_decref(root);
        return 1;
    }

    const size_t n = json_array_size(keys);
    BSL_LOG_INFO("Found %zu key objects", n);

    for (size_t i = 0; i < n; ++i)
    {
        const json_t *key_obj = json_array_get(keys, i);
        if (!json_is_object(key_obj))
        {
            continue;
        }

        const json_t *kty = json_object_get(key_obj, "kty");
        if (!kty)
        {
            BSL_LOG_ERR("Missing \"kty\" ");
            continue;
        }

        if (0 != strcmp("oct", json_string_value(kty)))
        {
            BSL_LOG_ERR("Not a symmetric key set");
            continue;
        }

        const json_t *kid = json_object_get(key_obj, "kid");
        if (!kid || !json_is_string(kid))
        {
            BSL_LOG_ERR("Missing \"kid\" ");
            continue;
        }
        const char *kid_str = json_string_value(kid);
        BSL_LOG_DEBUG("kid: %s", kid_str);

        const json_t *k = json_object_get(key_obj, "k");
        if (!k || !json_is_string(k))
        {
            BSL_LOG_ERR("Missing \"k\" ");
            continue;
        }

        BSL_Data_t k_data;
        BSL_Data_Init(&k_data);
        retval = BSL_TextUtil_Base64_Decode(&k_data, json_string_value(k), json_string_length(k));

        if (!retval)
        {
            BSL_Data_t kid_view = BSL_DATA_INIT_VIEW_CSTR(kid_str);

            BSL_Crypto_KeyHandle_t keyhandle;
            BSL_Crypto_LoadKey(k_data.ptr, k_data.len, &keyhandle);
            retval = MockBPA_KeyStore_AddKey(&kid_view, keyhandle);
            BSL_Crypto_ReleaseKeyHandle(keyhandle);
        }
        BSL_Data_Deinit(&k_data);

        if (retval)
        {
            BSL_LOG_ERR("JKW register failure");
            break;
        }
    }

    json_decref(root);
    return retval;
}

/** Decode a @c COSE_KeySet array.
 *  Matches ::BSL_CBOR_Decode_f signature.
 */
static int mock_bpa_key_registry_cosekey_decode(QCBORDecodeContext *dec, const void *obj _U_)
{
    int retval = BSL_SUCCESS;

    QCBORItem item;
    QCBORDecode_EnterArray(dec, NULL);

    // array-of-key-maps
    while (QCBOR_SUCCESS == QCBORDecode_PeekNext(dec, &item))
    {
        bool       has_kty = false;
        int64_t    kty     = 0;
        bool       has_alg = false;
        int64_t    alg     = 0;
        UsefulBufC kid     = NULLUsefulBufC;
        UsefulBufC baseiv  = NULLUsefulBufC;
        UsefulBufC k_data  = NULLUsefulBufC;

        QCBORDecode_EnterArray(dec, NULL); // using QCBOR_DECODE_MODE_MAP_AS_ARRAY

        while (QCBOR_SUCCESS == QCBORDecode_PeekNext(dec, &item))
        {
            int64_t label;
            QCBORDecode_GetInt64(dec, &label);
            if (QCBOR_SUCCESS != QCBORDecode_GetError(dec))
            {
                BSL_LOG_ERR("Unable to get key label");
                break;
            }
            BSL_LOG_DEBUG("got label %" PRId64, label);

            switch (label)
            {
                case BSLX_COSEMSG_KEY_PARAM_KTY:
                    QCBORDecode_GetInt64(dec, &kty);
                    has_kty = true;
                    break;
                case BSLX_COSEMSG_KEY_PARAM_KID:
                    QCBORDecode_GetByteString(dec, &kid);
                    break;
                case BSLX_COSEMSG_KEY_PARAM_ALG:
                    QCBORDecode_GetInt64(dec, &alg);
                    has_alg = true;
                    break;
                case BSLX_COSEMSG_KEY_PARAM_BASEIV:
                    QCBORDecode_GetByteString(dec, &baseiv);
                    break;
                case -1:
                    if (has_kty && (kty == 4))
                    {
                        QCBORDecode_GetByteString(dec, &k_data);
                    }
                    break;
                default:
                    // consume but ignore
                    QCBORDecode_VGetNextConsume(dec, &item);
                    break;
            }
            if (QCBOR_SUCCESS != QCBORDecode_GetError(dec))
            {
                BSL_LOG_ERR("Unable to get key value");
                break;
            }

            if (has_kty && (kty != 4))
            {
                BSL_LOG_WARNING("Ignoring non-symmetric key type %" PRId64, kty);
                break;
            }
        }
        QCBORDecode_ExitArray(dec);

        // If valid enough to store
        if (has_kty && kid.ptr && k_data.ptr)
        {
            BSL_Data_t kid_view;
            BSL_Data_InitView(&kid_view, kid.len, (BSL_DataPtr_t)kid.ptr);

            BSL_Crypto_KeyHandle_t keyhandle;
            BSL_Crypto_LoadKey(k_data.ptr, k_data.len, &keyhandle);

            if (has_alg)
            {
                BSL_IdValPair_SetInt64(MockBPA_KeyStore_SetKeyParameter(keyhandle, BSLX_COSEMSG_KEY_PARAM_ALG),
                                       BSLX_COSEMSG_KEY_PARAM_ALG, alg);
            }
            else
            {
                BSL_LOG_WARNING("COSE Key without an alg parameter");
            }

            if (baseiv.len > 0)
            {
                BSL_Data_t view;
                BSL_Data_InitView(&view, baseiv.len, (BSL_DataPtr_t)baseiv.ptr);
                BSL_IdValPair_SetBytestr(MockBPA_KeyStore_SetKeyParameter(keyhandle, BSLX_COSEMSG_KEY_PARAM_BASEIV),
                                         BSLX_COSEMSG_KEY_PARAM_BASEIV, view);
            }

            retval = MockBPA_KeyStore_AddKey(&kid_view, keyhandle);
            BSL_Crypto_ReleaseKeyHandle(keyhandle);
            BSL_LOG_DEBUG("Adding key result %d", retval);
            if (BSL_SUCCESS != retval)
            {
                BSL_LOG_ERR("Unable to store key");
                break;
            }
        }
    }
    QCBORDecode_ExitArray(dec);
    return retval;
}

int MockBPA_KeyStore_LoadCoseKeySet(int infd)
{
    struct stat sb;
    if ((fstat(infd, &sb) < 0) || (sb.st_size == 0))
    {
        BSL_LOG_ERR("Error getting file size");
        close(infd);
        return BSL_ERR_DECODING;
    }

    void *data = mmap(NULL, sb.st_size, PROT_READ, MAP_PRIVATE, infd, 0);
    if (!data)
    {
        BSL_LOG_ERR("Error in mmap");
        close(infd);
        return BSL_ERR_DECODING;
    }

    BSL_Data_t view;
    BSL_Data_InitView(&view, sb.st_size, (BSL_DataPtr_t)data);

    int retval = BSL_CBOR_Decode(&view, &mock_bpa_key_registry_cosekey_decode, NULL);

    if (munmap(data, sb.st_size) < 0)
    {
        BSL_LOG_ERR("Error in munmap");
    }
    close(infd);
    return retval;
}

int MockBPA_KeyStore_LoadFile(const char *file_path)
{
    int retval = BSL_SUCCESS;

    int infd = open(file_path, O_RDONLY);
    if (infd < 0)
    {
        BSL_LOG_ERR("Failed to open input file %s", file_path);
        return BSL_ERR_DECODING;
    }

    BSL_LOG_INFO("Reading keys from %s", file_path);
    m_string_t path;
    m_string_init_set_cstr(path, file_path);
    bool is_json = m_string_end_with_str_p(path, ".json");
    bool is_cbor = m_string_end_with_str_p(path, ".cbor");
    m_string_clear(path);

    if (is_json)
    {
        retval = MockBPA_KeyStore_LoadJwk(infd);
    }
    else if (is_cbor)
    {
        retval = MockBPA_KeyStore_LoadCoseKeySet(infd);
    }
    else
    {
        BSL_LOG_ERR("Unhandled key file extension for %s", file_path);
        retval = BSL_ERR_ARG_INVALID;
    }

    return retval;
}
