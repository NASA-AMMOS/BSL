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
 * Backend cryptography implementation
 * @ingroup backend_dyn
 */
#include "CryptoInterface.h"
#include <bsl/BPSecLib_Private.h>
#include <bsl/front/TextUtil.h>
#include <bsl/dynamic/IdValPair.h>

#include <m-dict.h>
#include <m-shared-ptr.h>
#include <m-bstring.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/kdf.h>

#if defined(HAVE_VALGRIND)
#include <valgrind/memcheck.h>
#endif /* defined(HAVE_VALGRIND) */

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

/// Random bytes generator
static BSL_Crypto_RandBytesFn rand_bytes_generator;

/// Crypto key registry
static BSL_CryptoKeyDict_t StaticKeyRegistry;
static pthread_mutex_t     StaticCryptoMutex = PTHREAD_MUTEX_INITIALIZER;

void BSL_CryptoInit(void)
{
    pthread_mutex_lock(&StaticCryptoMutex);
    BSL_CryptoKeyDict_init(StaticKeyRegistry);
    pthread_mutex_unlock(&StaticCryptoMutex);
    rand_bytes_generator = RAND_bytes;
}

void BSL_CryptoDeinit(void)
{
    pthread_mutex_lock(&StaticCryptoMutex);
    BSL_CryptoKeyDict_clear(StaticKeyRegistry);
    pthread_mutex_unlock(&StaticCryptoMutex);
}

void BSL_Crypto_SetRngGenerator(BSL_Crypto_RandBytesFn rand_gen_fn)
{
    rand_bytes_generator = rand_gen_fn;
}

void BSL_Crypto_ReleaseKeyHandle(BSL_Crypto_KeyHandle_t keyhandle)
{
    if (!keyhandle)
    {
        return;
    }

    BSL_CryptoKeyPtr_t *ptr = keyhandle;
    BSL_CryptoKeyPtr_release(ptr);
}

bool BSL_Crypto_CompareKeys(BSL_Crypto_KeyHandle_t hdl1, BSL_Crypto_KeyHandle_t hdl2)
{
    if (!hdl1 || !hdl2)
    {
        return false;
    }
    const BSL_CryptoKey_t *key1 = BSL_CryptoKeyPtr_ref(hdl1);
    const BSL_CryptoKey_t *key2 = BSL_CryptoKeyPtr_ref(hdl2);

    return BSL_Crypto_Compare(key1->raw.ptr, key1->raw.len, key2->raw.ptr, key2->raw.len);
}

int BSL_Crypto_UnwrapKey(BSL_Crypto_KeyHandle_t kek_handle, const BSL_Data_t *wrapped_key,
                         BSL_Crypto_KeyHandle_t *cek_handle)
{
    ASSERT_ARG_NONNULL(kek_handle);
    ASSERT_ARG_NONNULL(wrapped_key);
    ASSERT_ARG_NONNULL(cek_handle);

    BSL_CryptoKey_t *kek = BSL_CryptoKeyPtr_ref(kek_handle);

    *cek_handle = NULL;

    const EVP_CIPHER *cipher;
    switch (kek->raw.len)
    {
        case 16:
        {
            cipher = EVP_aes_128_wrap();
            break;
        }
        case 24:
        {
            cipher = EVP_aes_192_wrap();
            break;
        }
        case 32:
        {
            cipher = EVP_aes_256_wrap();
            break;
        }
        default:
        {
            BSL_LOG_DEBUG("UNWRAP AES MODE INVALID");
            return BSL_ERR_SECURITY_CONTEXT_CRYPTO_FAILED;
        }
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    CHK_PROPERTY(ctx != NULL);

    BSL_CryptoKeyPtr_t *cek_ptr = BSL_CryptoKeyPtr_new();
    // managed struct
    BSL_CryptoKey_t *cek = BSL_CryptoKeyPtr_ref(cek_ptr);
    CHK_PROPERTY(cek != NULL);

    // wrapped key always 8 bytes greater than CEK @cite rfc3394 (2.2.1)
    BSL_Data_Resize(&cek->raw, wrapped_key->len - 8);

    BSL_LOG_PLAINTEXT_PTR("using KEK", cek_handle, kek->raw.ptr, kek->raw.len);
    int dec_result = EVP_DecryptInit_ex(ctx, cipher, NULL, kek->raw.ptr, NULL);
    if (dec_result != 1)
    {
        BSL_LOG_ERR("EVP_DecryptInit_ex: %s", ERR_error_string(ERR_get_error(), NULL));
        BSL_CryptoKeyPtr_release(cek_ptr);
        return BSL_ERR_SECURITY_CONTEXT_CRYPTO_FAILED;
    }
    EVP_CIPHER_CTX_set_padding(ctx, 0);

    pthread_mutex_lock(&kek->stats_mutex);
    kek->stats.stats[BSL_CRYPTO_KEYSTATS_TIMES_USED]++;
    kek->stats.stats[BSL_CRYPTO_KEYSTATS_BYTES_PROCESSED] += cek->raw.len;
    pthread_mutex_unlock(&kek->stats_mutex);

    int out_len = (int)cek->raw.len;
    BSL_LOG_PLAINTEXT_PTR("wrapped key", cek_handle, wrapped_key->ptr, wrapped_key->len);
    int decrypt_res = EVP_DecryptUpdate(ctx, cek->raw.ptr, &out_len, wrapped_key->ptr, wrapped_key->len);
    if (decrypt_res != 1)
    {
        BSL_LOG_ERR("EVP_DecryptUpdate: %s", ERR_error_string(ERR_get_error(), NULL));
        EVP_CIPHER_CTX_free(ctx);
        BSL_CryptoKeyPtr_release(cek_ptr);
        return BSL_ERR_SECURITY_CONTEXT_CRYPTO_FAILED;
    }
    cek->raw.len = (size_t)out_len;

    uint8_t buf[EVP_CIPHER_CTX_block_size(ctx)];
    int     final_len = 0;
    int     res       = EVP_DecryptFinal_ex(ctx, buf, &final_len);
    if (res != 1)
    {
        BSL_LOG_ERR("Failed DecryptFinal: %s", ERR_error_string(ERR_get_error(), NULL));
        EVP_CIPHER_CTX_free(ctx);
        BSL_CryptoKeyPtr_release(cek_ptr);
        return BSL_ERR_SECURITY_CONTEXT_CRYPTO_FAILED;
    }

    if (final_len > 0)
    {
        BSL_Data_AppendFrom(&cek->raw, (size_t)final_len, buf);
    }

    EVP_CIPHER_CTX_free(ctx);
    BSL_LOG_PLAINTEXT_PTR("unwrapped key", cek, cek->raw.ptr, cek->raw.len);

    *cek_handle = cek_ptr;
    return 0;
}

int BSL_Crypto_WrapKey(BSL_Crypto_KeyHandle_t kek_handle, BSL_Crypto_KeyHandle_t cek_handle, BSL_Data_t *wrapped_key)
{
    CHK_ARG_NONNULL(kek_handle);
    CHK_ARG_NONNULL(cek_handle);
    CHK_ARG_NONNULL(wrapped_key);

    BSL_CryptoKey_t *kek = BSL_CryptoKeyPtr_ref(kek_handle);
    BSL_CryptoKey_t *cek = BSL_CryptoKeyPtr_ref(cek_handle);

    const EVP_CIPHER *cipher;
    switch (kek->raw.len)
    {
        case 16:
        {
            cipher = EVP_aes_128_wrap();
            break;
        }
        case 24:
        {
            cipher = EVP_aes_192_wrap();
            break;
        }
        case 32:
        {
            cipher = EVP_aes_256_wrap();
            break;
        }
        default:
        {
            BSL_LOG_DEBUG("WRAP AES MODE INVALID");
            return BSL_ERR_SECURITY_CONTEXT_CRYPTO_FAILED;
        }
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL)
    {
        BSL_LOG_ERR("Could not create cipher context");
        return -1;
    }

    BSL_LOG_PLAINTEXT_PTR("using KEK", cek_handle, kek->raw.ptr, kek->raw.len);
    int enc_result = EVP_EncryptInit_ex(ctx, cipher, NULL, kek->raw.ptr, NULL);
    if (!enc_result)
    {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    pthread_mutex_lock(&kek->stats_mutex);
    kek->stats.stats[BSL_CRYPTO_KEYSTATS_TIMES_USED]++;
    kek->stats.stats[BSL_CRYPTO_KEYSTATS_BYTES_PROCESSED] += cek->raw.len;
    pthread_mutex_unlock(&kek->stats_mutex);

    // wrapped key always 8 bytes greater than CEK @cite rfc3394 (2.2.1)
    BSL_Data_Resize(wrapped_key, cek->raw.len + 8);

    int out_len = (int)wrapped_key->len;
    BSL_LOG_PLAINTEXT_PTR("unwrapped key", cek_handle, cek->raw.ptr, cek->raw.len);
    if (!EVP_EncryptUpdate(ctx, (unsigned char *)wrapped_key->ptr, &out_len, cek->raw.ptr, cek->raw.len))
    {
        EVP_CIPHER_CTX_free(ctx);
        return -2;
    }
    wrapped_key->len = (size_t)out_len;

    uint8_t buf[EVP_CIPHER_CTX_block_size(ctx)];
    int     final_len = 0;
    if (!EVP_EncryptFinal_ex(ctx, buf, &final_len))
    {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    if (final_len > 0)
    {
        BSL_Data_AppendFrom(&cek->raw, final_len, buf);
    }

    EVP_CIPHER_CTX_free(ctx);
    BSL_LOG_PLAINTEXT_PTR("wrapped key", cek_handle, wrapped_key->ptr, wrapped_key->len);

    return 0;
}

// work-around allowance for empty salt and info
static const uint8_t BSL_Crypto_zero = 0;

#define BSL_Crypto_PtrOrZero(ptr) (ptr) ? (ptr) : (void *)&BSL_Crypto_zero

int BSL_Crypto_KDF(BSL_Crypto_KeyHandle_t kdk_handle, BSL_Crypto_KDFVariant_t func, const BSL_Data_t *salt,
                   const BSL_Data_t *info, size_t keylen, BSL_Crypto_KeyHandle_t *cek_handle)
{
    CHK_ARG_NONNULL(kdk_handle);
    CHK_ARG_NONNULL(salt);
    CHK_ARG_NONNULL(info);
    CHK_ARG_NONNULL(cek_handle);
    CHK_PRECONDITION(keylen > 0);

    char *digest_name;
    switch (func)
    {
        case BSL_CRYPTO_KDF_HKDF_SHA_256:
            digest_name = SN_sha256;
            break;
        case BSL_CRYPTO_KDF_HKDF_SHA_512:
            digest_name = SN_sha512;
            break;
        default:
            BSL_LOG_ERR("Invalid KDF func %d", func);
            return BSL_ERR_SECURITY_CONTEXT_CRYPTO_FAILED;
    }

    BSL_CryptoKey_t *kdk = BSL_CryptoKeyPtr_ref(kdk_handle);
    CHK_PRECONDITION(kdk->raw.len > 0);

    BSL_CryptoKeyPtr_t *cek_ptr = BSL_CryptoKeyPtr_new();
    // managed struct
    BSL_CryptoKey_t *cek = BSL_CryptoKeyPtr_ref(cek_ptr);
    CHK_PROPERTY(cek != NULL);

    if (BSL_SUCCESS != BSL_Data_Resize(&cek->raw, keylen))
    {
        BSL_CryptoKeyPtr_release(cek_ptr);
        return BSL_ERR_SECURITY_CONTEXT_CRYPTO_FAILED;
    }

    int retval = BSL_SUCCESS;

    EVP_KDF *kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
    if (!kdf)
    {
        BSL_LOG_ERR("EVP_KDF_fetch: %s", ERR_error_string(ERR_get_error(), NULL));
        retval = BSL_ERR_SECURITY_CONTEXT_CRYPTO_FAILED;
    }

    EVP_KDF_CTX *kctx = NULL;
    if (BSL_SUCCESS == retval)
    {
        kctx = EVP_KDF_CTX_new(kdf);
        if (!kctx)
        {
            BSL_LOG_ERR("EVP_KDF_CTX_new: %s", ERR_error_string(ERR_get_error(), NULL));
            retval = BSL_ERR_SECURITY_CONTEXT_CRYPTO_FAILED;
        }
    }
    if (kdf)
    {
        EVP_KDF_free(kdf);
    }

    if (BSL_SUCCESS == retval)
    {
        OSSL_PARAM  params[5];
        OSSL_PARAM *par = params;

        *par++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, digest_name, strlen(digest_name));
        BSL_LOG_PLAINTEXT_PTR("using key", kctx, kdk->raw.ptr, kdk->raw.len);
        *par++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, kdk->raw.ptr, kdk->raw.len);
        BSL_LOG_PLAINTEXT_PTR("using salt", kctx, salt->ptr, salt->len);
        *par++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, BSL_Crypto_PtrOrZero(salt->ptr), salt->len);
        BSL_LOG_PLAINTEXT_PTR("using info", kctx, info->ptr, info->len);
        *par++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, BSL_Crypto_PtrOrZero(info->ptr), info->len);
        *par   = OSSL_PARAM_construct_end();

        pthread_mutex_lock(&kdk->stats_mutex);
        kdk->stats.stats[BSL_CRYPTO_KEYSTATS_TIMES_USED]++;
        kdk->stats.stats[BSL_CRYPTO_KEYSTATS_BYTES_PROCESSED] += cek->raw.len;
        pthread_mutex_unlock(&kdk->stats_mutex);

        int res = EVP_KDF_derive(kctx, cek->raw.ptr, cek->raw.len, params);
        BSL_LOG_DEBUG("EVP_KDF_derive gave %zu bytes, return %d", cek->raw.len, res);
        BSL_LOG_PLAINTEXT_PTR("KDF out", kctx, cek->raw.ptr, cek->raw.len);
        if (res <= 0)
        {
            BSL_LOG_ERR("EVP_KDF_derive: %s", ERR_error_string(ERR_get_error(), NULL));
            retval = BSL_ERR_SECURITY_CONTEXT_CRYPTO_FAILED;
        }
    }
    if (kctx)
    {
        EVP_KDF_CTX_free(kctx);
    }

    if (BSL_SUCCESS == retval)
    {
        *cek_handle = cek_ptr;
    }
    else
    {
        *cek_handle = NULL;
        BSL_CryptoKeyPtr_release(cek_ptr);
    }
    return retval;
}

int BSL_AuthCtx_Init(BSL_AuthCtx_t *hmac_ctx, BSL_Crypto_KeyHandle_t keyhandle, BSL_Crypto_SHAVariant_e sha_var)
{
    CHK_ARG_NONNULL(hmac_ctx);
    CHK_ARG_NONNULL(keyhandle);

    char *digest_name;
    switch (sha_var)
    {
        case BSL_CRYPTO_SHA_256:
            digest_name = SN_sha256;
            break;
        case BSL_CRYPTO_SHA_384:
            digest_name = SN_sha384;
            break;
        case BSL_CRYPTO_SHA_512:
            digest_name = SN_sha512;
            break;
        default:
            BSL_LOG_ERR("Invalid SHA variant %d", sha_var);
            return BSL_ERR_SECURITY_CONTEXT_CRYPTO_FAILED;
    }

    hmac_ctx->keyhandle = BSL_CryptoKeyPtr_acquire(keyhandle);

    BSL_CryptoKey_t *key_info = BSL_CryptoKeyPtr_ref(hmac_ctx->keyhandle);
    CHK_PRECONDITION(key_info->raw.len > 0);

    EVP_MAC *mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
    CHK_PRECONDITION(mac != NULL);

    hmac_ctx->libhandle = EVP_MAC_CTX_new(mac);
    EVP_MAC_free(mac);
    CHK_PRECONDITION(hmac_ctx->libhandle != NULL);

    OSSL_PARAM params[2];
    {
        OSSL_PARAM *par = params;
        *par++          = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, digest_name, strlen(digest_name));
        *par++          = OSSL_PARAM_construct_end();
    }

    BSL_LOG_PLAINTEXT_PTR("using key", hmac_ctx, key_info->raw.ptr, key_info->raw.len);
    int res = EVP_MAC_init(hmac_ctx->libhandle, key_info->raw.ptr, key_info->raw.len, params);
    CHK_PROPERTY(res == 1);

    hmac_ctx->block_size = EVP_MAC_CTX_get_block_size(hmac_ctx->libhandle);
    if (hmac_ctx->block_size == 0)
    {
        hmac_ctx->block_size = 1024;
        BSL_LOG_ERR("invalid block size zero, assuming %zu", hmac_ctx->block_size);
    }

    res = BSL_Data_InitBuffer(&hmac_ctx->in_buf, hmac_ctx->block_size);
    CHK_PROPERTY(!res);

    pthread_mutex_lock(&key_info->stats_mutex);
    key_info->stats.stats[BSL_CRYPTO_KEYSTATS_TIMES_USED]++;
    pthread_mutex_unlock(&key_info->stats_mutex);

    return 0;
}

int BSL_AuthCtx_DigestBuffer(BSL_AuthCtx_t *hmac_ctx, const void *data, size_t data_len)
{
    ASSERT_ARG_NONNULL(hmac_ctx);
    ASSERT_ARG_NONNULL(data);
    CHK_PRECONDITION(data_len > 0);
    CHK_PRECONDITION(data_len <= INT_MAX);

    BSL_LOG_PLAINTEXT_PTR("data in", hmac_ctx, data, data_len);
    int res = EVP_MAC_update(hmac_ctx->libhandle, data, data_len);
    BSL_LOG_DEBUG("EVP_MAC_update took %zu bytes, return %d", data_len, res);
    CHK_PROPERTY(res == 1);

    BSL_CryptoKey_t *key_info = BSL_CryptoKeyPtr_ref(hmac_ctx->keyhandle);
    pthread_mutex_lock(&key_info->stats_mutex);
    key_info->stats.stats[BSL_CRYPTO_KEYSTATS_BYTES_PROCESSED] += data_len;
    pthread_mutex_unlock(&key_info->stats_mutex);

    return 0;
}

int BSL_AuthCtx_DigestSeq(BSL_AuthCtx_t *hmac_ctx, BSL_SeqReader_t *reader)
{
    ASSERT_ARG_NONNULL(hmac_ctx);
    ASSERT_ARG_NONNULL(reader);

    BSL_CryptoKey_t *key_info = BSL_CryptoKeyPtr_ref(hmac_ctx->keyhandle);

    while (true)
    {
        // read until there is no more
        size_t block_size = hmac_ctx->block_size;
        BSL_SeqReader_Get(reader, hmac_ctx->in_buf.ptr, &block_size);
        if (block_size == 0)
        {
            break;
        }

        BSL_LOG_PLAINTEXT_PTR("data in", hmac_ctx, hmac_ctx->in_buf.ptr, block_size);
        int res = EVP_MAC_update(hmac_ctx->libhandle, hmac_ctx->in_buf.ptr, block_size);
        BSL_LOG_DEBUG("EVP_MAC_update took %zu bytes, return %d", block_size, res);
        CHK_PROPERTY(res == 1);

        pthread_mutex_lock(&key_info->stats_mutex);
        key_info->stats.stats[BSL_CRYPTO_KEYSTATS_BYTES_PROCESSED] += block_size;
        pthread_mutex_unlock(&key_info->stats_mutex);
    }

    return 0;
}

int BSL_AuthCtx_Finalize(BSL_AuthCtx_t *hmac_ctx, BSL_Data_t *tag)
{
    ASSERT_ARG_NONNULL(hmac_ctx);
    ASSERT_ARG_NONNULL(tag);

    // get the needed tag size
    size_t size = EVP_MAC_CTX_get_mac_size(hmac_ctx->libhandle);
    CHK_PROPERTY(size > 0);
    CHK_PROPERTY(size <= INT_MAX);
    BSL_Data_Resize(tag, size);

    int res = EVP_MAC_final(hmac_ctx->libhandle, tag->ptr, &size, tag->len);
    BSL_LOG_DEBUG("EVP_MAC_final gave %zu bytes, return %d", size, res);
    CHK_PROPERTY(res == 1);
    BSL_LOG_PLAINTEXT_PTR("tag out", hmac_ctx, tag->ptr, size);

    return 0;
}

void BSL_AuthCtx_Deinit(BSL_AuthCtx_t *hmac_ctx)
{
    ASSERT_ARG_NONNULL(hmac_ctx);

    BSL_Data_Deinit(&hmac_ctx->in_buf);
    EVP_MAC_CTX_free(hmac_ctx->libhandle);
    BSL_CryptoKeyPtr_release(hmac_ctx->keyhandle);
    memset(hmac_ctx, 0, sizeof(BSL_AuthCtx_t));
}

bool BSL_Crypto_Compare(const void *data1, size_t size1, const void *data2, size_t size2)
{
    if (!data1 || !data2 || (size1 != size2))
    {
        return false;
    }
    return CRYPTO_memcmp(data1, data2, size1) == 0;
}

int BSL_Cipher_Init(BSL_Cipher_t *cipher_ctx, BSL_CipherMode_e enc, BSL_Crypto_AESVariant_e aes_var,
                    const BSL_Data_t *iv_val, BSL_Crypto_KeyHandle_t keyhandle)
{
    ASSERT_ARG_NONNULL(cipher_ctx);
    ASSERT_ARG_NONNULL(iv_val);
    ASSERT_ARG_NONNULL(keyhandle);
    CHK_PRECONDITION(iv_val->len > 0);
    CHK_PRECONDITION(iv_val->len <= INT_MAX);

    memset(cipher_ctx, 0, sizeof(*cipher_ctx));

    cipher_ctx->keyhandle = BSL_CryptoKeyPtr_acquire(keyhandle);

    BSL_CryptoKey_t *key = BSL_CryptoKeyPtr_ref(cipher_ctx->keyhandle);

    cipher_ctx->libhandle   = EVP_CIPHER_CTX_new();
    cipher_ctx->enc         = enc;
    cipher_ctx->AES_variant = aes_var;

    const EVP_CIPHER *cipher = NULL;
    switch (cipher_ctx->AES_variant)
    {
        case BSL_CRYPTO_AES_128:
            cipher = EVP_aes_128_gcm();
            break;
        case BSL_CRYPTO_AES_256:
            cipher = EVP_aes_256_gcm();
            break;
        case BSL_CRYPTO_AES_192:
        default:
            BSL_LOG_ERR("Invalid AES variant");
            return BSL_ERR_FAILURE;
    }

    int res =
        EVP_CipherInit_ex(cipher_ctx->libhandle, cipher, NULL, NULL, NULL, (cipher_ctx->enc == BSL_CRYPTO_ENCRYPT));
    CHK_PROPERTY(res == 1);

    cipher_ctx->block_size = (size_t)EVP_CIPHER_get_block_size(cipher_ctx->libhandle);
    if (cipher_ctx->block_size == 0)
    {
        cipher_ctx->block_size = 1024;
        BSL_LOG_ERR("invalid block size zero, assuming %zu", cipher_ctx->block_size);
    }

    res = EVP_CIPHER_CTX_ctrl(cipher_ctx->libhandle, EVP_CTRL_GCM_SET_IVLEN, (int)iv_val->len, NULL);
    CHK_PROPERTY(res == 1);

    BSL_LOG_PLAINTEXT_PTR("using key", cipher_ctx, key->raw.ptr, key->raw.len);
    BSL_LOG_PLAINTEXT_PTR("using IV", cipher_ctx, iv_val->ptr, iv_val->len);
    res = EVP_CipherInit_ex(cipher_ctx->libhandle, NULL, NULL, key->raw.ptr, iv_val->ptr, -1);
    CHK_PROPERTY(res == 1);

    res = BSL_Data_InitBuffer(&cipher_ctx->in_buf, cipher_ctx->block_size);
    CHK_PROPERTY(!res);

    res = BSL_Data_InitBuffer(&cipher_ctx->out_buf, cipher_ctx->block_size);
    CHK_PROPERTY(!res);

    pthread_mutex_lock(&key->stats_mutex);
    key->stats.stats[BSL_CRYPTO_KEYSTATS_TIMES_USED]++;
    pthread_mutex_unlock(&key->stats_mutex);

    return 0;
}

int BSL_Cipher_AddAadBuffer(BSL_Cipher_t *cipher_ctx, const void *aad, size_t aad_len)
{
    ASSERT_ARG_NONNULL(cipher_ctx);
    ASSERT_ARG_NONNULL(aad);
    CHK_PRECONDITION(aad_len > 0);
    CHK_PRECONDITION(aad_len <= INT_MAX);

    // len needs to be passed as output
    int len = 0;
    BSL_LOG_PLAINTEXT_PTR("AAD in", cipher_ctx, aad, aad_len);
    int res = EVP_CipherUpdate(cipher_ctx->libhandle, NULL, &len, aad, (int)aad_len);
    BSL_LOG_DEBUG("EVP_CipherUpdate took %zu bytes, return %d", aad_len, res);
    CHK_PROPERTY(res == 1);

    BSL_CryptoKey_t *key = BSL_CryptoKeyPtr_ref(cipher_ctx->keyhandle);
    pthread_mutex_lock(&key->stats_mutex);
    key->stats.stats[BSL_CRYPTO_KEYSTATS_BYTES_PROCESSED] += aad_len;
    pthread_mutex_unlock(&key->stats_mutex);

    return 0;
}

int BSL_Cipher_AddAadSeq(BSL_Cipher_t *cipher_ctx, BSL_SeqReader_t *reader)
{
    ASSERT_ARG_NONNULL(cipher_ctx);
    ASSERT_ARG_NONNULL(reader);

    BSL_CryptoKey_t *key = BSL_CryptoKeyPtr_ref(cipher_ctx->keyhandle);

    while (true)
    {
        // read until there is no more
        size_t block_size = cipher_ctx->block_size;
        BSL_SeqReader_Get(reader, cipher_ctx->in_buf.ptr, &block_size);
        if (block_size == 0)
        {
            break;
        }

        int block_size_int = (int)block_size;

        BSL_LOG_PLAINTEXT_PTR("AAD in", cipher_ctx, cipher_ctx->in_buf.ptr, block_size_int);
        int res =
            EVP_CipherUpdate(cipher_ctx->libhandle, NULL, &block_size_int, cipher_ctx->in_buf.ptr, block_size_int);
        CHK_PROPERTY(res == 1);

        pthread_mutex_lock(&key->stats_mutex);
        key->stats.stats[BSL_CRYPTO_KEYSTATS_BYTES_PROCESSED] += block_size_int;
        pthread_mutex_unlock(&key->stats_mutex);
    }

    return 0;
}

int BSL_Cipher_AddSeq(BSL_Cipher_t *cipher_ctx, BSL_SeqReader_t *reader, BSL_SeqWriter_t *writer, size_t limit)
{
    ASSERT_ARG_NONNULL(cipher_ctx);
    ASSERT_ARG_NONNULL(reader);
    BSL_LOG_DEBUG("block size %zu bytes", cipher_ctx->block_size);

    BSL_CryptoKey_t *key = BSL_CryptoKeyPtr_ref(cipher_ctx->keyhandle);

    while (limit)
    {
        // read until the limit or there is no more
        size_t block_size = M_MIN(limit, cipher_ctx->block_size);
        BSL_SeqReader_Get(reader, cipher_ctx->in_buf.ptr, &block_size);
        if (block_size == 0)
        {
            break;
        }
        // actual used size
        limit -= block_size;
        int block_size_int = (int)block_size;

        BSL_LOG_PLAINTEXT_PTR("cipher in", cipher_ctx, cipher_ctx->in_buf.ptr, block_size_int);
        int res = EVP_CipherUpdate(cipher_ctx->libhandle, cipher_ctx->out_buf.ptr, &block_size_int,
                                   cipher_ctx->in_buf.ptr, block_size_int);
        BSL_LOG_DEBUG("EVP_CipherUpdate took %zu bytes, gave %d bytes, return %d", block_size, block_size_int, res);
        BSL_LOG_PLAINTEXT_PTR("cipher out", cipher_ctx, cipher_ctx->out_buf.ptr, block_size_int);
        CHK_PROPERTY(res == 1);

        pthread_mutex_lock(&key->stats_mutex);
        key->stats.stats[BSL_CRYPTO_KEYSTATS_BYTES_PROCESSED] += block_size_int;
        pthread_mutex_unlock(&key->stats_mutex);

        if ((block_size_int > 0) && writer)
        {
            block_size = (size_t)block_size_int;
            BSL_SeqWriter_Put(writer, cipher_ctx->out_buf.ptr, block_size);
        }
    }

    return BSL_SUCCESS;
}

size_t BSL_Cipher_TagLen(const BSL_Cipher_t *cipher_ctx)
{
    ASSERT_ARG_NONNULL(cipher_ctx);
    ASSERT_ARG_NONNULL(cipher_ctx->libhandle);
    return EVP_CIPHER_CTX_get_tag_length(cipher_ctx->libhandle);
}

int BSL_Cipher_GetTag(BSL_Cipher_t *cipher_ctx, BSL_Data_t *tag)
{
    ASSERT_ARG_NONNULL(cipher_ctx);
    ASSERT_ARG_NONNULL(cipher_ctx->libhandle);
    ASSERT_ARG_NONNULL(tag);

    BSL_Data_Resize(tag, EVP_CIPHER_CTX_get_tag_length(cipher_ctx->libhandle));

    int res = EVP_CIPHER_CTX_ctrl(cipher_ctx->libhandle, EVP_CTRL_GCM_GET_TAG, (int)(tag->len), tag->ptr);
    BSL_LOG_DEBUG("Completed EVP_CIPHER_CTX_ctrl len %zu, return %d", tag->len, res);
    BSL_LOG_PLAINTEXT_PTR("tag out", cipher_ctx, tag->ptr, tag->len);
    CHK_PROPERTY(res == 1);
#if defined(HAVE_VALGRIND)
    VALGRIND_MAKE_MEM_DEFINED(tag->ptr, tag->len);
#endif /* defined(HAVE_VALGRIND) */
    return 0;
}

int BSL_Cipher_SetTag(BSL_Cipher_t *cipher_ctx, const BSL_Data_t *tag)
{
    ASSERT_ARG_NONNULL(cipher_ctx);
    ASSERT_ARG_NONNULL(tag);

    BSL_LOG_PLAINTEXT_PTR("tag in", cipher_ctx, tag->ptr, tag->len);
    int res = EVP_CIPHER_CTX_ctrl(cipher_ctx->libhandle, EVP_CTRL_GCM_SET_TAG, (int)(tag->len), (void *)(tag->ptr));
    BSL_LOG_DEBUG("Completed EVP_CIPHER_CTX_ctrl len %zu, return %d", tag->len, res);
    CHK_PROPERTY(res == 1);

    return 0;
}

int BSL_Cipher_FinalizeSeq(BSL_Cipher_t *cipher_ctx, BSL_SeqWriter_t *writer)
{
    CHK_ARG_NONNULL(cipher_ctx);

    int block_size_int = (int)(cipher_ctx->block_size);

    int res = EVP_CipherFinal_ex(cipher_ctx->libhandle, cipher_ctx->out_buf.ptr, &block_size_int);
    BSL_LOG_DEBUG("EVP_CipherFinal_ex gave %d bytes, return %d", block_size_int, res);
    if (res != 1)
    {
        BSL_LOG_ERR("EVP_CipherFinal_ex error %s", ERR_error_string(ERR_get_error(), NULL));
        return BSL_ERR_FAILURE;
    }

    if ((block_size_int > 0) && writer)
    {
        size_t bsl_len = (size_t)block_size_int;
        BSL_SeqWriter_Put(writer, cipher_ctx->out_buf.ptr, bsl_len);
    }

    return BSL_SUCCESS;
}

int BSL_Cipher_Deinit(BSL_Cipher_t *cipher_ctx)
{
    CHK_ARG_NONNULL(cipher_ctx);
    BSL_Data_Deinit(&cipher_ctx->out_buf);
    BSL_Data_Deinit(&cipher_ctx->in_buf);
    EVP_CIPHER_CTX_free(cipher_ctx->libhandle);
    BSL_CryptoKeyPtr_release(cipher_ctx->keyhandle);
    memset(cipher_ctx, 0, sizeof(*cipher_ctx));
    return BSL_SUCCESS;
}

int BSL_Crypto_GenKey(size_t key_length, BSL_Crypto_KeyHandle_t *key_out)
{
    CHK_ARG_NONNULL(key_out);
    *key_out = NULL;
    CHK_ARG_EXPR(key_length > 0);

    BSL_CryptoKeyPtr_t *key_ptr = BSL_CryptoKeyPtr_new();
    // managed struct
    BSL_CryptoKey_t *key = BSL_CryptoKeyPtr_ref(key_ptr);
    CHK_PROPERTY(key != NULL);

    BSL_Data_Resize(&key->raw, key_length);
    if (rand_bytes_generator(key->raw.ptr, (int)key->raw.len) != 1)
    {
        BSL_CryptoKeyPtr_release(key_ptr);
        return BSL_ERR_FAILURE;
    }

    *key_out = key_ptr;
    return BSL_SUCCESS;
}

int BSL_Crypto_LoadKey(const uint8_t *secret, size_t secret_len, BSL_Crypto_KeyHandle_t *key_out)
{
    CHK_ARG_NONNULL(key_out);
    *key_out = NULL;
    CHK_ARG_EXPR(secret_len > 0);

    BSL_CryptoKeyPtr_t *key_ptr = BSL_CryptoKeyPtr_new();
    // managed struct
    BSL_CryptoKey_t *key = BSL_CryptoKeyPtr_ref(key_ptr);
    CHK_PROPERTY(key != NULL);

    int ecode = 0;
    if ((ecode = BSL_Data_CopyFrom(&key->raw, secret_len, secret)) != 0)
    {
        BSL_LOG_ERR("Failed to copy key");
        BSL_CryptoKeyPtr_release(key_ptr);
        return ecode;
    }

    *key_out = key_ptr;
    return BSL_SUCCESS;
}

int BSL_Crypto_GenIV(BSL_Data_t *buf)
{
    CHK_ARG_NONNULL(buf);

    memset(buf->ptr, 0, buf->len);
    CHK_PROPERTY(rand_bytes_generator((unsigned char *)(buf->ptr), buf->len) == 1);
    return BSL_SUCCESS;
}

int BSL_Crypto_AddRegistryKey(const BSL_Data_t *keyid, BSL_Crypto_KeyHandle_t handle)
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

BSL_IdValPair_t *BSL_Crypto_SetKeyParameter(BSL_Crypto_KeyHandle_t handle, int64_t param_id)
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

const BSL_IdValPair_t *BSL_Crypto_GetKeyParameter(BSL_Crypto_KeyHandle_t handle, int64_t param_id)
{
    ASSERT_ARG_NONNULL(handle);
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

int BSL_Crypto_GetRegistryKey(const BSL_Data_t *keyid, BSL_Crypto_KeyHandle_t *key_handle)
{
    ASSERT_ARG_NONNULL(keyid);
    CHK_ARG_NONNULL(key_handle);

    m_bstring_t keyid_str;
    m_bstring_init(keyid_str);
    m_bstring_push_back_bytes(keyid_str, keyid->len, keyid->ptr);

    int retval = BSL_SUCCESS;
    pthread_mutex_lock(&StaticCryptoMutex);
    BSL_CryptoKeyPtr_t **found = BSL_CryptoKeyDict_get(StaticKeyRegistry, keyid_str);
    if (!found)
    {
        *key_handle = NULL;
        retval      = BSL_ERR_NOT_FOUND;
    }
    else
    {
        *key_handle = BSL_CryptoKeyPtr_acquire(*found);
    }
    pthread_mutex_unlock(&StaticCryptoMutex);

    m_bstring_clear(keyid_str);
    return retval;
}

int BSL_Crypto_RemoveRegistryKey(const BSL_Data_t *keyid)
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

int BSL_Crypto_GetKeyStatistics(BSL_Crypto_KeyHandle_t handle, BSL_Crypto_KeyStats_t *stats)
{
    ASSERT_ARG_NONNULL(handle);
    CHK_ARG_NONNULL(stats);

    BSL_CryptoKey_t *key = BSL_CryptoKeyPtr_ref(handle);

    pthread_mutex_lock(&key->stats_mutex);
    // copy as POD
    *stats = key->stats;
    pthread_mutex_unlock(&key->stats_mutex);

    return BSL_SUCCESS;
}
