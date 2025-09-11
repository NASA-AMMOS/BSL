/*
 * Copyright (c) 2025 The Johns Hopkins University Applied Physics
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
#include <BPSecLib_Private.h>
#include <CryptoInterface.h>

#include <m-dict.h>
#include <m-string.h>
#include <openssl/err.h>
#include <openssl/rand.h>

/**
 * Struct to hold private key information
 */
typedef struct BSL_CryptoKey_s
{
    /// Pointer to OpenSSL PKEY struct (used in hmac ctx)
    EVP_PKEY *pkey;
    /// Pointer to raw key information (used in cipher ctx)
    BSL_Data_t raw;
    /// Statistics related to this key
    BSL_Crypto_KeyStats_t stats;
} BSL_CryptoKey_t;

static int BSL_CryptoKey_Init(BSL_CryptoKey_t *key)
{
    key->pkey = NULL;
    BSL_Data_Init(&(key->raw));

    for (uint64_t i = 0; i < BSL_CRYPTO_KEYSTATS_MAX_INDEX; i++)
    {
        key->stats.stats[i] = 0;
    }

    return 0;
}

static int BSL_CryptoKey_Deinit(BSL_CryptoKey_t *key)
{
    if (key->pkey)
    {
        EVP_PKEY_free(key->pkey);
    }
    BSL_Data_Deinit(&(key->raw));

    for (uint64_t i = 0; i < BSL_CRYPTO_KEYSTATS_MAX_INDEX; i++)
    {
        key->stats.stats[i] = 0;
    }
    return 0;
}

// NOLINTBEGIN
/// @cond Doxygen_Suppress
#define M_OPL_BSL_CryptoKey_t() M_OPEXTEND(M_POD_OPLIST, CLEAR(API_2(BSL_CryptoKey_Deinit)))
/// Stable dict of crypto keys (key: key ID | value: key)
DICT_DEF2(BSL_CryptoKeyDict, string_t, STRING_OPLIST, BSL_CryptoKey_t, M_OPL_BSL_CryptoKey_t())
/// @endcond

/// Random bytes generator
static BSL_Crypto_RandBytesFn rand_bytes_generator;

/// Crypto key registry
static BSL_CryptoKeyDict_t StaticKeyRegistry;
static pthread_mutex_t     StaticCryptoMutex = PTHREAD_MUTEX_INITIALIZER;
// NOLINTEND

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

int BSL_Crypto_ClearGeneratedKeyHandle(void *keyhandle)
{
    CHK_ARG_NONNULL(keyhandle);

    BSL_CryptoKey_t *key = (BSL_CryptoKey_t *)keyhandle;
    BSL_CryptoKey_Deinit(key);
    BSL_FREE(key);

    return BSL_SUCCESS;
}

int BSL_Crypto_UnwrapKey(void *kek_handle, BSL_Data_t *wrapped_key, void **cek_handle)
{
    BSL_CryptoKey_t *kek = (BSL_CryptoKey_t *)kek_handle;

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
    if (ctx == NULL)
    {
        return BSL_ERR_SECURITY_CONTEXT_CRYPTO_FAILED;
    }

    BSL_CryptoKey_t *cek = BSL_MALLOC(sizeof(BSL_CryptoKey_t));
    if (cek == NULL)
    {
        return BSL_ERR_SECURITY_CONTEXT_CRYPTO_FAILED;
    }
    BSL_CryptoKey_Init(cek);

    /**
     * wrapped key always 8 bytes greater than CEK @cite rfc3394 (2.2.1)
     */
    BSL_Data_Resize(&cek->raw, wrapped_key->len - 8);

    int dec_result = EVP_DecryptInit_ex(ctx, cipher, NULL, kek->raw.ptr, NULL);
    if (dec_result != 1)
    {
        BSL_CryptoKey_Deinit(cek);
        BSL_FREE(cek);
        return BSL_ERR_SECURITY_CONTEXT_CRYPTO_FAILED;
    }
    EVP_CIPHER_CTX_set_padding(ctx, 0);

    kek->stats.stats[BSL_CRYPTO_KEYSTATS_TIMES_USED]++;

    int decrypt_res = EVP_DecryptUpdate(ctx, cek->raw.ptr, (int *)&cek->raw.len, wrapped_key->ptr, wrapped_key->len);
    if (decrypt_res != 1)
    {
        BSL_LOG_ERR("EVP_DecryptUpdate: %s", ERR_error_string(ERR_get_error(), NULL));
        EVP_CIPHER_CTX_free(ctx);
        BSL_CryptoKey_Deinit(cek);
        BSL_FREE(cek);
        return BSL_ERR_SECURITY_CONTEXT_CRYPTO_FAILED;
    }

    kek->stats.stats[BSL_CRYPTO_KEYSTATS_BYTES_PROCESSED] += wrapped_key->len;

    uint8_t buf[EVP_CIPHER_CTX_block_size(ctx)];
    int     final_len = 0;
    int     res       = EVP_DecryptFinal_ex(ctx, buf, &final_len);
    if (res != 1)
    {
        BSL_LOG_ERR("Failed DecryptFinal: %s", ERR_error_string(ERR_get_error(), NULL));
        EVP_CIPHER_CTX_free(ctx);
        BSL_CryptoKey_Deinit(cek);
        BSL_FREE(cek);
        return BSL_ERR_SECURITY_CONTEXT_CRYPTO_FAILED;
    }

    if (final_len > 0)
    {
        BSL_Data_AppendFrom(&cek->raw, final_len, buf);
    }

    EVP_CIPHER_CTX_free(ctx);

    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HMAC, NULL);
    res                = EVP_PKEY_keygen_init(pctx);
    if (res != 1)
    {
        BSL_CryptoKey_Deinit(cek);
        BSL_FREE(cek);
        return BSL_ERR_SECURITY_CONTEXT_CRYPTO_FAILED;
    }

    cek->pkey = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, cek->raw.ptr, cek->raw.len);
    EVP_PKEY_CTX_free(pctx);

    *cek_handle = cek;
    return 0;
}

int BSL_Crypto_WrapKey(void *kek_handle, void *cek_handle, BSL_Data_t *wrapped_key, void **wrapped_key_handle)
{

    CHK_ARG_NONNULL(kek_handle);
    CHK_ARG_NONNULL(cek_handle);
    CHK_ARG_NONNULL(wrapped_key);

    BSL_CryptoKey_t *cek = (BSL_CryptoKey_t *)cek_handle;
    BSL_CryptoKey_t *kek = (BSL_CryptoKey_t *)kek_handle;

    if (cek->raw.len > kek->raw.len)
    {
        BSL_LOG_ERR("KEK size %zu too small to encrypt CEK size %zu", kek->raw.len, cek->raw.len);
        return BSL_ERR_SECURITY_CONTEXT_CRYPTO_FAILED;
    }

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

    int enc_result = EVP_EncryptInit_ex(ctx, cipher, NULL, kek->raw.ptr, NULL);
    if (!enc_result)
    {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    kek->stats.stats[BSL_CRYPTO_KEYSTATS_TIMES_USED]++;

    int len = (int)wrapped_key->len;
    if (!EVP_EncryptUpdate(ctx, (unsigned char *)wrapped_key->ptr, &len, cek->raw.ptr, cek->raw.len))
    {
        EVP_CIPHER_CTX_free(ctx);
        return -2;
    }
    wrapped_key->len = (size_t)len;

    kek->stats.stats[BSL_CRYPTO_KEYSTATS_BYTES_PROCESSED] += cek->raw.len;

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

    if (wrapped_key_handle != NULL)
    {
        EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HMAC, NULL);
        int           res  = EVP_PKEY_keygen_init(pctx);
        CHK_PROPERTY(res == 1);

        BSL_CryptoKey_t *new_wrapped_key_handle = BSL_MALLOC(sizeof(BSL_CryptoKey_t));
        BSL_CryptoKey_Init(new_wrapped_key_handle);
        new_wrapped_key_handle->pkey = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, wrapped_key->ptr, wrapped_key->len);
        BSL_Data_Init(&new_wrapped_key_handle->raw);

        int ecode = 0;
        if ((ecode = BSL_Data_CopyFrom(&new_wrapped_key_handle->raw, wrapped_key->len, wrapped_key->ptr)) < 0)
        {
            BSL_LOG_ERR("Failed to copy key");
            return ecode;
        }

        *wrapped_key_handle = new_wrapped_key_handle;
        EVP_PKEY_CTX_free(pctx);
    }

    return 0;
}

int BSL_AuthCtx_Init(BSL_AuthCtx_t *hmac_ctx, void *keyhandle, BSL_CryptoCipherSHAVariant_e sha_var)
{
    CHK_ARG_NONNULL(hmac_ctx);
    CHK_ARG_NONNULL(keyhandle);

    hmac_ctx->keyhandle       = keyhandle;
    BSL_CryptoKey_t *key_info = (BSL_CryptoKey_t *)hmac_ctx->keyhandle;

    hmac_ctx->libhandle = EVP_MD_CTX_new();
    CHK_PRECONDITION(hmac_ctx->libhandle != NULL);

    hmac_ctx->SHA_variant = sha_var;

    const EVP_MD *sha = NULL;
    switch (hmac_ctx->SHA_variant)
    {
        case BSL_CRYPTO_SHA_256:
            sha = EVP_sha256();
            break;
        case BSL_CRYPTO_SHA_384:
            sha = EVP_sha384();
            break;
        case BSL_CRYPTO_SHA_512:
            sha = EVP_sha512();
            break;
        default:
            BSL_LOG_ERR("Invalid SHA variant %d", sha_var);
            return BSL_ERR_FAILURE;
    }

    int res = EVP_DigestSignInit(hmac_ctx->libhandle, NULL, sha, NULL, key_info->pkey);
    CHK_PROPERTY(res == 1);

    hmac_ctx->block_size = (size_t)EVP_MD_CTX_block_size(hmac_ctx->libhandle);
    if (hmac_ctx->block_size == 0)
    {
        hmac_ctx->block_size = 1024;
        BSL_LOG_ERR("invalid block size zero, assuming %zu", hmac_ctx->block_size);
    }

    key_info->stats.stats[BSL_CRYPTO_KEYSTATS_TIMES_USED]++;

    return 0;
}

int BSL_AuthCtx_DigestBuffer(BSL_AuthCtx_t *hmac_ctx, const void *data, size_t data_len)
{
    ASSERT_ARG_NONNULL(data);
    int res = EVP_DigestSignUpdate(hmac_ctx->libhandle, data, data_len);
    CHK_PROPERTY(res == 1);

    BSL_CryptoKey_t *key_info = (BSL_CryptoKey_t *)hmac_ctx->keyhandle;
    key_info->stats.stats[BSL_CRYPTO_KEYSTATS_BYTES_PROCESSED] += data_len;

    return 0;
}

int BSL_AuthCtx_DigestSeq(BSL_AuthCtx_t *hmac_ctx, BSL_SeqReader_t *reader)
{
    BSL_CryptoKey_t *key_info = (BSL_CryptoKey_t *)hmac_ctx->keyhandle;

    uint8_t buf[hmac_ctx->block_size];
    size_t  block_size = hmac_ctx->block_size;
    while (block_size == hmac_ctx->block_size)
    {
        BSL_SeqReader_Get(reader, buf, &block_size);
        EVP_DigestSignUpdate(hmac_ctx->libhandle, buf, block_size);

        key_info->stats.stats[BSL_CRYPTO_KEYSTATS_BYTES_PROCESSED] += block_size;
    }

    return 0;
}

int BSL_AuthCtx_Finalize(BSL_AuthCtx_t *hmac_ctx, void **hmac, size_t *hmac_len)
{
    size_t req = 0;
    int    res = EVP_DigestSignFinal(hmac_ctx->libhandle, NULL, &req);
    CHK_PROPERTY(res == 1);

    *hmac_len = req;
    res       = EVP_DigestSignFinal(hmac_ctx->libhandle, *hmac, hmac_len);
    CHK_PROPERTY(res == 1);

    return 0;
}

int BSL_AuthCtx_Deinit(BSL_AuthCtx_t *hmac_ctx)
{
    EVP_MD_CTX_free(hmac_ctx->libhandle);
    memset(hmac_ctx, 0, sizeof(BSL_AuthCtx_t));
    return 0;
}

int BSL_Cipher_Init(BSL_Cipher_t *cipher_ctx, BSL_CipherMode_e enc, BSL_CryptoCipherAESVariant_e aes_var,
                    const void *init_vec, int iv_len, void *key_handle)
{
    ASSERT_ARG_NONNULL(cipher_ctx);
    ASSERT_ARG_NONNULL(init_vec);
    ASSERT_ARG_NONNULL(key_handle);

    cipher_ctx->keyhandle = key_handle;
    BSL_CryptoKey_t *key  = (BSL_CryptoKey_t *)cipher_ctx->keyhandle;

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

    res = EVP_CIPHER_CTX_ctrl(cipher_ctx->libhandle, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL);
    CHK_PROPERTY(res == 1);

    res = EVP_CipherInit_ex(cipher_ctx->libhandle, NULL, NULL, key->raw.ptr, init_vec, -1);
    CHK_PROPERTY(res == 1);

    key->stats.stats[BSL_CRYPTO_KEYSTATS_TIMES_USED]++;

    return 0;
}

int BSL_Cipher_AddAAD(BSL_Cipher_t *cipher_ctx, const void *aad, int aad_len)
{
    // len needs to be passed or function call will crash program, no NULL checking on that param it seems
    int len = 0;
    int res = EVP_CipherUpdate(cipher_ctx->libhandle, NULL, &len, aad, aad_len);
    CHK_PROPERTY(res == 1);

    BSL_CryptoKey_t *key = (BSL_CryptoKey_t *)cipher_ctx->keyhandle;
    key->stats.stats[BSL_CRYPTO_KEYSTATS_BYTES_PROCESSED] += aad_len;

    return 0;
}

int BSL_Cipher_AddData(BSL_Cipher_t *cipher_ctx, BSL_Data_t plaintext, BSL_Data_t ciphertext)
{
    ASSERT_ARG_NONNULL(cipher_ctx);
    int cipherlen = (int)ciphertext.len;
    if (EVP_CipherUpdate(cipher_ctx->libhandle, ciphertext.ptr, &cipherlen, plaintext.ptr, (int)plaintext.len) != 1)
    {
        return -1;
    }

    BSL_CryptoKey_t *key = (BSL_CryptoKey_t *)cipher_ctx->keyhandle;
    key->stats.stats[BSL_CRYPTO_KEYSTATS_BYTES_PROCESSED] += plaintext.len;

    return cipherlen;
}

int BSL_Cipher_AddSeq(BSL_Cipher_t *cipher_ctx, BSL_SeqReader_t *reader, BSL_SeqWriter_t *writer)
{
    BSL_LOG_DEBUG("sequential %zu bytes", cipher_ctx->block_size);
    uint8_t read_buf[cipher_ctx->block_size];
    uint8_t write_buf[cipher_ctx->block_size];

    BSL_CryptoKey_t *key = (BSL_CryptoKey_t *)cipher_ctx->keyhandle;

    while (true)
    {
        // read until there is no more
        size_t block_size = cipher_ctx->block_size;
        BSL_SeqReader_Get(reader, read_buf, &block_size);
        if (block_size == 0)
        {
            break;
        }

        int block_size_int = (int)block_size;
        int res = EVP_CipherUpdate(cipher_ctx->libhandle, write_buf, &block_size_int, read_buf, block_size_int);
        BSL_LOG_DEBUG("EVP_CipherUpdate took %zu bytes, gave %u bytes", block_size, block_size_int);
        CHK_PROPERTY(res == 1);

        key->stats.stats[BSL_CRYPTO_KEYSTATS_BYTES_PROCESSED] += block_size_int;
        block_size = (size_t)block_size_int;
        BSL_SeqWriter_Put(writer, write_buf, block_size);
    }

    return 0;
}

int BSL_Cipher_GetTag(BSL_Cipher_t *cipher_ctx, void **tag)
{
    int res = EVP_CIPHER_CTX_ctrl(cipher_ctx->libhandle, EVP_CTRL_GCM_GET_TAG, BSL_CRYPTO_AESGCM_AUTH_TAG_LEN, *tag);
    CHK_PROPERTY(res == 1);
    return 0;
}

int BSL_Cipher_SetTag(BSL_Cipher_t *cipher_ctx, const void *tag)
{
    int res =
        EVP_CIPHER_CTX_ctrl(cipher_ctx->libhandle, EVP_CTRL_GCM_SET_TAG, BSL_CRYPTO_AESGCM_AUTH_TAG_LEN, (void *)tag);
    BSL_LOG_INFO("Completed EVP_CIPHER_CTX_ctrl *tag=%p", (uint8_t *)tag);
    CHK_PROPERTY(res == 1);

    return 0;
}

int BSL_Cipher_FinalizeData(BSL_Cipher_t *cipher_ctx, BSL_Data_t *extra)
{
    CHK_ARG_NONNULL(cipher_ctx);
    CHK_ARG_EXPR(extra->ptr != NULL);
    uint8_t buf[EVP_CIPHER_CTX_block_size(cipher_ctx->libhandle)];
    CHK_PRECONDITION(extra->len >= sizeof(buf));

    BSL_LOG_DEBUG("extra: ptr=0x%p len=%zu", extra->ptr, extra->len);

    int len = 0;
    int res = EVP_CipherFinal_ex(cipher_ctx->libhandle, buf, &len);
    if (res != 1)
    {
        BSL_LOG_ERR("%s", ERR_error_string(ERR_get_error(), NULL));
    }
    CHK_PROPERTY(res == 1);
    BSL_LOG_DEBUG("extra->len = %zu | got len = %d", extra->len, len);
    memset(extra->ptr, 0, extra->len);
    BSL_LOG_INFO("Completed EVP_CipherFinal_ex");
    if (len > 0)
    {
        memcpy(extra->ptr, buf, sizeof(buf));
        extra->len = len;
    }
    return 0;
}

int BSL_Cipher_FinalizeSeq(BSL_Cipher_t *cipher_ctx, BSL_SeqWriter_t *writer)
{
    CHK_ARG_NONNULL(cipher_ctx);
    CHK_ARG_NONNULL(writer);

    // finalize can add 1 cipher block
    uint8_t buf[cipher_ctx->block_size];

    int evp_len = 0;
    int res     = EVP_CipherFinal_ex(cipher_ctx->libhandle, buf, &evp_len);
    if (res != 1)
    {
        BSL_LOG_ERR("EVP_CipherFinal_ex error %s", ERR_error_string(ERR_get_error(), NULL));
        return BSL_ERR_FAILURE;
    }

    if (evp_len > 0)
    {
        size_t bsl_len = evp_len;
        BSL_SeqWriter_Put(writer, buf, bsl_len);
    }

    return 0;
}

int BSL_Cipher_Deinit(BSL_Cipher_t *cipher_ctx)
{
    CHK_ARG_NONNULL(cipher_ctx);
    EVP_CIPHER_CTX_free(cipher_ctx->libhandle);
    memset(cipher_ctx, 0, sizeof(*cipher_ctx));
    return BSL_SUCCESS;
}

int BSL_Crypto_GenKey(size_t key_length, void **key_out)
{
    CHK_ARG_NONNULL(key_out);
    CHK_ARG_EXPR(key_length == 16 || key_length == 32);

    BSL_CryptoKey_t *new_key = BSL_MALLOC(sizeof(BSL_CryptoKey_t));
    CHK_PROPERTY(new_key);
    BSL_CryptoKey_Init(new_key);

    BSL_Data_InitBuffer(&new_key->raw, key_length);
    if (rand_bytes_generator(new_key->raw.ptr, (int)new_key->raw.len) != 1)
    {
        return -2;
    }

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HMAC, NULL);
    CHK_PROPERTY(ctx);
    int res = EVP_PKEY_keygen_init(ctx);
    CHK_PROPERTY(res == 1);

    new_key->pkey = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, new_key->raw.ptr, (int)new_key->raw.len);
    EVP_PKEY_CTX_free(ctx);

    *key_out = new_key;
    return BSL_SUCCESS;
}

int BSL_Crypto_GenIV(void *buf, int size)
{
    CHK_ARG_NONNULL(buf);
    if (!(size >= 8 && size <= 16))
    {
        return -1;
    }

    memset(buf, 0, size);
    CHK_PROPERTY(rand_bytes_generator((unsigned char *)buf, size) == 1);
    return 0;
}

int BSL_Crypto_AddRegistryKey(const char *keyid, const uint8_t *secret, size_t secret_len)
{
    CHK_ARG_NONNULL(secret);
    CHK_ARG_EXPR(secret_len > 0);

    BSL_CryptoKey_t key;
    BSL_CryptoKey_Init(&key);
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HMAC, NULL);
    int           res = EVP_PKEY_keygen_init(ctx);
    CHK_PROPERTY(res == 1);

    key.pkey = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, secret, (int)secret_len);
    EVP_PKEY_CTX_free(ctx);

    BSL_Data_Init(&key.raw);

    int ecode = 0;
    if ((ecode = BSL_Data_CopyFrom(&key.raw, secret_len, secret)) < 0)
    {
        BSL_LOG_ERR("Failed to copy key");
        return ecode;
    }

    string_t keyid_str;
    string_init_set_str(keyid_str, keyid);

    pthread_mutex_lock(&StaticCryptoMutex);
    BSL_CryptoKeyDict_set_at(StaticKeyRegistry, keyid_str, key);
    pthread_mutex_unlock(&StaticCryptoMutex);

    string_clear(keyid_str);
    return 0;
}

int BSL_Crypto_GetRegistryKey(const char *keyid, void **key_handle)
{
    CHK_ARG_NONNULL(key_handle);
    CHK_ARG_NONNULL(keyid);

    string_t keyid_str;
    string_init_set_str(keyid_str, keyid);

    int retval = BSL_SUCCESS;
    pthread_mutex_lock(&StaticCryptoMutex);
    BSL_CryptoKey_t *found = BSL_CryptoKeyDict_get(StaticKeyRegistry, keyid_str);
    if (!found)
    {
        retval = BSL_ERR_NOT_FOUND;
    }
    else
    {
        *key_handle = found;
    }
    pthread_mutex_unlock(&StaticCryptoMutex);
    string_clear(keyid_str);
    return retval;
}

int BSL_Crypto_RemoveRegistryKey(const char *keyid)
{
    string_t keyid_str;
    string_init_set_str(keyid_str, keyid);

    pthread_mutex_lock(&StaticCryptoMutex);
    int res = BSL_CryptoKeyDict_erase(StaticKeyRegistry, keyid_str);
    pthread_mutex_unlock(&StaticCryptoMutex);

    string_clear(keyid_str);
    return res ? BSL_SUCCESS : -1;
}

int BSL_Crypto_GetKeyStatistics(const char *keyid, BSL_Crypto_KeyStats_t *stats)
{
    CHK_ARG_NONNULL(stats);
    CHK_ARG_NONNULL(keyid);

    string_t keyid_str;
    string_init_set_str(keyid_str, keyid);

    int retval = BSL_SUCCESS;
    pthread_mutex_lock(&StaticCryptoMutex);
    BSL_CryptoKey_t *found = BSL_CryptoKeyDict_get(StaticKeyRegistry, keyid_str);
    if (!found)
    {
        retval = BSL_ERR_NOT_FOUND;
    }
    else
    {
        for (uint64_t i = 0; i < BSL_CRYPTO_KEYSTATS_MAX_INDEX; i++)
        {
            stats->stats[i] = found->stats.stats[i];
        }
    }
    pthread_mutex_unlock(&StaticCryptoMutex);
    string_clear(keyid_str);
    return retval;
}
