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
 * Backend cryptography implementation
 */
#include "CryptoInterface.h"

#include "bsl/BPSecLib_Private.h"
#include "bsl/front/TextUtil.h"
#include "bsl/dynamic/IdValPair.h"

#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>

#if defined(HAVE_VALGRIND)
#include <valgrind/memcheck.h>
#endif /* defined(HAVE_VALGRIND) */

extern BSL_KeyStore_Descriptors_t BSL_KeyStore_State;

/// Random bytes generator
static BSL_Crypto_RandBytesFn rand_bytes_generator = RAND_bytes;

void BSL_Crypto_SetRngGenerator(BSL_Crypto_RandBytesFn rand_gen_fn)
{
    rand_bytes_generator = rand_gen_fn;
}

int BSL_Crypto_UnwrapKey(BSL_Crypto_KeyHandle_t kek_handle, const BSL_Data_t *wrapped_key,
                         BSL_Crypto_KeyHandle_t *cek_handle)
{
    ASSERT_ARG_NONNULL(kek_handle);
    ASSERT_ARG_NONNULL(wrapped_key);
    ASSERT_ARG_NONNULL(cek_handle);
    *cek_handle = NULL;

    int retval = BSL_SUCCESS;
    int res;

    BSL_Data_t kek_view;
    CHK_PRECONDITION(BSL_SUCCESS == BSL_KeyStore_State.get_keymat(kek_handle, &kek_view));

    const EVP_CIPHER *cipher;
    switch (kek_view.len)
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
    // GCOV_EXCL_START
    if (ctx == NULL)
    {
        BSL_LOG_ERR("Could not create cipher context");
        return BSL_ERR_SECURITY_CONTEXT_CRYPTO_FAILED;
    }
    // GCOV_EXCL_STOP

    BSL_Data_t cek_keymat;
    // wrapped key always 8 bytes greater than CEK @cite rfc3394 (2.2.1)
    res = BSL_Data_InitBuffer(&cek_keymat, wrapped_key->len - 8);
    if (BSL_SUCCESS != res)
    {
        retval = res;
    }

    if (BSL_SUCCESS == retval)
    {
        BSL_LOG_PLAINTEXT_PTR("using KEK", cek_handle, kek_view.ptr, kek_view.len);
        res = EVP_DecryptInit_ex(ctx, cipher, NULL, kek_view.ptr, NULL);
        // GCOV_EXCL_START
        if (res != 1)
        {
            BSL_LOG_ERR("EVP_DecryptInit_ex: %s", ERR_error_string(ERR_get_error(), NULL));
            retval = BSL_ERR_SECURITY_CONTEXT_CRYPTO_FAILED;
        }
        // GCOV_EXCL_STOP
        EVP_CIPHER_CTX_set_padding(ctx, 0);
    }

    BSL_KeyStore_State.update_stats(kek_handle, 1, cek_keymat.len);

    int out_len;
    if (BSL_SUCCESS == retval)
    {
        out_len = (int)cek_keymat.len;
        BSL_LOG_PLAINTEXT_PTR("wrapped key", cek_handle, wrapped_key->ptr, wrapped_key->len);
        res = EVP_DecryptUpdate(ctx, cek_keymat.ptr, &out_len, wrapped_key->ptr, (int)wrapped_key->len);
        // GCOV_EXCL_START
        if (res != 1)
        {
            BSL_LOG_ERR("EVP_DecryptUpdate: %s", ERR_error_string(ERR_get_error(), NULL));
            retval = BSL_ERR_SECURITY_CONTEXT_CRYPTO_FAILED;
        }
        // GCOV_EXCL_STOP
        else
        {
            cek_keymat.len = (size_t)out_len;
        }
    }

    if (BSL_SUCCESS == retval)
    {
        out_len = 0;
        res     = EVP_DecryptFinal_ex(ctx, NULL, &out_len);
        // GCOV_EXCL_START
        if (res != 1)
        {
            BSL_LOG_ERR("Failed DecryptFinal: %s", ERR_error_string(ERR_get_error(), NULL));
            retval = BSL_ERR_SECURITY_CONTEXT_CRYPTO_FAILED;
        }
        else if (out_len > 0)
        {
            BSL_LOG_ERR("Key wrap without padding should not have any final data");
            retval = BSL_ERR_SECURITY_CONTEXT_CRYPTO_FAILED;
        }
        // GCOV_EXCL_STOP
        BSL_LOG_PLAINTEXT_PTR("unwrapped key", cek_handle, cek_keymat.ptr, cek_keymat.len);
    }

    EVP_CIPHER_CTX_free(ctx);

    if (BSL_SUCCESS == retval)
    {
        retval = BSL_Crypto_LoadKey(cek_keymat.ptr, cek_keymat.len, cek_handle);
    }
    BSL_Data_Deinit(&cek_keymat);

    return retval;
}

int BSL_Crypto_WrapKey(BSL_Crypto_KeyHandle_t kek_handle, BSL_Crypto_KeyHandle_t cek_handle, BSL_Data_t *wrapped_key)
{
    CHK_ARG_NONNULL(kek_handle);
    CHK_ARG_NONNULL(cek_handle);
    CHK_ARG_NONNULL(wrapped_key);

    int retval = BSL_SUCCESS;
    int res;

    BSL_Data_t kek_view;
    CHK_PRECONDITION(BSL_SUCCESS == BSL_KeyStore_State.get_keymat(kek_handle, &kek_view));

    BSL_Data_t cek_view;
    CHK_PRECONDITION(BSL_SUCCESS == BSL_KeyStore_State.get_keymat(cek_handle, &cek_view));

    const EVP_CIPHER *cipher;
    switch (kek_view.len)
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
    // GCOV_EXCL_START
    if (ctx == NULL)
    {
        BSL_LOG_ERR("Could not create cipher context");
        return BSL_ERR_SECURITY_CONTEXT_CRYPTO_FAILED;
    }
    // GCOV_EXCL_STOP

    // wrapped key always 8 bytes greater than CEK @cite rfc3394 (2.2.1)
    res = BSL_Data_Resize(wrapped_key, cek_view.len + 8);
    if (BSL_SUCCESS != res)
    {
        retval = res;
    }

    if (BSL_SUCCESS == retval)
    {
        BSL_LOG_PLAINTEXT_PTR("using KEK", cek_handle, kek_view.ptr, kek_view.len);
        // GCOV_EXCL_START
        res = EVP_EncryptInit_ex(ctx, cipher, NULL, kek_view.ptr, NULL);
        if (res != 1)
        {
            retval = BSL_ERR_SECURITY_CONTEXT_CRYPTO_FAILED;
        }
        // GCOV_EXCL_STOP
    }

    BSL_KeyStore_State.update_stats(kek_handle, 1, cek_view.len);

    int out_len;
    if (BSL_SUCCESS == retval)
    {
        out_len = (int)wrapped_key->len;
        BSL_LOG_PLAINTEXT_PTR("unwrapped key", cek_handle, cek_view.ptr, cek_view.len);
        res = EVP_EncryptUpdate(ctx, (unsigned char *)wrapped_key->ptr, &out_len, cek_view.ptr, (int)cek_view.len);
        if (res != 1)
        {
            retval = BSL_ERR_SECURITY_CONTEXT_CRYPTO_FAILED;
        }
        wrapped_key->len = (size_t)out_len;
    }

    if (BSL_SUCCESS == retval)
    {
        out_len = 0;
        res     = EVP_EncryptFinal_ex(ctx, NULL, &out_len);
        // GCOV_EXCL_START
        if (res != 1)
        {
            retval = BSL_ERR_SECURITY_CONTEXT_CRYPTO_FAILED;
        }
        else if (out_len > 0)
        {
            BSL_LOG_ERR("Key wrap without padding should not have any final data");
            retval = BSL_ERR_SECURITY_CONTEXT_CRYPTO_FAILED;
        }
        // GCOV_EXCL_STOP
        BSL_LOG_PLAINTEXT_PTR("wrapped key", cek_handle, wrapped_key->ptr, wrapped_key->len);
    }

    EVP_CIPHER_CTX_free(ctx);

    return retval;
}

// work-around allowance for empty salt and info
static const uint8_t BSL_Crypto_zero = 0;

#define BSL_Crypto_PtrOrZero(ptr) (ptr) ? (ptr) : (void *)&BSL_Crypto_zero

int BSL_Crypto_KDF(BSL_Crypto_KeyHandle_t kdk_handle, BSL_Crypto_KDFVariant_t func, const BSL_Data_t *salt,
                   const BSL_Data_t *info, size_t keylen, BSL_Crypto_KeyHandle_t *cek_handle)
{
    CHK_ARG_NONNULL(cek_handle);
    *cek_handle = NULL;
    CHK_ARG_NONNULL(kdk_handle);
    CHK_ARG_NONNULL(salt);
    CHK_ARG_NONNULL(info);
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

    int retval = BSL_SUCCESS;
    int res;

    BSL_Data_t kdk_view;
    CHK_PRECONDITION(BSL_SUCCESS == BSL_KeyStore_State.get_keymat(kdk_handle, &kdk_view));

    BSL_Data_t cek_keymat;
    if (BSL_SUCCESS != BSL_Data_InitBuffer(&cek_keymat, keylen))
    {
        retval = BSL_ERR_SECURITY_CONTEXT_CRYPTO_FAILED;
    }

    EVP_KDF *kdf = NULL;
    if (BSL_SUCCESS == retval)
    {
        kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
        // GCOV_EXCL_START
        if (!kdf)
        {
            BSL_LOG_ERR("EVP_KDF_fetch: %s", ERR_error_string(ERR_get_error(), NULL));
            retval = BSL_ERR_SECURITY_CONTEXT_CRYPTO_FAILED;
        }
        // GCOV_EXCL_STOP
    }

    EVP_KDF_CTX *kctx = NULL;
    if (BSL_SUCCESS == retval)
    {
        kctx = EVP_KDF_CTX_new(kdf);
        // GCOV_EXCL_START
        if (!kctx)
        {
            BSL_LOG_ERR("EVP_KDF_CTX_new: %s", ERR_error_string(ERR_get_error(), NULL));
            retval = BSL_ERR_SECURITY_CONTEXT_CRYPTO_FAILED;
        }
        // GCOV_EXCL_STOP
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
        BSL_LOG_PLAINTEXT_PTR("using key", kctx, kdk_view.ptr, kdk_view.len);
        *par++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, kdk_view.ptr, kdk_view.len);
        BSL_LOG_PLAINTEXT_PTR("using salt", kctx, salt->ptr, salt->len);
        *par++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, BSL_Crypto_PtrOrZero(salt->ptr), salt->len);
        BSL_LOG_PLAINTEXT_PTR("using info", kctx, info->ptr, info->len);
        *par++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, BSL_Crypto_PtrOrZero(info->ptr), info->len);
        *par   = OSSL_PARAM_construct_end();

        BSL_KeyStore_State.update_stats(kdk_handle, 1, cek_keymat.len);

        res = EVP_KDF_derive(kctx, cek_keymat.ptr, cek_keymat.len, params);
        BSL_LOG_DEBUG("EVP_KDF_derive gave %zu bytes, return %d", cek_keymat.len, res);
        BSL_LOG_PLAINTEXT_PTR("KDF out", kctx, cek_keymat.ptr, cek_keymat.len);
        // GCOV_EXCL_START
        if (res <= 0)
        {
            BSL_LOG_ERR("EVP_KDF_derive: %s", ERR_error_string(ERR_get_error(), NULL));
            retval = BSL_ERR_SECURITY_CONTEXT_CRYPTO_FAILED;
        }
        // GCOV_EXCL_STOP
    }
    if (kctx)
    {
        EVP_KDF_CTX_free(kctx);
    }

    if (BSL_SUCCESS == retval)
    {
        retval = BSL_Crypto_LoadKey(cek_keymat.ptr, cek_keymat.len, cek_handle);
    }

    BSL_Data_Deinit(&cek_keymat);
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

    hmac_ctx->keyhandle = BSL_KeyStore_State.acquire_key(keyhandle);
    CHK_PRECONDITION(hmac_ctx->keyhandle);

    BSL_Data_t key_view;
    CHK_PRECONDITION(BSL_SUCCESS == BSL_KeyStore_State.get_keymat(hmac_ctx->keyhandle, &key_view));

    EVP_MAC *mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
    CHK_PRECONDITION(mac != NULL);

    hmac_ctx->libhandle = EVP_MAC_CTX_new(mac);
    EVP_MAC_free(mac);
    CHK_PRECONDITION(hmac_ctx->libhandle != NULL);

    OSSL_PARAM params[2];
    {
        OSSL_PARAM *par = params;

        *par++ = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, digest_name, strlen(digest_name));
        *par++ = OSSL_PARAM_construct_end();
    }

    BSL_LOG_PLAINTEXT_PTR("using key", hmac_ctx, key_view.ptr, key_view.len);
    int res = EVP_MAC_init(hmac_ctx->libhandle, key_view.ptr, key_view.len, params);
    CHK_PROPERTY(res == 1);

    hmac_ctx->block_size = EVP_MAC_CTX_get_block_size(hmac_ctx->libhandle);
    BSL_LOG_DEBUG("MAC block size %zu", hmac_ctx->block_size);
    // GCOV_EXCL_START
    if (hmac_ctx->block_size == 0)
    {
        hmac_ctx->block_size = 1024;
        BSL_LOG_ERR("invalid block size zero, assuming %zu", hmac_ctx->block_size);
    }
    // GCOV_EXCL_STOP

    res = BSL_Data_InitBuffer(&hmac_ctx->in_buf, hmac_ctx->block_size);
    CHK_PROPERTY(!res);

    BSL_KeyStore_State.update_stats(keyhandle, 1, 0);

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

    BSL_KeyStore_State.update_stats(hmac_ctx->keyhandle, 0, data_len);

    return 0;
}

int BSL_AuthCtx_DigestSeq(BSL_AuthCtx_t *hmac_ctx, BSL_SeqReader_t *reader)
{
    ASSERT_ARG_NONNULL(hmac_ctx);
    ASSERT_ARG_NONNULL(reader);

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

        BSL_KeyStore_State.update_stats(hmac_ctx->keyhandle, 0, block_size);
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
    BSL_KeyStore_State.release_key(hmac_ctx->keyhandle);

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

    cipher_ctx->keyhandle = BSL_KeyStore_State.acquire_key(keyhandle);
    CHK_PRECONDITION(cipher_ctx->keyhandle);

    BSL_Data_t key_view;
    CHK_PRECONDITION(BSL_SUCCESS == BSL_KeyStore_State.get_keymat(cipher_ctx->keyhandle, &key_view));

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

    const int do_encrypt = (cipher_ctx->enc == BSL_CRYPTO_ENCRYPT);

    int res = EVP_CipherInit_ex(cipher_ctx->libhandle, cipher, NULL, NULL, NULL, do_encrypt);
    CHK_PROPERTY(res == 1);

    {
        const size_t need_len = (size_t)EVP_CIPHER_CTX_get_key_length(cipher_ctx->libhandle);
        CHK_PROPERTY(key_view.len == need_len);
    }

    cipher_ctx->block_size = (size_t)EVP_CIPHER_CTX_get_block_size(cipher_ctx->libhandle);
    if (cipher_ctx->block_size == 1)
    {
        // Choose a reasonable chunk size
        cipher_ctx->block_size = 1024;
    }
    BSL_LOG_DEBUG("Cipher block size %zu", cipher_ctx->block_size);
    // GCOV_EXCL_START
    if (cipher_ctx->block_size == 0)
    {
        cipher_ctx->block_size = 1024;
        BSL_LOG_ERR("invalid block size zero, assuming %zu", cipher_ctx->block_size);
    }
    // GCOV_EXCL_STOP

    res = EVP_CIPHER_CTX_ctrl(cipher_ctx->libhandle, EVP_CTRL_GCM_SET_IVLEN, (int)iv_val->len, NULL);
    CHK_PROPERTY(res == 1);

    BSL_LOG_PLAINTEXT_PTR("using key", cipher_ctx, key_view.ptr, key_view.len);
    BSL_LOG_PLAINTEXT_PTR("using IV", cipher_ctx, iv_val->ptr, iv_val->len);
    res = EVP_CipherInit_ex(cipher_ctx->libhandle, NULL, NULL, key_view.ptr, iv_val->ptr, -1);
    CHK_PROPERTY(res == 1);

    res = BSL_Data_InitBuffer(&cipher_ctx->in_buf, cipher_ctx->block_size);
    CHK_PROPERTY(!res);

    res = BSL_Data_InitBuffer(&cipher_ctx->out_buf, cipher_ctx->block_size);
    CHK_PROPERTY(!res);

    BSL_KeyStore_State.update_stats(cipher_ctx->keyhandle, 1, 0);

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

    BSL_KeyStore_State.update_stats(cipher_ctx->keyhandle, 0, aad_len);

    return 0;
}

int BSL_Cipher_AddAadSeq(BSL_Cipher_t *cipher_ctx, BSL_SeqReader_t *reader)
{
    ASSERT_ARG_NONNULL(cipher_ctx);
    ASSERT_ARG_NONNULL(reader);

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

        BSL_KeyStore_State.update_stats(cipher_ctx->keyhandle, 0, block_size_int);
    }

    return 0;
}

int BSL_Cipher_AddSeq(BSL_Cipher_t *cipher_ctx, BSL_SeqReader_t *reader, BSL_SeqWriter_t *writer, size_t limit)
{
    ASSERT_ARG_NONNULL(cipher_ctx);
    ASSERT_ARG_NONNULL(reader);

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

        BSL_KeyStore_State.update_stats(cipher_ctx->keyhandle, 0, block_size_int);

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
    // GCOV_EXCL_START
    if (res != 1)
    {
        BSL_LOG_ERR("EVP_CipherFinal_ex error %s", ERR_error_string(ERR_get_error(), NULL));
        return BSL_ERR_FAILURE;
    }
    // GCOV_EXCL_STOP

    if ((block_size_int > 0) && writer)
    {
        size_t bsl_len = (size_t)block_size_int;
        BSL_SeqWriter_Put(writer, cipher_ctx->out_buf.ptr, bsl_len);
    }

    return BSL_SUCCESS;
}

void BSL_Cipher_Deinit(BSL_Cipher_t *cipher_ctx)
{
    ASSERT_ARG_NONNULL(cipher_ctx);

    BSL_Data_Deinit(&cipher_ctx->out_buf);
    BSL_Data_Deinit(&cipher_ctx->in_buf);
    EVP_CIPHER_CTX_free(cipher_ctx->libhandle);
    BSL_KeyStore_State.release_key(cipher_ctx->keyhandle);

    memset(cipher_ctx, 0, sizeof(*cipher_ctx));
}

int BSL_Crypto_GenIV(BSL_Data_t *buf)
{
    ASSERT_PRECONDITION(rand_bytes_generator);
    CHK_ARG_NONNULL(buf);

    memset(buf->ptr, 0, buf->len);
    CHK_PROPERTY(rand_bytes_generator((unsigned char *)(buf->ptr), buf->len) == 1);
    return BSL_SUCCESS;
}
