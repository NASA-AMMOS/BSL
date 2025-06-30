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
 * Backend cryptography implementation
 * @ingroup backend_dyn
 */
#include <Logging.h>

#include "DynCrypto.h"

/// Crypto key registry
static BSL_CryptoKeyDict_t crypto_keys;
static pthread_mutex_t     crypto_mtx = PTHREAD_MUTEX_INITIALIZER;

void BSL_CryptoInit(void)
{
    BSL_CryptoKeyDict_init(crypto_keys);
}

void BSL_CryptoDeinit(void)
{
    BSL_CryptoKeyDict_clear(crypto_keys);
}

int BSL_CryptoTools_UnwrapAESKey(BSL_Data_t *unwrapped_key_output, BSL_Data_t wrapped_key_plaintext, size_t key_id,
                                 size_t aes_variant)
{
    BSL_LOG_INFO("* * * * * * * * * * * AES KEY UNWRAP * *  * * * ");
    const EVP_CIPHER *cipher = (aes_variant == BSL_CRYPTO_AES_128) ? EVP_aes_128_wrap() : EVP_aes_256_wrap();
    EVP_CIPHER_CTX   *ctx    = EVP_CIPHER_CTX_new();
    assert(ctx != NULL);

    // Give the actual key extra margin on each side.
    uint8_t  keybuf[128];
    uint8_t *key = &keybuf[16];
    memset(keybuf, 0, sizeof(keybuf));

    size_t keylen = 0;
    assert(BSL_CryptoTools_GetKeyFromRegistry(key_id, (const uint8_t **)&key, &keylen) == 0);
    assert(keylen > 0);

    int dec_result = EVP_DecryptInit_ex(ctx, cipher, NULL, key, NULL);
    assert(dec_result == 1);
    EVP_CIPHER_CTX_set_padding(ctx, 0);

    int     unwrapped_key_len = 16;
    uint8_t str[200];
    BSL_LOG_INFO("cipher     : %s", aes_variant == BSL_CRYPTO_AES_128 ? "EVP_aes_128_wrap" : "EVP_aes_256_wrap");
    BSL_LOG_INFO(": %s", BSL_Log_DumpAsHexString(str, 200, key, keylen));
    BSL_LOG_INFO("secret key len:   %lu", keylen);
    BSL_LOG_INFO("unwrapped key len (int):   %d", unwrapped_key_len);
    int decrypt_res = EVP_DecryptUpdate(ctx, unwrapped_key_output->ptr, &unwrapped_key_len, wrapped_key_plaintext.ptr,
                                        (int)wrapped_key_plaintext.len);
    BSL_LOG_INFO("unwrapped key len (int):   %d", unwrapped_key_len);
    if (decrypt_res != 1)
    {
        BSL_LOG_ERR("EVP_DecryptUpdate: %s", ERR_error_string(ERR_get_error(), NULL));
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    unwrapped_key_output->len = (size_t)unwrapped_key_len;

    int final_len;
    int r = EVP_DecryptFinal_ex(ctx, &unwrapped_key_output->ptr[unwrapped_key_output->len], &final_len);
    if (r != 1)
    {
        BSL_LOG_ERR("Failed DecryptFinal: %s", ERR_error_string(ERR_get_error(), NULL));
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    unwrapped_key_output->len += (size_t)final_len;
    BSL_LOG_INFO("DecryptFinal added = %lu", final_len);
    BSL_LOG_INFO("Final length = %lu", unwrapped_key_output->len);

    EVP_CIPHER_CTX_free(ctx);
    return 0;
}

int BSL_CryptoTools_WrapAESKey(BSL_Data_t *wrapped_key, BSL_Data_t cek, size_t content_key_id, size_t aes_variant)
{
    const EVP_CIPHER *cipher = (aes_variant == BSL_CRYPTO_AES_128) ? EVP_aes_128_wrap() : EVP_aes_256_wrap();
    EVP_CIPHER_CTX   *ctx    = EVP_CIPHER_CTX_new();
    if (ctx == NULL)
    {
        BSL_LOG_ERR("Could not create cipher context");
        return -1;
    }

    // EVP_CIPHER_CTX_set_flags(ctx, EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);
    uint8_t  keybuf[128];
    uint8_t *key = &keybuf[16];
    memset(keybuf, 0, sizeof(keybuf));
    size_t keylen = 64;

    // TODO(bvb) replace w error checking
    int got_crypto_key = BSL_CryptoTools_GetKeyFromRegistry(content_key_id, (const uint8_t **)&key, &keylen);
    assert(got_crypto_key == 0);
    assert(keylen > 0);

    uint8_t str[200];
    BSL_LOG_INFO("keylen = %lu", keylen);
    BSL_LOG_INFO("KEK (from registry) : %s", BSL_Log_DumpAsHexString(str, 200, key, keylen));

    // uint8_t defIV = { 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6 };
    // int enc_result = EVP_EncryptInit_ex(ctx, cipher, NULL, key, defIV);

    int enc_result = EVP_EncryptInit_ex(ctx, cipher, NULL, cek.ptr, NULL);

    // memset(keybuf, 0, sizeof(keybuf));

    if (!enc_result)
    {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    int len = (int)wrapped_key->len;
    BSL_LOG_INFO("BEFORE EncryptFinal set ciphertext len to = %lu (cek len=%lu)", wrapped_key->len, cek.len);
    if (!EVP_EncryptUpdate(ctx, wrapped_key->ptr, &len,
                           // (int*)&wrapped_key->len,
                           key, (int)keylen))
    {
        EVP_CIPHER_CTX_free(ctx);
        return -2;
    }

    BSL_LOG_INFO("EncryptFinal set ciphertext len to = %d", len);
    wrapped_key->len = (size_t)len;
    BSL_LOG_INFO("EncryptFinal set ciphertext len to = %lu", wrapped_key->len);

    int final_len;
    if (!EVP_EncryptFinal_ex(ctx, &wrapped_key->ptr[wrapped_key->len], &final_len))
    {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    wrapped_key->len += (size_t)final_len;
    BSL_LOG_INFO("EncryptFinal added = %lu", final_len);
    BSL_LOG_INFO("Final length = %lu", wrapped_key->len);

    EVP_CIPHER_CTX_free(ctx);
    return 0;
}

int BSL_CryptoHMACCtx_Init(BSL_CryptoHMACCtx_t *hmac_ctx, uint64_t keyid, BSL_CryptoCipherSHAVariant_e sha_var)
{
    hmac_ctx->libhandle = EVP_MD_CTX_new();
    CHKERR1(hmac_ctx->libhandle != NULL);

    hmac_ctx->SHA_variant = sha_var;

    const EVP_MD *sha;
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
            return 1;
    }

    pthread_mutex_lock(&crypto_mtx);
    const BSL_CryptoKey_t *key_info = BSL_CryptoKeyDict_cget(crypto_keys, keyid);
    if (key_info == NULL)
    {
        // Special case which should not happen
        BSL_LOG_ERR("Failed to lookup Key ID %" PRId64, keyid);
        pthread_mutex_unlock(&crypto_mtx);
        return -1;
    }

    int res = EVP_DigestSignInit(hmac_ctx->libhandle, NULL, sha, NULL, key_info->pkey);
    pthread_mutex_unlock(&crypto_mtx);
    CHKERR1(res == 1);

    hmac_ctx->block_size = (size_t)EVP_MD_CTX_block_size(hmac_ctx->libhandle);

    return 0;
}

int BSL_CryptoHMACCtx_DigestBuffer(BSL_CryptoHMACCtx_t *hmac_ctx, const void *data, size_t data_len)
{
    assert(data != NULL);
    int res = EVP_DigestSignUpdate(hmac_ctx->libhandle, data, data_len);
    CHKERR1(res == 1);

    return 0;
}

int BSL_CryptoHMACCtx_DigestSeq(BSL_CryptoHMACCtx_t *hmac_ctx, BSL_SeqReader_t *reader)
{
    uint8_t buf[hmac_ctx->block_size];

    size_t block_size = hmac_ctx->block_size;
    while (block_size == hmac_ctx->block_size)
    {
        BSL_SeqReader_Get(reader, buf, &block_size);
        EVP_DigestSignUpdate(hmac_ctx->libhandle, buf, block_size);
    }

    return 0;
}

int BSL_CryptoHMACCtx_Finalize(BSL_CryptoHMACCtx_t *hmac_ctx, void **hmac, size_t *hmac_len)
{
    int    res;
    size_t req;
    res = EVP_DigestSignFinal(hmac_ctx->libhandle, NULL, &req);
    CHKERR1(res == 1);

    *hmac_len = req;
    res       = EVP_DigestSignFinal(hmac_ctx->libhandle, *hmac, hmac_len);
    CHKERR1(res == 1);

    return 0;
}

int BSL_CryptoHMACCtx_Deinit(BSL_CryptoHMACCtx_t *hmac_ctx)
{
    EVP_MD_CTX_free(hmac_ctx->libhandle);
    return 0;
}

int BSL_CryptoCipherCtx_Init(BSL_CryptoCipherCtx_t *cipher_ctx, BSL_CryptoCipherCtxMode_e enc,
                             BSL_CryptoCipherAESVariant_e aes_var, const void *init_vec, int iv_len,
                             BSL_Data_t content_enc_key)
{
    assert(cipher_ctx != NULL);
    assert(init_vec != NULL);
    assert(content_enc_key.ptr != NULL);
    assert(content_enc_key.len > 0);

    int res;
    cipher_ctx->libhandle   = EVP_CIPHER_CTX_new();
    cipher_ctx->enc         = enc;
    cipher_ctx->AES_variant = aes_var;

    const EVP_CIPHER *cipher;
    switch (cipher_ctx->AES_variant)
    {
        case BSL_CRYPTO_AES_128:
            cipher = EVP_aes_128_gcm();
            break;
        case BSL_CRYPTO_AES_256:
            cipher = EVP_aes_256_gcm();
            break;
        default:
            return 1;
    }

    res = EVP_CipherInit_ex(cipher_ctx->libhandle, cipher, NULL, NULL, NULL, (cipher_ctx->enc == BSL_CRYPTO_ENCRYPT));
    CHKERR1(res == 1);

    cipher_ctx->block_size = (size_t)EVP_CIPHER_CTX_block_size(cipher_ctx->libhandle);

    res = EVP_CIPHER_CTX_ctrl(cipher_ctx->libhandle, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL);
    CHKERR1(res == 1);

    res = EVP_CipherInit_ex(cipher_ctx->libhandle, NULL, NULL, content_enc_key.ptr, init_vec, -1);
    CHKERR1(res == 1);

    return 0;
}

int BSL_CryptoCipherCtx_AddAAD(BSL_CryptoCipherCtx_t *cipher_ctx, const void *aad, int aad_len)
{
    // len needs to be passed or function call will crash program, no NULL checking on that param it seems
    int len;
    int res = EVP_CipherUpdate(cipher_ctx->libhandle, NULL, &len, aad, aad_len);
    CHKERR1(res == 1);
    return 0;
}

int BSL_CryptoCipherCtx_AddData(BSL_CryptoCipherCtx_t *cipher_ctx, BSL_Data_t plaintext, BSL_Data_t ciphertext)
{
    assert(cipher_ctx != NULL);
    BSL_LOG_DEBUG("plaintext:  ptr=0x%p len=%lu", plaintext.ptr, plaintext.len);
    BSL_LOG_DEBUG("ciphertext: ptr=0x%p len=%lu", ciphertext.ptr, ciphertext.len);
    int cipherlen = (int)ciphertext.len;
    if (EVP_CipherUpdate(cipher_ctx->libhandle, ciphertext.ptr, &cipherlen, plaintext.ptr, plaintext.len) != 1)
    {
        return -1;
    }
    return (int)cipherlen;
}

int BSL_CryptoCipherCtx_AddSeq(BSL_CryptoCipherCtx_t *cipher_ctx, BSL_SeqReader_t *reader, BSL_SeqWriter_t *writer)
{
    int res;

    uint8_t read_buf[cipher_ctx->block_size];
    uint8_t write_buf[cipher_ctx->block_size];

    size_t block_size = cipher_ctx->block_size;
    while (block_size == (cipher_ctx->block_size))
    {
        BSL_SeqReader_Get(reader, read_buf, &block_size);
        res = EVP_CipherUpdate(cipher_ctx->libhandle, write_buf, (int *)&block_size, read_buf, block_size);
        CHKERR1(res == 1);
        BSL_SeqWriter_Put(writer, write_buf, &block_size);
    }

    return 0;
}

int BSL_CryptoCipherCtx_GetTag(BSL_CryptoCipherCtx_t *cipher_ctx, void **tag)
{
    int res = EVP_CIPHER_CTX_ctrl(cipher_ctx->libhandle, EVP_CTRL_GCM_GET_TAG, BSL_CRYPTO_AESGCM_AUTH_TAG_LEN, *tag);
    CHKERR1(res == 1);
    return 0;
}

int BSL_CryptoCipherCtx_SetTag(BSL_CryptoCipherCtx_t *cipher_ctx, const void *tag)
{
    int res =
        EVP_CIPHER_CTX_ctrl(cipher_ctx->libhandle, EVP_CTRL_GCM_SET_TAG, BSL_CRYPTO_AESGCM_AUTH_TAG_LEN, (void *)tag);
    CHKERR1(res == 1);

    return 0;
}

int BSL_CryptoCipherContext_FinalizeData(BSL_CryptoCipherCtx_t *cipher_ctx, BSL_Data_t *extra)
{
    assert(cipher_ctx != NULL);
    uint8_t buf[EVP_CIPHER_CTX_block_size(cipher_ctx->libhandle)];
    assert(extra->len >= sizeof(buf));

    BSL_LOG_DEBUG("exta: ptr=0x%p len=%lu", extra->ptr, extra->len);

    int len;
    int res = EVP_CipherFinal_ex(cipher_ctx->libhandle, buf, &len);
    if (res != 1)
    {
        BSL_LOG_ERR("%s", ERR_error_string(ERR_get_error(), NULL));
    }
    CHKERR1(res == 1);
    memset(extra->ptr, 0, extra->len);
    BSL_LOG_INFO("Completed EVP_CipherFinal_ex");
    if (len > 0)
    {
        memcpy(extra->ptr, buf, sizeof(buf));
        extra->len = len;
    }
    return 0;
}

int BSL_CryptoCipherContext_FinalizeSeq(BSL_CryptoCipherCtx_t *cipher_ctx, BSL_SeqWriter_t *writer)
{
    // finalize can add 1 cipher block
    uint8_t buf[EVP_CIPHER_CTX_block_size(cipher_ctx->libhandle)];

    int len;
    int res = EVP_CipherFinal_ex(cipher_ctx->libhandle, buf, &len);
    CHKERR1(res == 1);

    if (len > 0)
    {
        BSL_SeqWriter_Put(writer, buf, (size_t *)&len);
    }

    return 0;
}

int BSL_CryptoCipherCtx_Deinit(BSL_CryptoCipherCtx_t *cipher_ctx)
{
    EVP_CIPHER_CTX_free(cipher_ctx->libhandle);

    return 0;
}

int BSL_CryptoTools_GenKey(void *buf, int n)
{
    memset(buf, 0, n);
    // Generate at min 128 bits and at most 2048
    if (n < 16 || n > 256)
    {
        return 1;
    }
    CHKERR1(RAND_bytes((unsigned char *)buf, n) == 1);
    return 0;
}

int BSL_CryptoTools_GenIV(void *buf, int size)
{
    memset(buf, 0, size);
    if (size < 8 || size > 16)
    {
        return 1;
    }
    CHKERR1(RAND_bytes((unsigned char *)buf, size) == 1);
    return 0;
}

int BSL_CryptoTools_AddKeyToRegistry(uint64_t keyid, const uint8_t *secret, size_t secret_len)
{
    BSL_CryptoKey_t key;
    EVP_PKEY_CTX   *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HMAC, NULL);
    int             res = EVP_PKEY_keygen_init(ctx);
    CHKERR1(res == 1);

    key.pkey = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, secret, (int)secret_len);
    EVP_PKEY_CTX_free(ctx);

    BSL_Data_Init(&key.raw);
    if (BSL_Data_CopyFrom(&key.raw, secret_len, secret))
    {
        return 2;
    }

    pthread_mutex_lock(&crypto_mtx);
    BSL_CryptoKeyDict_set_at(crypto_keys, keyid, key);
    pthread_mutex_unlock(&crypto_mtx);

    return 0;
}

int BSL_CryptoTools_GetKeyFromRegistry(uint64_t keyid, const uint8_t **secret, size_t *secret_len)
{
    CHKERR1(secret);

    pthread_mutex_lock(&crypto_mtx);
    const BSL_CryptoKey_t *found = BSL_CryptoKeyDict_cget(crypto_keys, keyid);

    if (!found)
    {
        return 2;
    }

    *secret = found->raw.ptr;

    if (secret_len)
    {
        *secret_len = found->raw.len;
    }

    pthread_mutex_unlock(&crypto_mtx);
    return 0;
}

int BSL_CryptoKey_Deinit(BSL_CryptoKey_t *key)
{
    fflush(stdout);
    EVP_PKEY_free(key->pkey);
    BSL_Data_Deinit(&(key->raw));
    return 0;
}
