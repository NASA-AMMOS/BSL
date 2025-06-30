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
 * Abstract interface for crypto processing.
 * @ingroup frontend
 *
 * HMAC Operations:
 *
 * To generate HMAC over a string,
 * 1. Initialize the HMAC generation context: BSL_CryptoHMACCtx_Init()
 * 2. Add data to the HMAC context. This can be done with a flat buffer: BSL_CryptoHMACCtx_DigestBuffer(),
 * or with a sequential reader: BSL_CryptoHMACCtx_DigestSeq()
 * 3. Fialize the HMAC context to get final tag: BSL_CryptoHMACCtx_Finalize()
 * 4. Deinitialize the HMAC context: BSL_CryptoHMACCtx_Deinit()
 *
 * Crypto Operations:
 *
 * To encrypt plaintext,
 * 1. Initialize the cipher context, using BSL_CRYPTO_ENCRYPT as the enc parameter: BSL_CryptoCipherCtx_Init()
 * Also provide the initialization vector (IV), IV Length, and key ID
 * 2. (Optional) add additional authentication data (aad) with BSL_CryptoCipherCtx_AddAAD()
 * 3. Add data to the cipher context by calling BSL_CryptoCipherCtx_AddSeq()
 * 4. Finalize cipher operation: calling BSL_CryptoCipherContext_FinalizeSeq()
 * 5. Get tag information: BSL_CryptoCipherCtx_GetTag()
 * 6. Deinitilize the cipher context: BSL_CryptoCipherCtx_Deinit()
 *
 * To decrypt ciphertext:
 * 1. Initialize the cipher context, using BSL_CRYPTO_DENCRYPT as the enc parameter: BSL_CryptoCipherCtx_Init()
 * Also provide the initialization vector (IV), IV Length, and key ID
 * 2. (Optional) add additional authentication data (aad) with BSL_CryptoCipherCtx_AddAAD()
 * 3. Add data to the cipher context by calling BSL_CryptoCipherCtx_AddSeq()
 * 4. Set tag information to be used to validate decryption: BSL_CryptoCipherCtx_SetTag()
 * 5. Finalize cipher operation: calling BSL_CryptoCipherContext_FinalizeSeq()
 * 6. Deinitilize the cipher context: BSL_CryptoCipherCtx_Deinit()
 *
 */
#ifndef BSL_CRYPTO_INTERFACE_H
#define BSL_CRYPTO_INTERFACE_H

#include <stdint.h>

#include "DataContainers.h"
#include "SeqReadWrite.h"
#include "TypeDefintions.h" // NOLINT

#ifdef __cplusplus
extern "C" {
#endif

#define BSL_CRYPTO_AESGCM_AUTH_TAG_LEN (16)

/**
 * Enum def to define cipher contexts as encryption or decryption operations
 */
typedef enum
{
    /// @brief We use undefined for zero, in case this value is never explicitly set and is just zero by default.
    // BSL_CRYPTO_UNDEFINED = 0,
    BSL_CRYPTO_ENCRYPT,
    BSL_CRYPTO_DECRYPT
} BSL_CryptoCipherCtxMode_e;

typedef enum
{
    BSL_CRYPTO_SHA_256,
    BSL_CRYPTO_SHA_384,
    BSL_CRYPTO_SHA_512
} BSL_CryptoCipherSHAVariant_e;

typedef enum
{
    BSL_CRYPTO_AES_128,
    BSL_CRYPTO_AES_256
} BSL_CryptoCipherAESVariant_e;

/**
 * Struct def for HMAC operation context
 */
typedef struct BSL_CryptoHMACCtx_s
{
    /// pointer to library specific data
    void *libhandle;
    /// SHA variant of context
    BSL_CryptoCipherSHAVariant_e SHA_variant;
    /**
     * Block size used by backend
     * @note Private value
     */
    size_t block_size;
} BSL_CryptoHMACCtx_t;

/**
 * Struct def for cipher operation context
 */
typedef struct BSL_CryptoCipherCtx_s
{
    /// pointer to library specific data
    void *libhandle;
    /// indicates if operation is encryption or decryption
    BSL_CryptoCipherCtxMode_e enc;
    /// AES variant of context
    BSL_CryptoCipherAESVariant_e AES_variant;
    /// block size of cipher context
    size_t block_size;
} BSL_CryptoCipherCtx_t;

/** Initialize the crypto subsystem.
 * This must be called once per process.
 */
void BSL_CryptoInit(void);

/** Deinitialize the crypto subsystem.
 * This should be called at the end of the process.
 */
void BSL_CryptoDeinit(void);

/**
 * Initialize HMAC context resources and set private key and SHA variant
 * @param[in,out] hmac_ctx pointer to hmac context struct to init and set
 * @param keyid ID of private key to use
 * @param[in] sha_var SHA variant, see RFC9173 @cite rfc9173
 * @return 0 if successful
 */
int BSL_CryptoHMACCtx_Init(BSL_CryptoHMACCtx_t *hmac_ctx, uint64_t keyid, BSL_CryptoCipherSHAVariant_e sha_var);

/**
 * Input data to HMAC sign to context
 * @param[in,out] hmac_ctx pointer to hmac context struct to add data to
 * @param[in] data buffer containing data to sign
 * @param data_len length of incoming data buffer
 * @return 0 if successful
 */
int BSL_CryptoHMACCtx_DigestBuffer(BSL_CryptoHMACCtx_t *hmac_ctx, const void *data, size_t data_len);

/**
 * Input data to HMAC sign to context
 * @param[in,out] hmac_ctx pointer to hmac context struct to add data to
 * @param[in] reader sequential reader over data to sign
 * @return 0 if successful
 */
int BSL_CryptoHMACCtx_DigestSeq(BSL_CryptoHMACCtx_t *hmac_ctx, BSL_SeqReader_t *reader);

/**
 * Finalize HMAC tag
 * @param[in,out] hmac_ctx pointer to hmac context struct to add data to
 * @param[out] hmac ptr to hmac tag
 * @param[out] hmac_len ptr to tag length
 * @return 0 if successful
 */
int BSL_CryptoHMACCtx_Finalize(BSL_CryptoHMACCtx_t *hmac_ctx, void **hmac, size_t *hmac_len);

/**
 * Deinitialize HMAC context resources
 * @param[in,out] hmac_ctx pointer to hmac context struct to add data to
 * @return 0 if successful
 */
int BSL_CryptoHMACCtx_Deinit(BSL_CryptoHMACCtx_t *hmac_ctx);

int BSL_CryptoTools_UnwrapAESKey(BSL_Data_t *unwrapped_key_output, BSL_Data_t wrapped_key_plaintext, size_t key_id,
                                 size_t aes_variant);
int BSL_CryptoTools_WrapAESKey(BSL_Data_t *wrapped_key, BSL_Data_t cek, size_t content_key_id, size_t aes_variant);

/**
 * Initialize crypto context resources and set as encoding or decoding
 * @param cipher_ctx pointer to context to initialize
 * @param aes_var AES GCM variant to use
 * @param enc enum for BSL_CRYPTO_ENCRYPT or BSL_CRYPTO_DECRYPT
 * @param init_vec pointer to initialization vector (IV) data
 * @param iv_len length of IV data
 * @param content_enc_key AES key to use as Content Encryption Key.
 * @return 0 if successful
 */
int BSL_CryptoCipherCtx_Init(BSL_CryptoCipherCtx_t *cipher_ctx, BSL_CryptoCipherCtxMode_e enc,
                             BSL_CryptoCipherAESVariant_e aes_var, const void *init_vec, int iv_len,
                             BSL_Data_t content_enc_key);

/**
 * Add additional authenticated data (AAD) to cipher context
 * @param cipher_ctx pointer to context to add AAD  to
 * @param aad pointer to AAD
 * @param aad_len length of AAD
 * @return 0 if successful
 */
int BSL_CryptoCipherCtx_AddAAD(BSL_CryptoCipherCtx_t *cipher_ctx, const void *aad, int aad_len);

/**
 *
 */
int BSL_CryptoCipherCtx_AddData(BSL_CryptoCipherCtx_t *cipher_ctx, BSL_Data_t plaintext, BSL_Data_t ciphertext);

/**
 * Add data to encrypt or decrypt to the context sequentially
 * @param cipher_ctx pointer to context to add data to
 * @param[in] reader pointer to sequential reader - input to crypto operation is
 * @param[in,out] writer pointer to sequential writer - output of crypto operation will be writter
 * @return 0 if successful
 */
int BSL_CryptoCipherCtx_AddSeq(BSL_CryptoCipherCtx_t *cipher_ctx, BSL_SeqReader_t *reader, BSL_SeqWriter_t *writer);

/**
 * Get the tag of the crypto operation
 * @param cipher_ctx pointer to context to get tag from
 * @param[out] tag will contain tag information upon successful function completion
 * @return 0 if successful
 */
int BSL_CryptoCipherCtx_GetTag(BSL_CryptoCipherCtx_t *cipher_ctx, void **tag);

/**
 * Set the tag of the crypto operation.
 * Tag length is always 16 bytes
 * @param cipher_ctx pointer to context to set tag of
 * @param[in] tag pointer to tag
 * @return 0 if successful
 */
int BSL_CryptoCipherCtx_SetTag(BSL_CryptoCipherCtx_t *cipher_ctx, const void *tag);

/**
 * Finalize crypto operation.
 * Finalize may or may not add data to writer depending on implementation.
 * @param cipher_ctx pointer to context to finalize
 * @param[out] writer additional written data
 * @return 0 if successful
 */
int BSL_CryptoCipherContext_FinalizeSeq(BSL_CryptoCipherCtx_t *cipher_ctx, BSL_SeqWriter_t *writer);
int BSL_CryptoCipherContext_FinalizeData(BSL_CryptoCipherCtx_t *cipher_ctx, BSL_Data_t *extra);

/**
 * De-initialize crypto context resources
 * @param cipher_ctx pointer to context to deinitialize
 * @return 0 if successful
 */
int BSL_CryptoCipherCtx_Deinit(BSL_CryptoCipherCtx_t *cipher_ctx);

int BSL_CryptoTools_GenKey(void *buf, int n);

/**
 * Generate initialization vector (IV) for AES-GCM for BCBs
 * @param[in,out] buf to write iv to
 * @param size size in bytes of iv (MUST be between 8-16, SHOULD be 12 @cite rfc9173)
 * @returns 0 if successful
 */
int BSL_CryptoTools_GenIV(void *buf, int size);

#ifdef __cplusplus
} // extern C
#endif

#endif
