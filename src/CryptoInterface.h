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
 * @ingroup frontend
 * Abstract interface for crypto processing.
 * This file is organized into groups based on topic: key registry, HMAC, cipher, etc.
 */
#ifndef BSL_FRONTEND_CRYPTO_INTERFACE_H_
#define BSL_FRONTEND_CRYPTO_INTERFACE_H_

#include <stdint.h>

#include "BPSecLib_Private.h"
#include "BPSecLib_Public.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Initialize the crypto subsystem.
 * This must be called once per process.
 */
void BSL_CryptoInit(void);

/** Deinitialize the crypto subsystem.
 * This should be called at the end of the process.
 */
void BSL_CryptoDeinit(void);

/**
 * Function pointer def for random bytestring generator
 * @param buf buffer to fill with random bytes
 * @param len size of random buffer
 * @return 1 if success, 0 if failure
 */
typedef int (*BSL_Crypto_RandBytesFn)(unsigned char *buf, int len);

/**
 * Set RNG generator to be used by crypto library
 * @param[in] rand_gen_fn random bytes generation function.
 * @warning Intended to be used only for testing. Providing an alternative RNG may break FIPS-140 compatibility
 */
void BSL_Crypto_SetRngGenerator(BSL_Crypto_RandBytesFn rand_gen_fn);

/** Generate random bytes.
 * This can be used for cipher initialization vector (IV) or KDF salt.
 * @param[in,out] buf to write data into without changing its size.
 * The size in bytes needed is determined by the calling context.
 * @returns 0 if successful
 */
int BSL_Crypto_GenIV(BSL_Data_t *buf);

/** Compare two blocks of data in a time-invariant way.
 * This avoids side channel attacks which depend on comparison time.
 *
 * @param[in] data1 The first pointer.
 * @param size1 The size of @c data1 block.
 * @param[in] data2 The second pointer.
 * @param size2 The size of @c data2 block.
 * @return True if they compare equal.
 */
bool BSL_Crypto_Compare(const void *data1, size_t size1, const void *data2, size_t size2);

/** Opaque handle for backend library objects for stateful processing.
 */
typedef void *BSL_Crypto_LibHandle_t;

/** @name Key registry interface
 *
 * There are two forms of managed crypto keys in this interface:
 * 1. Identified keys persisted in a long-term, thread-safe registry.
 *    These keys have byte string names (which can contain UTF8 text) and can
 *    have additional parameters to restrict their use.
 * 2. Anonymous ephemeral keys used for individual operations and then discarded.
 *    These keys do not have names and are typically key-wrapped or the result of a
 *    key derivation function (KDF).
 */
///@{

typedef enum
{
    BSL_CRYPTO_KEYSTATS_TIMES_USED = 0,
    BSL_CRYPTO_KEYSTATS_BYTES_PROCESSED,
    /// Not a real index, used to size arrays
    BSL_CRYPTO_KEYSTATS_MAX_INDEX
} BSL_Crypto_KeyStatCounterIndex_t;

/**
 * Structure containing statistics for individual keys
 */
typedef struct BSL_Crypto_KeyStats_s
{
    /// Counters for each ::BSL_Crypto_KeyStatCounterIndex_t value
    uint64_t stats[BSL_CRYPTO_KEYSTATS_MAX_INDEX];
} BSL_Crypto_KeyStats_t;

/** Opaque handle for key objects in the key store.
 */
typedef struct BSL_CryptoKeyPtr_s *BSL_Crypto_KeyHandle_t;

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
 * @param[in, out] key_handle pointer to pointer for new key handle.
 * The handle must be released with BSL_Crypto_ReleaseKeyHandle() when it is done being used.
 * @return Zero if the key was present.
 */
int BSL_Crypto_GetRegistryKey(const BSL_Data_t *keyid, BSL_Crypto_KeyHandle_t *key_handle);

/** Erase key entry from crypto library registry, if present.
 *  @param[in] keyid key ID of key to remove.
 * @return Zero if the key was present.
 */
int BSL_Crypto_RemoveRegistryKey(const BSL_Data_t *keyid);

/**
 * Add a new key to the crypto key registry
 * @param[in] keyid key ID that crypto functions will use to access key
 * @param[out] handle Key handle to add to the registry.
 * Once the key is added it should be treated as read-only for thread-safety purposes.
 * When handle is output, the handle must be released with BSL_Crypto_ReleaseKeyHandle() when it is done being used.
 * @return Zero upon success.
 */
int BSL_Crypto_AddRegistryKey(const BSL_Data_t *keyid, BSL_Crypto_KeyHandle_t handle);

/** Add a context-specific parameter to a known key.
 *
 * @param[in] handle The key ID to update.
 * @param[in] param_id The parameter to access.
 * If the parameter does not already exist it will be created.
 * @return Non-NULL pointer if successful.
 */
BSL_IdValPair_t *BSL_Crypto_SetKeyParameter(BSL_Crypto_KeyHandle_t handle, int64_t param_id);

/** Get key parameter for read-only access.
 * @overload
 */
const BSL_IdValPair_t *BSL_Crypto_GetKeyParameter(BSL_Crypto_KeyHandle_t handle, int64_t param_id);

/**
 * Retrieve statistics related to a crypto key
 * @param[in] handle The handle of a key in the crypto registry to retrieve the stats of.
 * @param[out] stats struct containing statistics related to the key id
 */
int BSL_Crypto_GetKeyStatistics(BSL_Crypto_KeyHandle_t handle, BSL_Crypto_KeyStats_t *stats);

///@} key registry

/** @name AES Key Wrap interface */
///@{

/**
 * Perform key wrap.
 * KEK and CEK sizes must match.
 * @param[in] kek_handle key encryption key handle (encryption key)
 * @param[in] cek_handle content encryption key handle (encryption data)
 * @param[in,out] wrapped_key output wrapped key (ciphertext) bytes
 */
int BSL_Crypto_WrapKey(BSL_Crypto_KeyHandle_t kek_handle, BSL_Crypto_KeyHandle_t cek_handle, BSL_Data_t *wrapped_key);

/**
 * Perform key unwrap.
 * CEK size expected to match size of KEK.
 * @param[in] kek_handle key encryption key handle (decryption key)
 * @param[in] wrapped_key input wrapped key (ciphertext) bytes
 * @param[in,out] cek_handle output content encryption key (plaintext) handle.
 */
int BSL_Crypto_UnwrapKey(BSL_Crypto_KeyHandle_t kek_handle, const BSL_Data_t *wrapped_key,
                         BSL_Crypto_KeyHandle_t *cek_handle);

///@} aeskw

/** @name Key Derivation Function (KDF) interface */
///@{

typedef enum
{
    BSL_CRYPTO_KDF_HKDF_SHA_256,
    BSL_CRYPTO_KDF_HKDF_SHA_512,
} BSL_Crypto_KDFVariant_t;

/** Perform key derivation.
 *
 * @param[in] kdk_handle The derivation key handle.
 * @param func The derivation function variation.
 * @param[in] salt The extract step salt.
 * @param[in] info The expand step context data.
 * @param keylen The expand step length.
 * @param[in,out] cek_handle output content encryption key handle.
 */
int BSL_Crypto_KDF(BSL_Crypto_KeyHandle_t kdk_handle, BSL_Crypto_KDFVariant_t func, const BSL_Data_t *salt,
                   const BSL_Data_t *info, size_t keylen, BSL_Crypto_KeyHandle_t *cek_handle);

///@} kdf

/** @name Confidentiality cipher interface
 *
 * Cipher Operations:
 *
 * To encrypt plaintext,
 * 1. Initialize the cipher context, using ::BSL_CRYPTO_ENCRYPT as the enc parameter: BSL_Cipher_Init()
 * Also provide the initialization vector (IV), IV Length, and key ID
 * 2. (Optional) add additional authentication data (AAD) with BSL_Cipher_AddAadBuffer() or BSL_Cipher_AddAadSeq()
 * 3. Add data to the cipher context by calling BSL_Cipher_AddSeq()
 * 4. Finalize cipher operation: calling BSL_Cipher_FinalizeSeq()
 * 5. Get tag information: BSL_Cipher_GetTag()
 * 6. Deinitialize the cipher context: BSL_Cipher_Deinit()
 *
 * To decrypt ciphertext:
 * 1. Initialize the cipher context, using ::BSL_CRYPTO_DECRYPT as the enc parameter: BSL_Cipher_Init()
 * Also provide the initialization vector (IV), IV Length, and key ID
 * 2. (Optional) add additional authentication data (AAD) with BSL_Cipher_AddAadBuffer() or BSL_Cipher_AddAadSeq()
 * 3. Add data to the cipher context by calling BSL_Cipher_AddSeq()
 * 4. Set tag information to be used to validate decryption: BSL_Cipher_SetTag()
 * 5. Finalize cipher operation: calling BSL_Cipher_FinalizeSeq()
 * 6. Deinitialize the cipher context: BSL_Cipher_Deinit()
 */
///@{

/**
 * Enum def to define cipher contexts as encryption or decryption operations
 */
typedef enum
{
    /// Encrypt from plaintext to ciphertext
    BSL_CRYPTO_ENCRYPT,
    /// Decrypt from ciphertext to plaintext
    BSL_CRYPTO_DECRYPT
} BSL_CipherMode_e;

/** Choice of fully-specified cipher algorithm.
 */
typedef enum
{
    /// AES-GCM with 128-bit key
    BSL_CRYPTO_AES_128,
    /// AES-GCM with 192-bit key
    BSL_CRYPTO_AES_192,
    /// AES-GCM with 256-bit key
    BSL_CRYPTO_AES_256
} BSL_Crypto_AESVariant_e;

/**
 * Struct def for cipher operation context
 */
typedef struct BSL_Cipher_s
{
    /// pointer to library specific data
    BSL_Crypto_LibHandle_t libhandle;
    /// indicates if operation is encryption or decryption
    BSL_CipherMode_e enc;
    /// AES variant of context
    BSL_Crypto_AESVariant_e AES_variant;
    /// Key handle used by context
    BSL_Crypto_KeyHandle_t keyhandle;
    /// block size of cipher context
    size_t block_size;
    /** Storage for input blocks.
     * After init this is sized to #block_size.
     */
    BSL_Data_t in_buf;
    /** Storage for output blocks.
     * After init this is sized to #block_size.
     */
    BSL_Data_t out_buf;
} BSL_Cipher_t;

/**
 * Initialize crypto context resources and set as encoding or decoding
 * @param[out] cipher_ctx pointer to context to initialize
 * @param aes_var AES GCM variant to use
 * @param enc enum for BSL_CRYPTO_ENCRYPT or BSL_CRYPTO_DECRYPT
 * @param[in] iv_val The initialization vector (IV) data, which must be non-empty.
 * The length is internally limited to INT_MAX
 * @param[in] key_handle key handle to use.
 * The cipher context keeps its own reference to this handle.
 * @return 0 if successful
 */
int BSL_Cipher_Init(BSL_Cipher_t *cipher_ctx, BSL_CipherMode_e enc, BSL_Crypto_AESVariant_e aes_var,
                    const BSL_Data_t *iv_val, BSL_Crypto_KeyHandle_t key_handle);

/**
 * Add additional authenticated data (AAD) to cipher context
 * @param cipher_ctx pointer to context to add AAD  to
 * @param aad pointer to AAD
 * @param aad_len length of AAD, which is internally limited to INT_MAX.
 * @return 0 if successful
 */
int BSL_Cipher_AddAadBuffer(BSL_Cipher_t *cipher_ctx, const void *aad, size_t aad_len);
/** Add AAD from sequential reader.
 * @overload
 */
int BSL_Cipher_AddAadSeq(BSL_Cipher_t *cipher_ctx, BSL_SeqReader_t *reader);

/**
 * Add data to encrypt or decrypt to the context sequentially
 * @param cipher_ctx pointer to context to add data to
 * @param[in] reader pointer to sequential reader - input to crypto operation
 * @param[in] writer pointer to sequential writer (output of crypto operation), or NULL (crypto output will not be
 * written)
 * @param limit The number of bytes of the reader to read and process.
 * This can be shorter than the full length if the ciphertext contains an authentication tag.
 * @return 0 if successful
 */
int BSL_Cipher_AddSeq(BSL_Cipher_t *cipher_ctx, BSL_SeqReader_t *reader, BSL_SeqWriter_t *writer, size_t limit);

/** Determine the size of the authentication tag.
 * This will be the output of BSL_Cipher_GetTag() and the input of BSL_Cipher_SetTag().
 *
 * @return The non-zero tag length for a valid cipher state.
 */
size_t BSL_Cipher_TagLen(const BSL_Cipher_t *cipher_ctx);
/**
 * Get the tag of the crypto operation
 * @param cipher_ctx pointer to context to get tag from
 * @param[out] tag will be resized and contain data upon successful function completion
 * @return 0 if successful
 */
int BSL_Cipher_GetTag(BSL_Cipher_t *cipher_ctx, BSL_Data_t *tag);

/**
 * Set the tag of the crypto operation.
 * @param cipher_ctx pointer to context to set tag of
 * @param[in] tag pointer to tag to read from.
 * @return 0 if successful
 */
int BSL_Cipher_SetTag(BSL_Cipher_t *cipher_ctx, const BSL_Data_t *tag);

/**
 * Finalize crypto operation.
 * Finalize may or may not add data to writer depending on implementation.
 * @param cipher_ctx pointer to context to finalize
 * @param[out] writer additional written data
 * @return 0 if successful
 */
int BSL_Cipher_FinalizeSeq(BSL_Cipher_t *cipher_ctx, BSL_SeqWriter_t *writer);

/**
 * De-initialize crypto context resources
 * @param cipher_ctx pointer to context to deinitialize
 * @return 0 if successful
 */
int BSL_Cipher_Deinit(BSL_Cipher_t *cipher_ctx);

///@} cipher

/** @name Integrity MAC interface
 *
 * HMAC Operations:
 *
 * To generate HMAC over a string,
 * 1. Initialize the HMAC generation context: BSL_AuthCtx_Init()
 * 2. Add data to the HMAC context. This can be done with a flat buffer: BSL_AuthCtx_DigestBuffer(),
 * or with a sequential reader: BSL_AuthCtx_DigestSeq()
 * 3. Finalize the HMAC context to get final tag: BSL_AuthCtx_Finalize()
 * 4. Deinitialize the HMAC context: BSL_AuthCtx_Deinit()
 */
///@{

/** Choice of fully-specified MAC algorithm.
 */
typedef enum
{
    /// HMAC SHA2-256 with 256-bit key
    BSL_CRYPTO_SHA_256,
    /// HMAC SHA2-384 with 384-bit key
    BSL_CRYPTO_SHA_384,
    /// HMAC SHA2-512 with 512-bit key
    BSL_CRYPTO_SHA_512
} BSL_Crypto_SHAVariant_e;

/**
 * Struct def for HMAC operation context
 */
typedef struct BSL_AuthCtx_s
{
    /// pointer to library specific data
    BSL_Crypto_LibHandle_t libhandle;
    /// MAC variant of context
    BSL_Crypto_SHAVariant_e SHA_variant;
    /// Key handle used by context
    BSL_Crypto_KeyHandle_t keyhandle;
    /**
     * Block size used by backend
     * @note Private value
     */
    size_t block_size;
    /** Storage for input blocks.
     * After init this is sized to #block_size.
     */
    BSL_Data_t in_buf;
} BSL_AuthCtx_t;

/**
 * Initialize HMAC context resources and set private key and SHA variant
 * @param[in,out] hmac_ctx pointer to hmac context struct to init and set
 * @param[in] keyhandle handle for key to use.
 * The HMAC context keeps its own reference to this handle.
 * @param[in] sha_var SHA variant, see RFC9173 @cite rfc9173
 * @return 0 if successful
 */
BSL_REQUIRE_CHECK
int BSL_AuthCtx_Init(BSL_AuthCtx_t *hmac_ctx, BSL_Crypto_KeyHandle_t keyhandle, BSL_Crypto_SHAVariant_e sha_var);

/**
 * Input data to HMAC sign to context
 * @param[in,out] hmac_ctx pointer to hmac context struct to add data to
 * @param[in] data buffer containing data to sign
 * @param data_len length of incoming data buffer, which is internally limited to INT_MAX
 * @return 0 if successful
 */
BSL_REQUIRE_CHECK
int BSL_AuthCtx_DigestBuffer(BSL_AuthCtx_t *hmac_ctx, const void *data, size_t data_len);

/**
 * Input data to HMAC sign to context
 * @param[in,out] hmac_ctx pointer to hmac context struct to add data to
 * @param[in] reader sequential reader over data to sign
 * @return 0 if successful
 */
int BSL_AuthCtx_DigestSeq(BSL_AuthCtx_t *hmac_ctx, BSL_SeqReader_t *reader);

/**
 * Finalize HMAC tag
 * @param[in,out] hmac_ctx pointer to hmac context struct to add data to
 * @param[out] tag The HMAC output buffer to resize and populate.
 * @return 0 if successful
 */
int BSL_AuthCtx_Finalize(BSL_AuthCtx_t *hmac_ctx, BSL_Data_t *tag);

/**
 * Deinitialize HMAC context resources
 * @param[in,out] hmac_ctx pointer to hmac context struct to add data to
 */
void BSL_AuthCtx_Deinit(BSL_AuthCtx_t *hmac_ctx);

///@} MAC

#ifdef __cplusplus
} // extern C
#endif

#endif
