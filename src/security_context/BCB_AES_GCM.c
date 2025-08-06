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
 * Contains functionality and data structures to implement BCB using security context in RFC9173.
 * @ingroup example_security_context
 *
 */
#include <stdlib.h>

#include <qcbor/qcbor_encode.h>
#include <qcbor/qcbor_spiffy_decode.h>

#include <BPSecLib_Private.h>
#include <CryptoInterface.h>

#include "DefaultSecContext.h"
#include "DefaultSecContext_Private.h"
#include "rfc9173.h"

int BSLX_BCB_ComputeAAD(BSLX_BCB_t *bcb_context)
{
    CHK_ARG_NONNULL(bcb_context);

    // AAD buffer should be unallocated (this function allocates it)
    CHK_PRECONDITION(bcb_context->aad.len == 0);
    CHK_PRECONDITION(bcb_context->aad.ptr == NULL);

    uint64_t flags = 0;
    flags |= ((!bcb_context->skip_aad_prim_block) & 0x01);
    flags |= ((!bcb_context->skip_aad_target_block & 0x01) << 1);
    flags |= ((!bcb_context->skip_aad_sec_block & 0x01) << 2);

    // There are 4 fields in a block header: id, type, flags, crc
    // See: https://www.rfc-editor.org/rfc/rfc9173.html#name-aad-scope-flags
    // Note, this over-allocates and is resized downward later.
    const size_t aad_len = 1024;
    if (BSL_SUCCESS != BSL_Data_InitBuffer(&bcb_context->aad, aad_len))
    {
        BSL_LOG_ERR("Failed to allocate AAD space");
        return BSL_ERR_INSUFFICIENT_SPACE;
    }

    QCBOREncodeContext aad_enc;
    QCBOREncode_Init(&aad_enc, (UsefulBuf) { .ptr = bcb_context->aad.ptr, .len = bcb_context->aad.len });
    QCBOREncode_AddUInt64(&aad_enc, flags);

    if (flags & 0x01UL)
    {
        BSL_LOG_DEBUG("Adding primary block to AAD");
        UsefulBufC prim_blk_encoded = { .ptr = bcb_context->primary_block.cbor,
                                        .len = bcb_context->primary_block.cbor_len };
        QCBOREncode_AddEncoded(&aad_enc, prim_blk_encoded);
    }
    if (flags & 0x02UL)
    {
        BSL_LOG_DEBUG("Adding target block header to AAD");
        BSLX_EncodeHeader(&bcb_context->target_block, &aad_enc);
    }
    if (flags & 0x04UL)
    {
        BSL_LOG_DEBUG("Adding security block header to AAD");
        BSLX_EncodeHeader(&bcb_context->sec_block, &aad_enc);
    }

    UsefulBufC cbor_encoded_buffer = { 0 };
    if (QCBOR_SUCCESS != QCBOREncode_Finish(&aad_enc, &cbor_encoded_buffer))
    {
        BSL_LOG_ERR("Failed to encode AAD in BCB");
        BSL_Data_Deinit(&bcb_context->aad);
        return BSL_ERR_ENCODING;
    }

    BSL_Data_Resize(&bcb_context->aad, cbor_encoded_buffer.len);
    return BSL_SUCCESS;
}

static int BSLX_BCB_Decrypt(BSLX_BCB_t *bcb_context)
{
    CHK_ARG_NONNULL(bcb_context);

    BSL_LOG_INFO("BCB attempting to decrypt");

    // AAD must already be populated
    CHK_PRECONDITION(bcb_context->aad.ptr != NULL);
    CHK_PRECONDITION(bcb_context->aad.len > 0);

    // Key must have been set (this feeds the key encryption key)
    CHK_PRECONDITION(bcb_context->key_id);

    // BTSD replacement is not yet allocated
    CHK_PRECONDITION(bcb_context->btsd_replacement.ptr != NULL);
    CHK_PRECONDITION(bcb_context->btsd_replacement.len > 0);

    // Must have an auth tag for us to verify
    CHK_PRECONDITION(bcb_context->authtag.ptr != NULL);
    CHK_PRECONDITION(bcb_context->authtag.len > 0);

    // Init Vector must come in from the block params
    CHK_PRECONDITION(bcb_context->iv.ptr != NULL);
    CHK_PRECONDITION(bcb_context->iv.len > 0);

    // Wrapped key must come in from the params
    // CHK_PRECONDITION(bcb_context->wrapped_key.ptr != NULL);
    // CHK_PRECONDITION(bcb_context->wrapped_key.len > 0);

    bool                         is_aes128 = bcb_context->aes_variant == RFC9173_BCB_AES_VARIANT_A128GCM;
    BSL_CryptoCipherAESVariant_e aes_mode  = is_aes128 ? BSL_CRYPTO_AES_128 : BSL_CRYPTO_AES_256;

    // Over-allocate space for Content Enc Key
    BSL_Data_t content_enc_key = { 0 };
    if (bcb_context->wrapped_key.len > 0)
    {
        BSL_Data_InitBuffer(&content_enc_key, BSLX_MAX_KEYLEN);
        int unwrap_result =
            BSL_Crypto_UnwrapKey(&content_enc_key, bcb_context->wrapped_key, bcb_context->key_id, aes_mode);
        if (BSL_SUCCESS != unwrap_result)
        {
            BSL_LOG_ERR("Failed to unwrap AES key");
            goto error;
        }
    }
    else
    {
        BSL_LOG_WARNING("Using bare key without AES keywrap");
        if (BSL_SUCCESS
            != BSLB_Crypto_GetRegistryKey(bcb_context->key_id, (const uint8_t **)&content_enc_key.ptr,
                                          &content_enc_key.len))
        {
            BSL_LOG_ERR("Failed to load key");
            goto error;
        }
    }

    // This should have resized the buffer downward
    CHK_PROPERTY(content_enc_key.len < 2048);

    BSL_Cipher_t cipher      = { 0 };
    int          cipher_init = BSL_Cipher_Init(&cipher, BSL_CRYPTO_DECRYPT, aes_mode, bcb_context->iv.ptr,
                                               (int)bcb_context->iv.len, content_enc_key);
    if (BSL_SUCCESS != cipher_init)
    {
        BSL_LOG_ERR("Failed to init BCB AES cipher");
        goto error;
    }

    if (BSL_SUCCESS != BSL_Cipher_AddAAD(&cipher, bcb_context->aad.ptr, bcb_context->aad.len))
    {
        BSL_LOG_ERR("Failed to add AAD");
        goto error;
    }

    BSL_Data_t plaintext_data = { 0 };
    BSL_Data_InitView(&plaintext_data, bcb_context->target_block.btsd_len, bcb_context->target_block.btsd);
    int nbytes = BSL_Cipher_AddData(&cipher, plaintext_data, bcb_context->btsd_replacement);
    if (nbytes < 0)
    {
        BSL_LOG_ERR("Decrypting BTSD ciphertext failed");
        goto error;
    }
    const size_t plaintext_len = (size_t)nbytes;

    // Last step is to compute the authentication tag, with is produced
    // as an output parameter to this cipher suite.
    if (BSL_SUCCESS != BSL_Cipher_SetTag(&cipher, bcb_context->authtag.ptr))
    {
        BSL_LOG_ERR("Failed to set auth tag");
        goto error;
    }

    uint8_t aes_extra[BSLX_MAX_AES_PAD];
    memset(aes_extra, 0, sizeof(aes_extra));
    BSL_Data_t remainder_data = { 0 };
    BSL_Data_InitView(&remainder_data, sizeof(aes_extra), aes_extra);
    int finalize_bytes = BSL_Cipher_FinalizeData(&cipher, &remainder_data);
    if (finalize_bytes < 0)
    {
        BSL_LOG_ERR("Failed to check auth tag");
        goto error;
    }
    const size_t extra_bytes = (size_t)finalize_bytes;
    assert(extra_bytes == 0);
    BSL_Data_Resize(&bcb_context->btsd_replacement, plaintext_len + extra_bytes);

    BSL_Data_Deinit(&bcb_context->authtag);
    BSL_Data_Deinit(&content_enc_key);
    BSL_Cipher_Deinit(&cipher);
    assert(bcb_context->authtag.len == 0);
    return BSL_SUCCESS;

error:
    BSL_Data_Deinit(&bcb_context->authtag);
    BSL_Data_Deinit(&content_enc_key);
    BSL_Cipher_Deinit(&cipher);
    BSL_LOG_ERR("Returning failure from BCB decrypt");
    return BSL_ERR_NOT_IMPLEMENTED;
}

int BSLX_BCB_Encrypt(BSLX_BCB_t *bcb_context)
{
    CHK_ARG_NONNULL(bcb_context);

    // AAD must already be populated
    CHK_PRECONDITION(bcb_context->aad.ptr != NULL);
    CHK_PRECONDITION(bcb_context->aad.len > 0);

    // Must have a key ID from the security operation parameters
    CHK_PRECONDITION(bcb_context->key_id);

    // BTSD replacement is not yet allocated
    CHK_PRECONDITION(bcb_context->btsd_replacement.ptr != NULL);
    CHK_PRECONDITION(bcb_context->btsd_replacement.len > 0);

    // Auth tag must be empty
    CHK_PRECONDITION(bcb_context->authtag.len == 0);

    bool                         is_aes128 = bcb_context->aes_variant == RFC9173_BCB_AES_VARIANT_A128GCM;
    BSL_CryptoCipherAESVariant_e aes_mode  = is_aes128 ? BSL_CRYPTO_AES_128 : BSL_CRYPTO_AES_256;

    // https://www.rfc-editor.org/rfc/rfc9173.html#name-initialization-vector-iv
    // "A value of 12 bytes SHOULD be used unless local security policy requires a different length"
    BSL_Data_InitBuffer(&bcb_context->iv, RFC9173_BCB_DEFAULT_IV_LEN);
    void        *iv_ptr = bcb_context->iv.ptr;
    const size_t iv_len = bcb_context->iv.len;
    if (BSL_SUCCESS != BSL_Crypto_GenIV(iv_ptr, iv_len))
    {
        BSL_LOG_ERR("Failed to generate IV");
        return BSL_ERR_SECURITY_CONTEXT_FAILED;
    }

    BSL_Data_t content_enc_key = { 0 };
    if (BSL_SUCCESS != BSL_Data_InitBuffer(&content_enc_key, BSLX_MAX_KEYLEN))
    {
        BSL_LOG_ERR("Cannot allocate space for key");
        goto error;
    }

    // Generated the CEK, using keywrap when needed
    if (bcb_context->skip_keywrap)
    {
        // Bypass, use the Key-Encryption-Key (KEK) as the Content-Encryption-Key (CEK)
        // This is legal per the RFC9173 spec, but not generally advised.
        BSL_LOG_WARNING("Skipping keywrap (this is not advised)");
        // Directly load key_id into content enc key
        if (BSL_SUCCESS
            != BSLB_Crypto_GetRegistryKey(bcb_context->key_id, (const uint8_t **)&content_enc_key.ptr,
                                          &content_enc_key.len))
        {
            BSL_LOG_ERR("Cannot get registry key");
            goto error;
        }
        ASSERT_PROPERTY(content_enc_key.len > 0);
        ASSERT_PROPERTY(content_enc_key.ptr == NULL);
    }
    else
    {
        // FIXME the key bytes shouldn't be copied outside of crypto library.
        // possible alternative:
        // GenKey should instead return a keyid and add generated key to registry
        const size_t keysize = is_aes128 ? 16 : 32;
        BSL_LOG_DEBUG("Generating %lu bit AES key", keysize * 8);
        if (BSL_SUCCESS != BSL_Crypto_GenKey(content_enc_key.ptr, keysize))
        {
            BSL_LOG_ERR("Failed to generate AES key");
            goto error;
        }
        content_enc_key.len = keysize;

        if (BSL_SUCCESS != BSL_Data_InitBuffer(&bcb_context->wrapped_key, BSLX_MAX_KEYLEN))
        {
            BSL_LOG_ERR("Failed to allocate wrapped key");
            goto error;
        }

        int wrap_result = BSL_Crypto_WrapKey(&bcb_context->wrapped_key, content_enc_key, bcb_context->key_id, aes_mode);
        if (BSL_SUCCESS != wrap_result)
        {
            BSL_LOG_ERR("Failed to wrap AES key");
            goto error;
        }
    }

    BSL_Cipher_t cipher = { 0 };
    int cipher_init = BSL_Cipher_Init(&cipher, BSL_CRYPTO_ENCRYPT, aes_mode, bcb_context->iv.ptr, bcb_context->iv.len,
                                      content_enc_key);
    if (BSL_SUCCESS != cipher_init)
    {
        BSL_LOG_ERR("Failed to init BCB AES cipher");
        goto error;
    }

    if (BSL_SUCCESS != BSL_Cipher_AddAAD(&cipher, bcb_context->aad.ptr, bcb_context->aad.len))
    {
        BSL_LOG_ERR("Failed to add AAD");
        goto error;
    }

    BSL_Data_t plaintext_data = { 0 };
    BSL_Data_InitView(&plaintext_data, bcb_context->target_block.btsd_len, bcb_context->target_block.btsd);
    int nbytes = BSL_Cipher_AddData(&cipher, plaintext_data, bcb_context->btsd_replacement);
    if (nbytes < 0)
    {
        BSL_LOG_ERR("Encrypting plaintext BTSD failed");
        goto error;
    }
    const size_t ciphertext_len = (size_t)nbytes;
    ASSERT_PROPERTY(ciphertext_len >= plaintext_data.len);

    ASSERT_PROPERTY(ciphertext_len < bcb_context->btsd_replacement.len);
    uint8_t aes_extra[BSLX_MAX_AES_PAD];
    memset(aes_extra, 0, sizeof(aes_extra));
    BSL_Data_t remainder_data = { 0 };
    BSL_Data_InitView(&remainder_data, sizeof(aes_extra), aes_extra);
    int extra_bytes = BSL_Cipher_FinalizeData(&cipher, &remainder_data);
    if (extra_bytes < 0)
    {
        BSL_LOG_ERR("Finalizing AES failed");
        goto error;
    }
    const size_t extra_bytelen = (size_t)extra_bytes;

    // "Finalizing" drains any remaining bytes out of the cipher context
    // and appends them to the ciphertext.
    const size_t finalized_len = ciphertext_len + extra_bytelen;
    BSL_Data_Resize(&bcb_context->btsd_replacement, finalized_len);

    BSL_Data_InitBuffer(&bcb_context->authtag, BSL_CRYPTO_AESGCM_AUTH_TAG_LEN);
    if (BSL_SUCCESS != BSL_Cipher_GetTag(&cipher, (void **)&bcb_context->authtag.ptr))
    {
        BSL_LOG_ERR("Failed to get authentication tag");
        goto error;
    }

    CHK_POSTCONDITION(bcb_context->btsd_replacement.ptr != NULL);
    CHK_POSTCONDITION(bcb_context->btsd_replacement.len == ciphertext_len);

    BSL_Data_Deinit(&content_enc_key);
    BSL_Cipher_Deinit(&cipher);
    return BSL_SUCCESS;
    // Do any releasing
error:
    BSL_Data_Deinit(&content_enc_key);
    BSL_Cipher_Deinit(&cipher);
    return BSL_ERR_SECURITY_CONTEXT_FAILED;
}

int BSLX_BCB_GetParams(const BSL_BundleRef_t *bundle, BSLX_BCB_t *bcb_context, const BSL_SecOper_t *sec_oper)
{
    CHK_ARG_NONNULL(bundle);
    CHK_ARG_NONNULL(bcb_context);
    CHK_ARG_NONNULL(sec_oper);

    CHK_PRECONDITION(bcb_context->target_block.block_num > 0);
    CHK_PRECONDITION(bcb_context->target_block.btsd != NULL);
    CHK_PRECONDITION(bcb_context->target_block.btsd_len > 0);

    for (size_t param_index = 0; param_index < BSL_SecOper_CountParams(sec_oper); param_index++)
    {
        const BSL_SecParam_t *param  = BSL_SecOper_GetParamAt(sec_oper, param_index);
        bool                  is_int = BSL_SecParam_IsInt64(param);

        uint64_t param_id = BSL_SecParam_GetId(param);
        BSL_LOG_DEBUG("BCB parsing param id %lu", param_id);
        switch (param_id)
        {
            case RFC9173_BCB_SECPARAM_IV:
            {
                assert(!is_int);
                BSL_Data_t as_data;
                if (BSL_SecParam_GetAsBytestr(param, &as_data) < 0)
                {
                    bcb_context->err_count++;
                    break;
                }
                if (BSL_Data_InitView(&bcb_context->iv, as_data.len, as_data.ptr) < 0)
                {
                    bcb_context->err_count++;
                    break;
                }
                break;
            }
            case RFC9173_BCB_SECPARAM_AESVARIANT:
            {
                BSL_LOG_DEBUG("BCB parsing AES variant (optid=%lu)", param_id);
                assert(is_int);
                bcb_context->aes_variant = BSL_SecParam_GetAsUInt64(param);
                if (bcb_context->aes_variant < RFC9173_BCB_AES_VARIANT_A128GCM
                    || bcb_context->aes_variant > RFC9173_BCB_AES_VARIANT_A256GCM)
                {
                    BSL_LOG_ERR("Unknown AES variant %lu", bcb_context->aes_variant);
                    bcb_context->err_count++;
                }
                break;
            }
            case RFC9173_BCB_SECPARAM_WRAPPEDKEY:
            {
                BSL_LOG_DEBUG("BCB parsing Wrapped key parameter (optid=%lu)", param_id);
                assert(!is_int);
                BSL_Data_t as_data;
                if (BSL_SecParam_GetAsBytestr(param, &as_data) < 0)
                {
                    bcb_context->err_count++;
                    break;
                }
                if (BSL_Data_InitView(&bcb_context->wrapped_key, as_data.len, as_data.ptr) < 0)
                {
                    BSL_LOG_ERR("Could not get view of wrapped key");
                    bcb_context->err_count++;
                    break;
                }
                break;
            }
            case RFC9173_BCB_SECPARAM_AADSCOPE:
            {
                assert(is_int);
                uint64_t aad_scope = BSL_SecParam_GetAsUInt64(param);
                BSL_LOG_DEBUG("Param[%lu]: AAD_SCOPE value = %lu", param_id, aad_scope);
                bcb_context->aad_scope = aad_scope;
                if ((aad_scope & RFC9173_BCB_AADSCOPEFLAGID_INC_PRIM_BLOCK) == 0)
                {
                    BSL_LOG_DEBUG("BCB AAD does not contain primary block flag");
                    bcb_context->skip_aad_prim_block = true;
                }
                if ((aad_scope & RFC9173_BCB_AADSCOPEFLAGID_INC_TARGET_HEADER) == 0)
                {
                    BSL_LOG_DEBUG("BCB AAD does not contain target block flag");
                    bcb_context->skip_aad_target_block = true;
                }
                if ((aad_scope & RFC9173_BCB_AADSCOPEFLAGID_INC_SECURITY_HEADER) == 0)
                {
                    BSL_LOG_DEBUG("BCB AAD does not contain security header");
                    bcb_context->skip_aad_sec_block = true;
                }
                break;
            }
            case BSL_SECPARAM_TYPE_KEY_ID:
            {
                assert(!is_int);
                BSL_Data_t res;
                assert(BSL_SUCCESS == BSL_SecParam_GetAsBytestr(param, &res));
                bcb_context->key_id = (char *)res.ptr;
                BSL_LOG_DEBUG("Param[%lu]: KEY_ID value = %s", param_id, bcb_context->key_id);
                break;
            }
            case BSL_SECPARAM_TYPE_AUTH_TAG:
            {
                BSL_LOG_DEBUG("Parsing auth tag");
                BSL_SecParam_GetAsBytestr(param, &bcb_context->authtag);
                break;
            }
            case BSL_SECPARAM_TYPE_INT_USE_WRAPPED_KEY:
            {
                const uint64_t arg_val = BSL_SecParam_GetAsUInt64(param);
                BSL_LOG_DEBUG("Param[%lu]: USE_WRAPPED_KEY value = %lu", param_id, arg_val);
                bcb_context->skip_keywrap = (arg_val == 0);
                break;
            }
            default:
            {
                BSL_LOG_ERR("Param[%lu]: INVALID ???", param_id);
                bcb_context->err_count++;
            }
        }
    }

    if (!bcb_context->skip_aad_sec_block)
    {
        // If we are instructed to skip AAD check of the security block
        // then we don't have to worry about checking it.a
        const uint64_t sec_blk_num = BSL_SecOper_GetSecurityBlockNum(sec_oper);
        const int      sec_blk_res = BSL_BundleCtx_GetBlockMetadata(bundle, sec_blk_num, &bcb_context->sec_block);
        if (BSL_SUCCESS != sec_blk_res)
        {
            BSL_LOG_ERR("Failed to get security block");
            return BSL_ERR_HOST_CALLBACK_FAILED;
        }
    }

    return BSL_SUCCESS;
}

int BSLX_BCB_Init(BSLX_BCB_t *bcb_context, const BSL_BundleRef_t *bundle, const BSL_SecOper_t *sec_oper)
{
    CHK_ARG_NONNULL(bcb_context);
    CHK_ARG_NONNULL(bundle);
    CHK_ARG_NONNULL(sec_oper);

    memset(bcb_context, 0, sizeof(*bcb_context));

    // Over-allocate space for any padding gets added in.
    const size_t new_btsd_len = bcb_context->target_block.btsd_len + 2048;
    if (BSL_SUCCESS != BSL_Data_InitBuffer(&bcb_context->btsd_replacement, new_btsd_len))
    {
        BSL_LOG_ERR("Failed to allocate BTSD double buffer");
        return BSL_ERR_INSUFFICIENT_SPACE;
    }

    if (BSL_SUCCESS != BSL_Data_InitBuffer(&bcb_context->debugstr, 512))
    {
        BSL_LOG_ERR("Failed to allocated debug str");
        return BSL_ERR_INSUFFICIENT_SPACE;
    }

    bcb_context->crypto_mode = BSL_SecOper_IsRoleSource(sec_oper) == true ? BSL_CRYPTO_ENCRYPT : BSL_CRYPTO_DECRYPT;

    if (BSL_SUCCESS != BSL_BundleCtx_GetBundleMetadata(bundle, &bcb_context->primary_block))
    {
        BSL_LOG_ERR("Failed to get bundle metatadata");
        return BSL_ERR_HOST_CALLBACK_FAILED;
    }

    // The bundle must have at least one canonical block...
    CHK_PROPERTY(bcb_context->primary_block.block_count > 0);

    if (BSL_SUCCESS
        != BSL_BundleCtx_GetBlockMetadata(bundle, BSL_SecOper_GetTargetBlockNum(sec_oper), &bcb_context->target_block))
    {
        BSL_LOG_ERR("Failed to get target block data");
        return BSL_ERR_HOST_CALLBACK_FAILED;
    }

    CHK_POSTCONDITION(bcb_context->target_block.block_num > 0);
    CHK_POSTCONDITION(bcb_context->target_block.btsd != NULL);
    CHK_POSTCONDITION(bcb_context->target_block.btsd_len > 0);
    CHK_POSTCONDITION(bcb_context->btsd_replacement.ptr != NULL);
    return BSL_SUCCESS;
}

static void BSLX_BCB_Deinit(BSLX_BCB_t *bcb_context)
{
    ASSERT_ARG_NONNULL(bcb_context);

    BSL_Data_Deinit(&bcb_context->aad);
    BSL_Data_Deinit(&bcb_context->btsd_replacement);
    BSL_Data_Deinit(&bcb_context->debugstr);
    BSL_Data_Deinit(&bcb_context->authtag);
    BSL_Data_Deinit(&bcb_context->iv);
    BSL_Data_Deinit(&bcb_context->wrapped_key);
    memset(bcb_context, 0, sizeof(*bcb_context));
}

int BSLX_BCB_Execute(BSL_LibCtx_t *lib, const BSL_BundleRef_t *bundle, const BSL_SecOper_t *sec_oper,
                     BSL_SecOutcome_t *sec_outcome)
{
    (void)lib;
    CHK_ARG_NONNULL(bundle);
    CHK_ARG_NONNULL(sec_oper);
    CHK_ARG_NONNULL(sec_outcome);

    CHK_PRECONDITION(BSL_SecOper_GetSecurityBlockNum(sec_oper) > 0);

    BSL_CanonicalBlock_t target_block = { 0 };
    if (BSL_SUCCESS != BSL_BundleCtx_GetBlockMetadata(bundle, BSL_SecOper_GetTargetBlockNum(sec_oper), &target_block))
    {
        BSL_LOG_ERR("Failed to get block data");
        return BSL_ERR_HOST_CALLBACK_FAILED;
    }

    // Create the BCB context containing all parameters and other metadata.
    BSLX_BCB_t bcb_context = { 0 };

    // First initialize the BCB context (allocate, etc).
    if (BSL_SUCCESS != BSLX_BCB_Init(&bcb_context, bundle, sec_oper))
    {
        BSL_LOG_ERR("Failed to initialize BCB context");
        goto error;
    }

    // Next populate its parameters from the SecParams in the security operations
    if (BSL_SUCCESS != BSLX_BCB_GetParams(bundle, &bcb_context, sec_oper))
    {
        BSL_LOG_ERR("Failed to get BCB parameters");
        goto error;
    }

    // Compute the Addition Authenticated Data for authenticated crypto
    if (BSL_SUCCESS != BSLX_BCB_ComputeAAD(&bcb_context))
    {
        BSL_LOG_ERR("Failed to compute AAD");
        goto error;
    }

    // Select whether to call the encrypt or decrypt function
    int (*crypto_fn)(BSLX_BCB_t *) = BSL_SecOper_IsRoleAccepter(sec_oper) ? BSLX_BCB_Decrypt : BSLX_BCB_Encrypt;

    // Perform the encryption/decryption
    if (BSL_SUCCESS != crypto_fn(&bcb_context))
    {
        BSL_LOG_ERR("Failed to perform cryptographic action");
        goto error;
    }

    // Re-allocated the target block's BTSD, since enc/dec may slightly change its size.
    const uint64_t target_blk_id = BSL_SecOper_GetTargetBlockNum(sec_oper);
    if (BSL_SUCCESS
        != BSL_BundleCtx_ReallocBTSD((BSL_BundleRef_t *)bundle, target_blk_id, bcb_context.btsd_replacement.len))
    {
        BSL_LOG_ERR("Failed to replace target BTSD");
        goto error;
    }

    // Refresh the block metadata to account for change in size.
    if (BSL_SUCCESS != BSL_BundleCtx_GetBlockMetadata(bundle, BSL_SecOper_GetTargetBlockNum(sec_oper), &target_block))
    {
        BSL_LOG_ERR("Failed to get block data");
        goto error;
    }
    ASSERT_PROPERTY(target_block.btsd_len == bcb_context.btsd_replacement.len);
    // Copy the encrypted/decrypted data into the blocks newly reallocated BTSD space.
    memcpy(target_block.btsd, bcb_context.btsd_replacement.ptr, bcb_context.btsd_replacement.len);

    // Generally we expect an auth tag with the encryption
    // If present, append it to the result.
    if (bcb_context.authtag.len > 0)
    {
        BSL_SecResult_t *auth_tag = calloc(1, BSL_SecResult_Sizeof());
        if (BSL_SUCCESS
            != BSL_SecResult_Init(auth_tag, RFC9173_BCB_RESULTID_AUTHTAG, RFC9173_CONTEXTID_BCB_AES_GCM,
                                  BSL_SecOper_GetTargetBlockNum(sec_oper), bcb_context.authtag))
        {
            BSL_LOG_ERR("Failed to append BCB auth tag");
            goto error;
        }
        else
        {
            BSL_LOG_INFO("Appending BCB Auth Tag");
            BSL_SecOutcome_AppendResult(sec_outcome, auth_tag);
        }
        free(auth_tag);
    }

    if (bcb_context.iv.len > 0)
    {
        BSL_SecParam_t *iv_param = calloc(1, BSL_SecResult_Sizeof());
        if (BSL_SUCCESS != BSL_SecParam_InitBytestr(iv_param, RFC9173_BCB_SECPARAM_IV, bcb_context.iv))
        {
            BSL_LOG_ERR("Failed to append BCB source IV");
            goto error;
        }
        else
        {
            BSL_LOG_INFO("Appending BCB source IV");
            BSL_SecOutcome_AppendParam(sec_outcome, iv_param);
        }
        free(iv_param);
    }

    BSL_SecParam_t *aes_param = calloc(1, BSL_SecResult_Sizeof());
    if (BSL_SUCCESS != BSL_SecParam_InitInt64(aes_param, RFC9173_BCB_SECPARAM_AESVARIANT, bcb_context.aes_variant))
    {
        BSL_LOG_ERR("Failed to append BCB AES param");
        goto error;
    }
    else
    {
        BSL_LOG_INFO("Appending BCB AES param");
        BSL_SecOutcome_AppendParam(sec_outcome, aes_param);
    }
    free(aes_param);

    if (bcb_context.wrapped_key.len > 0)
    {
        BSL_SecParam_t *aes_wrapped_key_param = calloc(1, BSL_SecResult_Sizeof());
        if (BSL_SUCCESS
            != BSL_SecParam_InitBytestr(aes_wrapped_key_param, RFC9173_BCB_SECPARAM_WRAPPEDKEY,
                                        bcb_context.wrapped_key))
        {
            BSL_LOG_ERR("Failed to append BCB AES param");
            goto error;
        }
        else
        {
            BSL_LOG_INFO("Appending BCB AES param");
            BSL_SecOutcome_AppendParam(sec_outcome, aes_wrapped_key_param);
        }
        free(aes_wrapped_key_param);
    }

    BSL_SecParam_t *scope_flag_param = calloc(1, BSL_SecResult_Sizeof());
    if (BSL_SUCCESS != BSL_SecParam_InitInt64(scope_flag_param, RFC9173_BCB_SECPARAM_AADSCOPE, bcb_context.aad_scope))
    {
        BSL_LOG_ERR("Failed to append BCB AES param");
        goto error;
    }
    else
    {
        BSL_LOG_INFO("Appending BCB AES param");
        BSL_SecOutcome_AppendParam(sec_outcome, scope_flag_param);
    }
    free(scope_flag_param);

    BSLX_BCB_Deinit(&bcb_context);
    return BSL_SUCCESS;

error:

    BSLX_BCB_Deinit(&bcb_context);
    return BSL_ERR_NOT_IMPLEMENTED;
}
