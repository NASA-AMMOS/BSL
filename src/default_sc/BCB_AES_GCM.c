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
 * @ingroup default_sc
 * Contains functionality and data structures to implement BCB using security context in RFC9173.
 *
 */
#include <stdlib.h>

#include <qcbor/qcbor_encode.h>
#include <qcbor/qcbor_spiffy_decode.h>

#include <BPSecLib_Private.h>
#include <CryptoInterface.h>
#include <dynamic/CBOR.h>

#include "DefaultSecContext.h"
#include "DefaultSecContext_Private.h"
#include "rfc9173.h"

bool BSLX_BCB_Validate(BSL_LibCtx_t *lib, BSL_BundleRef_t *bundle, BSL_SecOper_t *sec_oper) // NOSONAR
{
    ASSERT_ARG_NONNULL(lib);
    ASSERT_ARG_NONNULL(bundle);
    ASSERT_ARG_NONNULL(sec_oper);
    return true;
}

int BSLX_BCB_ComputeAAD(BSLX_BCB_t *bcb_context)
{
    CHK_ARG_NONNULL(bcb_context);

    // AAD buffer should be unallocated (this function allocates it)
    CHK_PRECONDITION(bcb_context->aad.len == 0);
    CHK_PRECONDITION(bcb_context->aad.ptr == NULL);

    BSL_LOG_DEBUG("Using AAD scope %" PRIu64, bcb_context->aad_scope);

    // There are 4 fields in a block header: id, type, flags, crc
    // See: https://www.rfc-editor.org/rfc/rfc9173.html#name-aad-scope-flags
    // Note, this over-allocates and is resized downward later.
    const size_t aad_len = 1024;
    if (BSL_SUCCESS != BSL_Data_Resize(&bcb_context->aad, aad_len))
    {
        BSL_LOG_ERR("Failed to allocate AAD space");
        return BSL_ERR_INSUFFICIENT_SPACE;
    }

    QCBOREncodeContext aad_enc;
    QCBOREncode_Init(&aad_enc, (UsefulBuf) { .ptr = bcb_context->aad.ptr, .len = bcb_context->aad.len });
    QCBOREncode_AddUInt64(&aad_enc, bcb_context->aad_scope);

    if (bcb_context->aad_scope & RFC9173_BCB_AADSCOPEFLAGID_INC_PRIM_BLOCK)
    {
        BSL_LOG_DEBUG("Adding primary block to AAD");
        QCBOREncode_AddEncoded(&aad_enc, UsefulBufC_FROM_BSL_Data(*(bcb_context->primary_block.encoded)));
    }
    if (bcb_context->aad_scope & RFC9173_BCB_AADSCOPEFLAGID_INC_TARGET_HEADER)
    {
        BSL_LOG_DEBUG("Adding target block header to AAD");
        BSLX_EncodeHeader(&bcb_context->target_block, &aad_enc);
    }
    if (bcb_context->aad_scope & RFC9173_BCB_AADSCOPEFLAGID_INC_SECURITY_HEADER)
    {
        BSL_LOG_DEBUG("Adding security block header to AAD");
        BSLX_EncodeHeader(&bcb_context->sec_block, &aad_enc);
    }

    UsefulBufC cbor_encoded_buffer;
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
    CHK_PRECONDITION(bcb_context->key_id.ptr != NULL);

    // Must have an auth tag for us to verify
    CHK_PRECONDITION(bcb_context->authtag.ptr != NULL);
    CHK_PRECONDITION(bcb_context->authtag.len > 0);

    // Init Vector must come in from the block params
    CHK_PRECONDITION(bcb_context->iv.ptr != NULL);
    CHK_PRECONDITION(bcb_context->iv.len > 0);

    BSL_Crypto_KeyHandle_t key_id_handle;
    BSL_Crypto_KeyHandle_t cipher_key;

    if (BSL_SUCCESS != BSL_Crypto_GetRegistryKey(&bcb_context->key_id, &key_id_handle))
    {
        BSL_LOG_ERR("Cannot get registry key");
        return BSL_ERR_SECURITY_CONTEXT_FAILED;
    }

    if (bcb_context->keywrap && bcb_context->wrapped_key.len == 0)
    {
        BSL_LOG_ERR("Key wrapping enabled, but no wrapped key param set");
        return BSL_ERR_SECURITY_CONTEXT_FAILED;
    }

    if (!bcb_context->keywrap)
    {
        BSL_LOG_WARNING("Using bare key without AES keywrap");
        cipher_key = key_id_handle;
    }
    else
    {
        int unwrap_result = BSL_Crypto_UnwrapKey(key_id_handle, &bcb_context->wrapped_key, &cipher_key);
        BSL_Crypto_ReleaseKeyHandle(key_id_handle);
        if (BSL_SUCCESS != unwrap_result)
        {
            BSL_LOG_ERR("Failed to unwrap AES key");
            return BSL_ERR_SECURITY_CONTEXT_FAILED;
        }
    }

    int retval = BSL_SUCCESS;
    int res;

    BSL_Cipher_t cipher;
    res = BSL_Cipher_Init(&cipher, BSL_CRYPTO_DECRYPT, bcb_context->bsl_aes, &bcb_context->iv, cipher_key);
    BSL_Crypto_ReleaseKeyHandle(cipher_key);
    cipher_key = NULL;
    if (BSL_SUCCESS != res)
    {
        BSL_LOG_ERR("Failed to init BCB AES cipher");
        retval = BSL_ERR_SECURITY_CONTEXT_CRYPTO_FAILED;
    }

    if (retval == BSL_SUCCESS)
    {
        if (BSL_SUCCESS != BSL_Cipher_AddAadBuffer(&cipher, bcb_context->aad.ptr, bcb_context->aad.len))
        {
            BSL_LOG_ERR("Failed to add AAD");
            retval = BSL_ERR_SECURITY_CONTEXT_CRYPTO_FAILED;
        }
    }

    BSL_SeqReader_t *btsd_read  = NULL;
    BSL_SeqWriter_t *btsd_write = NULL;
    if (retval == BSL_SUCCESS)
    {
        btsd_read = BSL_BundleCtx_ReadBTSD(bcb_context->bundle, bcb_context->target_block.block_num);
        if (!btsd_read)
        {
            BSL_LOG_ERR("Failed to construct reader");
            retval = BSL_ERR_HOST_CALLBACK_FAILED;
        }

        if (bcb_context->overwrite_btsd)
        {
            btsd_write = BSL_BundleCtx_WriteBTSD(bcb_context->bundle, bcb_context->target_block.block_num,
                                                 bcb_context->target_block.btsd_len);
            if (!btsd_write)
            {
                BSL_LOG_ERR("Failed to construct writer");
                retval = BSL_ERR_HOST_CALLBACK_FAILED;
            }
        }
    }

    if (retval == BSL_SUCCESS)
    {
        // entire block is ciphertext
        res = BSL_Cipher_AddSeq(&cipher, btsd_read, btsd_write, bcb_context->target_block.btsd_len);
        if (BSL_SUCCESS != res)
        {
            BSL_LOG_ERR("Decrypting BTSD ciphertext failed");
            retval = BSL_ERR_SECURITY_CONTEXT_CRYPTO_FAILED;
        }
    }

    if (retval == BSL_SUCCESS)
    {
        // Last step is to compute the authentication tag, with is produced
        // as an output parameter to this cipher suite.
        if (BSL_SUCCESS != BSL_Cipher_SetTag(&cipher, &bcb_context->authtag))
        {
            BSL_LOG_ERR("Failed to set auth tag");
            retval = BSL_ERR_SECURITY_CONTEXT_CRYPTO_FAILED;
        }
    }

    if (retval == BSL_SUCCESS)
    {
        res = BSL_Cipher_FinalizeSeq(&cipher, btsd_write);
        if (BSL_SUCCESS != res)
        {
            BSL_LOG_ERR("Failed to finalize");
            retval = BSL_ERR_SECURITY_CONTEXT_CRYPTO_FAILED;
        }
    }

    // close write after read
    BSL_SeqReader_Destroy(btsd_read);
    if (NULL != btsd_write)
    {
        BSL_SeqWriter_Destroy(btsd_write, retval == BSL_SUCCESS);
    }

    BSL_Cipher_Deinit(&cipher);

    return retval;
}

int BSLX_BCB_Encrypt(BSLX_BCB_t *bcb_context)
{
    CHK_ARG_NONNULL(bcb_context);

    // AAD must already be populated
    CHK_PRECONDITION(bcb_context->aad.ptr != NULL);
    CHK_PRECONDITION(bcb_context->aad.len > 0);

    // Must have a key ID from the security operation parameters
    CHK_PRECONDITION(bcb_context->key_id.ptr != NULL);

    // Auth tag must be empty
    CHK_PRECONDITION(bcb_context->authtag.len == 0);

    BSL_Data_Resize(&bcb_context->iv, RFC9173_BCB_DEFAULT_IV_LEN);
    if (BSL_SUCCESS != BSL_Crypto_GenIV(&bcb_context->iv))
    {
        BSL_LOG_ERR("Failed to generate IV");
        return BSL_ERR_SECURITY_CONTEXT_FAILED;
    }

    BSL_Crypto_KeyHandle_t key_id_handle;
    BSL_Crypto_KeyHandle_t cipher_key;

    if (BSL_SUCCESS != BSL_Crypto_GetRegistryKey(&bcb_context->key_id, &key_id_handle))
    {
        BSL_LOG_ERR("Cannot get registry key");
        return BSL_ERR_SECURITY_CONTEXT_FAILED;
    }

    // Generated the CEK, using keywrap when needed
    if (!bcb_context->keywrap)
    {
        // Bypass, use the Key-Encryption-Key (KEK) as the Content-Encryption-Key (CEK)
        // This is legal per the RFC9173 spec, but not generally advised.
        BSL_LOG_WARNING("Skipping keywrap (this is not advised)");
        // Directly load key_id into content enc key
        cipher_key = key_id_handle;
    }
    else
    {
        BSL_LOG_DEBUG("Generating %zu bit AES key", bcb_context->keysize * 8);

        if (BSL_SUCCESS != BSL_Crypto_GenKey(bcb_context->keysize, &cipher_key))
        {
            BSL_LOG_ERR("Failed to generate AES key");
            BSL_Crypto_ReleaseKeyHandle(key_id_handle);
            BSL_Crypto_ReleaseKeyHandle(cipher_key);
            return BSL_ERR_SECURITY_CONTEXT_CRYPTO_FAILED;
        }

        int wrap_result = BSL_Crypto_WrapKey(key_id_handle, cipher_key, &bcb_context->wrapped_key);
        BSL_Crypto_ReleaseKeyHandle(key_id_handle);
        if (BSL_SUCCESS != wrap_result)
        {
            BSL_LOG_ERR("Failed to wrap AES key");
            BSL_Crypto_ReleaseKeyHandle(cipher_key);
            return BSL_ERR_SECURITY_CONTEXT_CRYPTO_FAILED;
        }
    }

    int retval = BSL_SUCCESS;
    int res;

    BSL_Cipher_t cipher;
    res = BSL_Cipher_Init(&cipher, BSL_CRYPTO_ENCRYPT, bcb_context->bsl_aes, &bcb_context->iv, cipher_key);
    BSL_Crypto_ReleaseKeyHandle(cipher_key);
    cipher_key = NULL;
    if (BSL_SUCCESS != res)
    {
        BSL_LOG_ERR("Failed to init BCB AES cipher");
        retval = BSL_ERR_SECURITY_CONTEXT_CRYPTO_FAILED;
    }

    if (retval == BSL_SUCCESS)
    {
        res = BSL_Cipher_AddAadBuffer(&cipher, bcb_context->aad.ptr, bcb_context->aad.len);
        if (BSL_SUCCESS != res)
        {
            BSL_LOG_ERR("Failed to add AAD");
            retval = BSL_ERR_SECURITY_CONTEXT_CRYPTO_FAILED;
        }
    }

    BSL_SeqReader_t *btsd_read  = NULL;
    BSL_SeqWriter_t *btsd_write = NULL;
    if (retval == BSL_SUCCESS)
    {
        btsd_read = BSL_BundleCtx_ReadBTSD(bcb_context->bundle, bcb_context->target_block.block_num);
        if (!btsd_read)
        {
            BSL_LOG_ERR("Failed to construct reader");
            retval = BSL_ERR_HOST_CALLBACK_FAILED;
        }
        // output is same size
        btsd_write = BSL_BundleCtx_WriteBTSD(bcb_context->bundle, bcb_context->target_block.block_num,
                                             bcb_context->target_block.btsd_len);
        if (!btsd_write)
        {
            BSL_LOG_ERR("Failed to construct writer");
            retval = BSL_ERR_HOST_CALLBACK_FAILED;
        }
    }

    if (retval == BSL_SUCCESS)
    {
        // entire block is plaintext
        res = BSL_Cipher_AddSeq(&cipher, btsd_read, btsd_write, bcb_context->target_block.btsd_len);
        if (BSL_SUCCESS != res)
        {
            BSL_LOG_ERR("Encrypting plaintext BTSD failed");
            retval = BSL_ERR_SECURITY_CONTEXT_CRYPTO_FAILED;
        }
    }

    if (retval == BSL_SUCCESS)
    {
        res = BSL_Cipher_FinalizeSeq(&cipher, btsd_write);
        if (BSL_SUCCESS != res)
        {
            BSL_LOG_ERR("Finalizing AES failed");
            retval = BSL_ERR_SECURITY_CONTEXT_CRYPTO_FAILED;
        }
    }

    if (retval == BSL_SUCCESS)
    {
        res = BSL_Cipher_GetTag(&cipher, &bcb_context->authtag);
        if (BSL_SUCCESS != res)
        {
            BSL_LOG_ERR("Failed to get authentication tag");
            retval = BSL_ERR_SECURITY_CONTEXT_CRYPTO_FAILED;
        }
    }

    // close write after read
    BSL_SeqReader_Destroy(btsd_read);
    BSL_SeqWriter_Destroy(btsd_write, retval == BSL_SUCCESS);

    BSL_Cipher_Deinit(&cipher);

    return retval;
}

int BSLX_BCB_GetOptions(const BSL_BundleRef_t *bundle, BSLX_BCB_t *bcb_context, const BSL_SecOper_t *sec_oper)
{
    CHK_ARG_NONNULL(bundle);
    CHK_ARG_NONNULL(bcb_context);
    CHK_ARG_NONNULL(sec_oper);

    CHK_PRECONDITION(bcb_context->target_block.block_num > 0);
    CHK_PRECONDITION(bcb_context->target_block.btsd_len > 0);

    bcb_context->keywrap = -1;

    const BSL_IdValPair_t *param;
    param = BSL_SecOper_FindOption(sec_oper, BSLX_BCB_OPT_AES_VARIANT);
    if (param)
    {
        BSL_LOG_DEBUG("BCB parsing AES variant (optid=%" PRIu64 ")", BSL_IdValPair_GetId(param));
        if (BSL_SUCCESS != BSL_IdValPair_GetAsInt64(param, &bcb_context->aes_variant))
        {
            BSL_LOG_ERR("Invalid AES variant value");
            bcb_context->err_count++;
        }
        // later validation checks the actual int values
    }
    param = BSL_SecOper_FindOption(sec_oper, BSLX_BCB_OPT_WRAPPED_KEY);
    if (param)
    {
        BSL_LOG_DEBUG("BCB parsing Wrapped key (optid=%" PRIu64 ")", BSL_IdValPair_GetId(param));
        BSL_Data_Deinit(&bcb_context->wrapped_key);
        if (BSL_SUCCESS != BSL_IdValPair_GetAsBytestr(param, &bcb_context->wrapped_key))
        {
            BSL_LOG_ERR("Invalid wrapped key value");
            bcb_context->err_count++;
        }
    }
    param = BSL_SecOper_FindOption(sec_oper, BSLX_BCB_OPT_SCOPE);
    if (param)
    {
        int64_t aad_scope;
        if (BSL_SUCCESS != BSL_IdValPair_GetAsInt64(param, &aad_scope))
        {
            BSL_LOG_ERR("Invalid AAD Scope value");
            bcb_context->err_count++;
        }
        else
        {
            BSL_LOG_DEBUG("Param[%" PRIu64 "]: AAD_SCOPE value = %" PRIu64, BSL_IdValPair_GetId(param), aad_scope);
            bcb_context->aad_scope     = aad_scope;
            bcb_context->opt_aad_scope = true;
        }
    }
    param = BSL_SecOper_FindOption(sec_oper, BSLX_BCB_OPT_KEY_ID);
    if (param)
    {
        const char *name;
        if (BSL_SUCCESS != BSL_IdValPair_GetAsTextstr(param, &name))
        {
            BSL_LOG_ERR("Invalid Key ID value");
            bcb_context->err_count++;
        }
        else
        {
            BSL_LOG_DEBUG("Param[%" PRIu64 "]: KEY_ID value = %s", BSL_IdValPair_GetId(param), name);
            BSL_Data_SetViewCstr(&bcb_context->key_id, name);
        }
    }
    param = BSL_SecOper_FindOption(sec_oper, BSLX_BCB_OPT_USE_KEY_WRAP);
    if (param)
    {
        if (BSL_SUCCESS != BSL_IdValPair_GetAsInt64(param, &bcb_context->keywrap))
        {
            BSL_LOG_ERR("Invalid use key wrap value");
            bcb_context->err_count++;
        }
        else
        {
            BSL_LOG_DEBUG("Param[%" PRIu64 "]: USE_WRAPPED_KEY value = %" PRIu64, BSL_IdValPair_GetId(param),
                          bcb_context->keywrap);
        }
    }

    if (bcb_context->keywrap < 0)
    {
        BSL_LOG_WARNING("BCB USE KEYWRAP param required.");
        return BSL_ERR_PROPERTY_CHECK_FAILED;
    }

    return BSL_SUCCESS;
}

int BSLX_BCB_Init(BSLX_BCB_t *bcb_context, BSL_BundleRef_t *bundle, const BSL_SecOper_t *sec_oper)
{
    CHK_ARG_NONNULL(bcb_context);
    CHK_ARG_NONNULL(bundle);
    CHK_ARG_NONNULL(sec_oper);

    memset(bcb_context, 0, sizeof(*bcb_context));

    bcb_context->is_source = BSL_SecOper_IsRoleSource(sec_oper);

    bcb_context->bundle = bundle;

    BSL_Data_Init(&bcb_context->key_id);
    BSL_Data_Init(&bcb_context->authtag);
    BSL_Data_Init(&bcb_context->wrapped_key);

    bcb_context->crypto_mode = bcb_context->is_source == true ? BSL_CRYPTO_ENCRYPT : BSL_CRYPTO_DECRYPT;

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
    CHK_POSTCONDITION(bcb_context->target_block.btsd_len > 0);
    return BSL_SUCCESS;
}

void BSLX_BCB_Deinit(BSLX_BCB_t *bcb_context)
{
    ASSERT_ARG_NONNULL(bcb_context);

    BSL_Data_Deinit(&bcb_context->aad);
    BSL_Data_Deinit(&bcb_context->authtag);
    BSL_Data_Deinit(&bcb_context->iv);
    BSL_Data_Deinit(&bcb_context->wrapped_key);
    BSL_Data_Deinit(&bcb_context->key_id);
    BSL_PrimaryBlock_deinit(&bcb_context->primary_block);

    memset(bcb_context, 0, sizeof(*bcb_context));
}

int BSLX_BCB_Execute(BSL_LibCtx_t *lib _U_, BSL_BundleRef_t *bundle, BSL_SecOper_t *sec_oper) // NOSONAR
{
    CHK_ARG_NONNULL(bundle);
    CHK_ARG_NONNULL(sec_oper);

    CHK_PRECONDITION(BSL_SecOper_GetSecurityBlockNum(sec_oper) > 0);

    BSL_CanonicalBlock_t target_block;
    if (BSL_SUCCESS != BSL_BundleCtx_GetBlockMetadata(bundle, BSL_SecOper_GetTargetBlockNum(sec_oper), &target_block))
    {
        BSL_LOG_ERR("Failed to get block data");
        return BSL_ERR_HOST_CALLBACK_FAILED;
    }

    // Create the BCB context containing all parameters and other metadata.
    BSLX_BCB_t bcb_context;
    // First initialize the BCB context (allocate, etc).
    if (BSL_SUCCESS != BSLX_BCB_Init(&bcb_context, bundle, sec_oper))
    {
        BSL_LOG_ERR("Failed to initialize BCB context");
        BSLX_BCB_Deinit(&bcb_context);
        return BSL_ERR_SECURITY_CONTEXT_FAILED;
    }

    // Next populate its parameters from the IdValPairs in the security operations
    if (BSL_SUCCESS != BSLX_BCB_GetOptions(bundle, &bcb_context, sec_oper))
    {
        BSL_LOG_ERR("Failed to get BCB parameters");
        BSLX_BCB_Deinit(&bcb_context);
        return BSL_ERR_SECURITY_CONTEXT_FAILED;
    }

    if (!bcb_context.is_source)
    {
        // find the existing parameters and results
        const BSL_IdValPair_t *param;

        param = BSL_SecOper_FindParam(sec_oper, RFC9173_BCB_SECPARAM_IV);
        if (param)
        {
            BSL_Data_Deinit(&bcb_context.iv);
            if (BSL_IdValPair_GetAsBytestr(param, &bcb_context.iv) < 0)
            {
                BSL_LOG_ERR("IV parameter is not valid");
                bcb_context.err_count++;
            }
        }

        param = BSL_SecOper_FindParam(sec_oper, RFC9173_BCB_SECPARAM_AESVARIANT);
        if (param)
        {
            int64_t got;
            if (BSL_SUCCESS != BSL_IdValPair_GetAsInt64(param, &got))
            {
                BSL_LOG_ERR("AES variant parameter is not valid");
                bcb_context.err_count++;
            }
            else if (got != bcb_context.aes_variant)
            {
                BSL_LOG_ERR("AES variant mismatch, needed %d got %d", bcb_context.aes_variant, got);
                bcb_context.err_count++;
            }
        }

        param = BSL_SecOper_FindParam(sec_oper, RFC9173_BCB_SECPARAM_AADSCOPE);
        if (param)
        {
            int64_t got;
            if (BSL_SUCCESS != BSL_IdValPair_GetAsInt64(param, &got))
            {
                BSL_LOG_ERR("AAD scope parameter is not valid");
                bcb_context.err_count++;
            }
            else
            {
                if (bcb_context.opt_aad_scope && (got != bcb_context.aad_scope))
                {
                    BSL_LOG_WARNING("AAD Scope mismatch, needed %d got %d", bcb_context.aad_scope, got);
                }
                bcb_context.aad_scope = got;
            }
        }

        param = BSL_SecOper_FindParam(sec_oper, RFC9173_BCB_SECPARAM_WRAPPEDKEY);
        if (param)
        {
            BSL_Data_Deinit(&bcb_context.wrapped_key);
            if (BSL_SUCCESS != BSL_IdValPair_GetAsBytestr(param, &bcb_context.wrapped_key))
            {
                BSL_LOG_ERR("Wrapped key parameter is not valid");
                bcb_context.err_count++;
            }
            BSL_LOG_DEBUG("Wrapped key parameter used");
        }

        param = BSL_SecOper_FindResult(sec_oper, RFC9173_BCB_RESULTID_AUTHTAG);
        if (param)
        {
            BSL_Data_Deinit(&bcb_context.authtag);
            if (BSL_SUCCESS != BSL_IdValPair_GetAsBytestr(param, &bcb_context.authtag))
            {
                BSL_LOG_ERR("Auth tag result is not valid");
                bcb_context.err_count++;
            }
        }
        else
        {
            BSL_LOG_ERR("Auth tag result is not present");
            bcb_context.err_count++;
        }
    }
    if (bcb_context.err_count)
    {
        BSLX_BCB_Deinit(&bcb_context);
        return BSL_ERR_SECURITY_CONTEXT_FAILED;
    }

    switch (bcb_context.aes_variant)
    {
        case RFC9173_BCB_AES_VARIANT_A128GCM:
            bcb_context.bsl_aes = BSL_CRYPTO_AES_128;
            bcb_context.keysize = 16;
            break;
        case RFC9173_BCB_AES_VARIANT_A256GCM:
            bcb_context.bsl_aes = BSL_CRYPTO_AES_256;
            bcb_context.keysize = 32;
            break;
        default:
            BSL_LOG_ERR("Invalid AES algorithm %" PRId64, bcb_context.aes_variant);
            BSLX_BCB_Deinit(&bcb_context);
            return BSL_ERR_SECURITY_CONTEXT_VALIDATION_FAILED;
    }

    if (bcb_context.aad_scope & RFC9173_BCB_AADSCOPEFLAGID_INC_SECURITY_HEADER)
    {
        // If we are instructed to skip AAD check of the security block
        // then we don't have to worry about checking it.a
        const uint64_t sec_blk_num = BSL_SecOper_GetSecurityBlockNum(sec_oper);
        const int      sec_blk_res = BSL_BundleCtx_GetBlockMetadata(bundle, sec_blk_num, &bcb_context.sec_block);
        if (BSL_SUCCESS != sec_blk_res)
        {
            BSL_LOG_ERR("Failed to get security block");
            return BSL_ERR_HOST_CALLBACK_FAILED;
        }
    }

    // Compute the Addition Authenticated Data for authenticated crypto
    if (BSL_SUCCESS != BSLX_BCB_ComputeAAD(&bcb_context))
    {
        BSL_LOG_ERR("Failed to compute AAD");
        BSLX_BCB_Deinit(&bcb_context);
        return BSL_ERR_SECURITY_CONTEXT_FAILED;
    }

    // If secop is accpeting BCB, target btsd should be overwritten with resulting plaintext
    bcb_context.overwrite_btsd = BSL_SecOper_IsRoleAcceptor(sec_oper);

    // Select whether to call the encrypt or decrypt function
    int (*crypto_fn)(BSLX_BCB_t *) = bcb_context.is_source ? &BSLX_BCB_Encrypt : &BSLX_BCB_Decrypt;

    // Perform the encryption/decryption
    if (BSL_SUCCESS != crypto_fn(&bcb_context))
    {
        BSL_LOG_ERR("Failed to perform cryptographic action");
        BSLX_BCB_Deinit(&bcb_context);
        return BSL_ERR_SECURITY_CONTEXT_FAILED;
    }

    if (bcb_context.is_source)
    {
        // Generally we expect an auth tag with the encryption
        // If present, append it to the result.
        if (bcb_context.authtag.len > 0)
        {
            BSL_LOG_INFO("Appending BCB Auth Tag");
            BSL_IdValPair_t *auth_tag = BSL_SecOper_AddResult(sec_oper, RFC9173_BCB_RESULTID_AUTHTAG);
            BSL_IdValPair_SetBytestr(auth_tag, RFC9173_BCB_RESULTID_AUTHTAG, bcb_context.authtag);
        }

        if (bcb_context.iv.len > 0)
        {
            BSL_LOG_INFO("Appending BCB source IV");
            BSL_IdValPair_t *iv_param = BSL_SecOper_AddParam(sec_oper, RFC9173_BCB_SECPARAM_IV);
            BSL_IdValPair_SetBytestr(iv_param, RFC9173_BCB_SECPARAM_IV, bcb_context.iv);
        }

        {
            BSL_LOG_INFO("Appending BCB AES param");
            BSL_IdValPair_t *aes_param = BSL_SecOper_AddParam(sec_oper, RFC9173_BCB_SECPARAM_AESVARIANT);
            BSL_IdValPair_SetInt64(aes_param, RFC9173_BCB_SECPARAM_AESVARIANT, bcb_context.aes_variant);
        }

        if (bcb_context.wrapped_key.len > 0)
        {
            BSL_LOG_INFO("Appending BCB wrapped key param");
            BSL_IdValPair_t *aes_wrapped_key_param = BSL_SecOper_AddParam(sec_oper, RFC9173_BCB_SECPARAM_WRAPPEDKEY);
            BSL_IdValPair_SetBytestr(aes_wrapped_key_param, RFC9173_BCB_SECPARAM_WRAPPEDKEY, bcb_context.wrapped_key);
        }

        {
            BSL_LOG_INFO("Appending BCB scope flag param");
            BSL_IdValPair_t *scope_flag_param = BSL_SecOper_AddParam(sec_oper, RFC9173_BCB_SECPARAM_AADSCOPE);
            BSL_IdValPair_SetInt64(scope_flag_param, RFC9173_BCB_SECPARAM_AADSCOPE, bcb_context.aad_scope);
        }
    }
    // non-source role work is already done during decryption

    BSLX_BCB_Deinit(&bcb_context);
    return BSL_SUCCESS;
}
