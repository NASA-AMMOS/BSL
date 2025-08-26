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
 * Header for the implementation of an example default security context (RFC 9173).
 * Note the prefix "xdefsc" means "Example Default Security Context".
 * @ingroup example_security_context
 */

#include <qcbor/qcbor_encode.h>
#include <qcbor/qcbor_spiffy_decode.h>
#include <stdio.h>
#include <sys/types.h>
#include <time.h>

#include <BPSecLib_Private.h>
#include <CryptoInterface.h>

#include "DefaultSecContext.h"
#include "DefaultSecContext_Private.h"
#include "rfc9173.h"

bool BSLX_BIB_Validate(BSL_LibCtx_t *lib, const BSL_BundleRef_t *bundle, const BSL_SecOper_t *sec_oper)
{
    // Note: Internal API distinction.
    // Called before the `_execute` function. This checks ahead of time whether it contains the necessary info in order
    // to perform the execution.
    (void)lib;
    (void)bundle;
    (void)sec_oper;
    return false;
}

bool BSLX_BCB_Validate(BSL_LibCtx_t *lib, const BSL_BundleRef_t *bundle, const BSL_SecOper_t *sec_oper)
{
    (void)lib;
    (void)bundle;
    (void)sec_oper;
    return false;
}

/**
 * Provides the mapping from the security-context-specific ID defined in RFC9173
 * to the local ID of the SHA variant used by the crypto engine (OpenSSL).
 */
static ssize_t map_rfc9173_sha_variant_to_crypto(size_t rfc9173_sha_variant)
{
    ssize_t crypto_sha_variant = -1;
    if (rfc9173_sha_variant == RFC9173_BIB_SHA_HMAC512)
    {
        crypto_sha_variant = BSL_CRYPTO_SHA_512;
    }
    else if (rfc9173_sha_variant == RFC9173_BIB_SHA_HMAC384)
    {
        crypto_sha_variant = BSL_CRYPTO_SHA_384;
    }
    else if (rfc9173_sha_variant == RFC9173_BIB_SHA_HMAC256)
    {
        crypto_sha_variant = BSL_CRYPTO_SHA_256;
    }
    else
    {
        BSL_LOG_ERR("Unknown RFC9173 SHA variant index: %zu", rfc9173_sha_variant);
        crypto_sha_variant = BSL_ERR_PROPERTY_CHECK_FAILED;
    }
    BSL_LOG_DEBUG("Mapping RFC9173 SHA Variant %zu -> %zd", rfc9173_sha_variant, crypto_sha_variant);
    return crypto_sha_variant;
}

/**
 * Populate the BIB parameters convenience struct from the security operation struct.
 *
 * TODO: move to common function.
 */
int BSLX_BIB_InitFromSecOper(BSLX_BIB_t *self, const BSL_SecOper_t *sec_oper)
{
    ASSERT_ARG_NONNULL(self);
    ASSERT_ARG_NONNULL(sec_oper);
    memset(self, 0, sizeof(*self));
    self->sha_variant           = -1;
    self->integrity_scope_flags = -1;
    self->hash_size = 0;
    // By default, skip keywrap
    self->keywrap_aes = 0;

    for (size_t param_index = 0; param_index < BSL_SecOper_CountParams(sec_oper); param_index++)
    {
        const BSL_SecParam_t *param    = BSL_SecOper_GetParamAt(sec_oper, param_index);
        uint64_t              param_id = BSL_SecParam_GetId(param);
        bool                  is_int   = BSL_SecParam_IsInt64(param);
        int64_t               int_val  = -1;
        if (is_int)
        {
            int_val = BSL_SecParam_GetAsUInt64(param);
        }

        if (param_id == BSL_SECPARAM_TYPE_KEY_ID)
        {
            ASSERT_PRECONDITION(!is_int);
            BSL_Data_t res;
            BSL_SecParam_GetAsBytestr(param, &res);
            self->key_id = (char *)res.ptr;
        }
        else if (param_id == RFC9173_BIB_PARAMID_SHA_VARIANT)
        {
            ASSERT_PRECONDITION(is_int);
            self->sha_variant = int_val;
        }
        else if (param_id == RFC9173_BIB_PARAMID_INTEG_SCOPE_FLAG)
        {
            ASSERT_PRECONDITION(is_int);
            self->integrity_scope_flags = int_val;
        }
        else if (param_id == RFC9173_BIB_PARAMID_WRAPPED_KEY)
        {
            ASSERT_PRECONDITION(!is_int);
            BSL_SecParam_GetAsBytestr(param, &self->wrapped_key);
        }
        else if (param_id == BSL_SECPARAM_TYPE_WRAPPED_KEY_AES_MODE)
        {
            const uint64_t arg_val = BSL_SecParam_GetAsUInt64(param);
            BSL_LOG_DEBUG("Param[%" PRIu64 "]: USE_WRAPPED_KEY value = %" PRIu64, param_id, arg_val);
            self->keywrap_aes = arg_val;
            break;
        }
        else
        {
            BSL_LOG_WARNING("Unknown param id: %" PRIu64, param_id);
            return BSL_ERR_PROPERTY_CHECK_FAILED;
        }
    }

    if (self->sha_variant < 0)
    {
        // Default is SHA384: https://www.rfc-editor.org/rfc/rfc9173.html#name-block-integrity-block
        BSL_LOG_DEBUG("No SHA Variant set, defaulting to SHA_HMAC384");
        self->sha_variant = RFC9173_BIB_SHA_HMAC384;
    }
    self->sha_variant = map_rfc9173_sha_variant_to_crypto(self->sha_variant);
    if (self->sha_variant < 0)
    {
        BSL_LOG_WARNING("BIB SHA varient required.");
        return BSL_ERR_PROPERTY_CHECK_FAILED;
    }
    
    switch(self->sha_variant)
    {
        case BSL_CRYPTO_SHA_512:
        {
            self->hash_size = 64;
            break;
        }
        case BSL_CRYPTO_SHA_384:
        {
            self->hash_size = 48;
            break;
        }
        case BSL_CRYPTO_SHA_256:
        {
            self->hash_size = 32;
            break;
        }
    }

    if (self->integrity_scope_flags < 0)
    {
        // If none given, assume they must all be true per spec.
        BSL_LOG_DEBUG("No scope flag set, defaulting to everything (0x07)");
        self->integrity_scope_flags = 0x07;
    }
    return BSL_SUCCESS;
}

void BSLX_BIB_Deinit(BSLX_BIB_t *self)
{
    ASSERT_ARG_NONNULL(self);

    BSL_PrimaryBlock_deinit(&self->primary_block);
    BSL_Data_Deinit(&self->wrapped_key);
    BSL_Data_Deinit(&self->hmac_result_val);
}

/**
 * Computes the Integrity-Protected Plaintext (IPPT) for a canonical bundle block (non-primary)
 */
int BSLX_BIB_GenIPPT(BSLX_BIB_t *self, BSL_Data_t ippt_space)
{
    ASSERT_ARG_NONNULL(self);
    ASSERT_ARG_EXPR(ippt_space.len > 0);
    ASSERT_ARG_NONNULL(ippt_space.ptr);

    QCBOREncodeContext encoder;
    QCBORError         cbor_err  = QCBOR_ERR_UNSUPPORTED;
    UsefulBuf          result_ub = { .ptr = ippt_space.ptr, ippt_space.len };
    QCBOREncode_Init(&encoder, result_ub);
    QCBOREncode_AddInt64(&encoder, self->integrity_scope_flags);

    if (self->target_block.block_num > 0)
    {
        // Now begin process of computing IPPT
        if (self->integrity_scope_flags & RFC9173_BIB_INTEGSCOPEFLAG_INC_PRIM)
        {
            UsefulBufC prim_encoded = { .ptr = self->primary_block.encoded.ptr,
                                        .len = self->primary_block.encoded.len };
            QCBOREncode_AddEncoded(&encoder, prim_encoded);
        }
        if (self->integrity_scope_flags & RFC9173_BIB_INTEGSCOPEFLAG_INC_TARGET_HDR)
        {
            BSLX_EncodeHeader(&self->target_block, &encoder);
        }
    }

    if (self->integrity_scope_flags & RFC9173_BIB_INTEGSCOPEFLAG_INC_SEC_HDR)
    {
        BSLX_EncodeHeader(&self->sec_block, &encoder);
    }

    const uint8_t *target_cbor;
    size_t         target_cbor_len;
    if (self->target_block.block_num > 0)
    {
        target_cbor     = self->target_block.btsd;
        target_cbor_len = self->target_block.btsd_len;
    }
    else
    {
        target_cbor     = self->primary_block.encoded.ptr;
        target_cbor_len = self->primary_block.encoded.len;
    }

    UsefulBufC target_blk_btsd = { .ptr = target_cbor, .len = target_cbor_len };
    QCBOREncode_AddBytes(&encoder, target_blk_btsd);
    UsefulBufC ippt_result;
    cbor_err = QCBOREncode_Finish(&encoder, &ippt_result);
    if (cbor_err != QCBOR_SUCCESS)
    {
        BSL_LOG_ERR("CBOR encoding IPPT failed, code=%" PRIu32 " (%s)", cbor_err, qcbor_err_to_str(cbor_err));
        return BSL_ERR_ENCODING;
    }
    return (int)(ippt_result.len);
}

/**
 * Performs the actual HMAC over the given IPPT, placing the result in `hmac_result`.
 * Returns the number of bytes written into hmac_result.
 * Negative indicates error.
 * NOTE: This does NOT resize the result, the caller must do so.
 */
int BSLX_BIB_GenHMAC(BSLX_BIB_t *self, BSL_Data_t ippt_data)
{
    CHK_ARG_NONNULL(self);

    BSL_AuthCtx_t hmac_ctx;
    int res = 0;

    const void *key_id_handle;
    const void *cipher_key;
    const void *wrapped_key;
    if (BSL_SUCCESS != BSLB_Crypto_GetRegistryKey(self->key_id, &key_id_handle))
    {
        BSL_LOG_ERR("Cannot get registry key");
        return BSL_ERR_SECURITY_CONTEXT_FAILED;
    }

    uint64_t keywrap_aes_to_use = 0;
    switch (self->keywrap_aes)
    {
        case 0:
        {
            keywrap_aes_to_use = 0;
            break;
        }
        case 16:
        {
            keywrap_aes_to_use = BSL_CRYPTO_AES_128;
            break;
        }
        case 24:
        {
            keywrap_aes_to_use = BSL_CRYPTO_AES_192;
            break;
        }
        case 32:
        {
            keywrap_aes_to_use = BSL_CRYPTO_AES_256;
            break;
        }
        default:
        {
            BSL_LOG_DEBUG("Invalid wrapped key length %"PRIu64" (must be 0 - skip, 16 - AES128, 24 - AES192, 32 - AES256)", self->keywrap_aes);
        }
    }

    if (0 == self->keywrap_aes)
    {
        // Bypass, use the Key-Encryption-Key (KEK) as the Content-Encryption-Key (CEK)
        // This is legal per the RFC9173 spec, but not generally advised.
        BSL_LOG_WARNING("Skipping keywrap (this is not advised)");
        // Directly load key_id into content enc key
        cipher_key = key_id_handle;
    }
    else
    {
        const size_t keysize = 16;
        BSL_LOG_DEBUG("Generating %zu bit AES key", keysize * 8);

        if (BSL_SUCCESS != BSL_Crypto_GenKey(keysize, &cipher_key))
        {
            BSL_LOG_ERR("Failed to generate AES key");
            BSL_Crypto_ClearKeyHandle((void *)cipher_key);
            return BSL_ERR_SECURITY_CONTEXT_CRYPTO_FAILED;
        }

        if (BSL_SUCCESS != BSL_Data_InitBuffer(&self->wrapped_key, keysize + 8))
        {
            BSL_LOG_ERR("Failed to allocate wrapped key");
            BSL_Crypto_ClearKeyHandle((void *)cipher_key);
            return BSL_ERR_SECURITY_CONTEXT_FAILED;
        }

        int wrap_result =
            BSL_Crypto_WrapKey(key_id_handle, keywrap_aes_to_use, cipher_key, &self->wrapped_key, &wrapped_key);

        if (BSL_SUCCESS != wrap_result)
        {
            BSL_LOG_ERR("Failed to wrap AES key");
            BSL_Crypto_ClearKeyHandle((void *)wrapped_key);
            BSL_Crypto_ClearKeyHandle((void *)cipher_key);
            return BSL_ERR_SECURITY_CONTEXT_CRYPTO_FAILED;
        }
    }

    if ((res = BSL_AuthCtx_Init(&hmac_ctx, cipher_key, self->sha_variant)) != 0)
    {
        BSL_LOG_ERR("bsl_hmac_ctx_init failed with code %d", res);
        BSL_AuthCtx_Deinit(&hmac_ctx);
        return BSL_ERR_SECURITY_CONTEXT_AUTH_FAILED;
    }
    if ((res = BSL_AuthCtx_DigestBuffer(&hmac_ctx, ippt_data.ptr, ippt_data.len)) != 0)
    {
        BSL_LOG_ERR("bsl_hmac_ctx_input_data_buffer failed with code %d", res);
        BSL_AuthCtx_Deinit(&hmac_ctx);
        return BSL_ERR_SECURITY_CONTEXT_AUTH_FAILED;
    }

    BSL_Data_InitBuffer(&self->hmac_result_val, self->hash_size);
    size_t hmaclen         = 0;
    if ((res = BSL_AuthCtx_Finalize(&hmac_ctx, (void **) &self->hmac_result_val.ptr, &hmaclen)) != 0)
    {
        BSL_LOG_ERR("bsl_hmac_ctx_finalize failed with code %d", res);
        BSL_AuthCtx_Deinit(&hmac_ctx);
        return BSL_ERR_SECURITY_CONTEXT_AUTH_FAILED;
    }
    self->hmac_result_val.len = hmaclen;

    if ((res = BSL_AuthCtx_Deinit(&hmac_ctx)) != 0)
    {
        BSL_LOG_ERR("bsl_hmac_ctx_deinit failed with code %d", res);
        return BSL_ERR_SECURITY_CONTEXT_AUTH_FAILED;
    }
    ASSERT_POSTCONDITION(hmaclen > 0);
    return (int)hmaclen;
}

int BSLX_BIB_Execute(BSL_LibCtx_t *lib, const BSL_BundleRef_t *bundle, const BSL_SecOper_t *sec_oper,
                     BSL_SecOutcome_t *sec_outcome)
{
    CHK_ARG_NONNULL(lib);
    CHK_ARG_NONNULL(bundle);
    CHK_ARG_NONNULL(sec_oper);
    CHK_ARG_NONNULL(sec_outcome);

    CHK_PRECONDITION(BSL_SecOper_IsConsistent(sec_oper));

    BSL_Data_t scratch_buffer = { 0 };
    if (BSL_SUCCESS != BSL_Data_InitBuffer(&scratch_buffer, 4096 * 4))
    {
        BSL_LOG_ERR("Failed to allocate scratch space");
        return BSL_ERR_INSUFFICIENT_SPACE;
    }

    BSLX_ScratchSpace_t scratch;
    scratch.buffer   = scratch_buffer.ptr;
    scratch.size     = scratch_buffer.len;
    scratch.position = 1;

    BSL_Data_t ippt_space = { .ptr = BSLX_ScratchSpace_take(&scratch, 5000), .len = 5000 };

    BSLX_BIB_t bib_context = { 0 };
    BSLX_BIB_InitFromSecOper(&bib_context, sec_oper);

    if (BSL_SUCCESS != BSL_BundleCtx_GetBundleMetadata(bundle, &bib_context.primary_block))
    {
        BSL_LOG_ERR("Failed to get bundle data");
        BSLX_BIB_Deinit(&bib_context);
        BSL_Data_Deinit(&scratch_buffer);
        return BSL_ERR_SECURITY_CONTEXT_FAILED;
    }

    const uint64_t target_blk_num = BSL_SecOper_GetTargetBlockNum(sec_oper);
    if (target_blk_num > 0)
    {
        // If the target block num is 0 (the primary block), then we do not need to fetch this
        if (BSL_SUCCESS != BSL_BundleCtx_GetBlockMetadata(bundle, target_blk_num, &bib_context.target_block))
        {
            BSL_LOG_ERR("Failed to get block data");
            BSLX_BIB_Deinit(&bib_context);
            BSL_Data_Deinit(&scratch_buffer);
            return BSL_ERR_SECURITY_CONTEXT_FAILED;
        }
    }

    const uint64_t sec_blk_num = BSL_SecOper_GetSecurityBlockNum(sec_oper);
    if (BSL_SUCCESS != BSL_BundleCtx_GetBlockMetadata(bundle, sec_blk_num, &bib_context.sec_block))
    {
        // It is somewhat anomalous to fail to get the security block;
        // It should already have been created. However, when doing set-piece
        // tests, it is possible. And it's not always needed for the security
        // operation anyway. So for now, long a warning about it, but otherwise proceed.
        BSL_LOG_WARNING("Failed to get security block data");
    }

    const int ippt_len = BSLX_BIB_GenIPPT(&bib_context, ippt_space);
    if (ippt_len <= 0)
    {
        BSL_LOG_ERR("GenIPPT returned %d", ippt_len);
        BSLX_BIB_Deinit(&bib_context);
        BSL_Data_Deinit(&scratch_buffer);
        return BSL_ERR_SECURITY_CONTEXT_FAILED;
    }
    ASSERT_POSTCONDITION(ippt_len > 0);
    ippt_space.len = (size_t)ippt_len;

    const int hmac_nbytes = BSLX_BIB_GenHMAC(&bib_context, ippt_space);
    if (hmac_nbytes < BSL_SUCCESS)
    {
        BSL_LOG_ERR("Failed to generate BIB HMAC");
        BSLX_BIB_Deinit(&bib_context);
        BSL_Data_Deinit(&scratch_buffer);
        return BSL_ERR_SECURITY_CONTEXT_FAILED;
    }

    // This gets all the parameters that need to be placed in the output
    for (size_t index = 0; index < BSL_SecOper_CountParams(sec_oper); index++)
    {
        const BSL_SecParam_t *sec_param = BSL_SecOper_GetParamAt(sec_oper, index);
        if (BSL_SecParam_IsParamIDOutput(BSL_SecParam_GetId(sec_param)))
        {
            BSL_SecParam_t *dst_param = BSLX_ScratchSpace_take(&scratch, BSL_SecParam_Sizeof());
            memcpy(dst_param, sec_param, BSL_SecParam_Sizeof());
            BSL_SecOutcome_AppendParam(sec_outcome, dst_param);
        }
    }

    BSL_SecResult_t *bib_result   = BSLX_ScratchSpace_take(&scratch, BSL_SecResult_Sizeof());
    BSL_SecResult_Init(bib_result, RFC9173_BIB_RESULTID_HMAC, RFC9173_CONTEXTID_BIB_HMAC_SHA2,
                       BSL_SecOper_GetTargetBlockNum(sec_oper), &bib_context.hmac_result_val);
    BSL_SecOutcome_AppendResult(sec_outcome, bib_result);

    BSLX_BIB_Deinit(&bib_context);
    BSL_Data_Deinit(&scratch_buffer);
    return BSL_SUCCESS;
}
