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
 * Header for the implementation of an example default security context (RFC 9173).
 * Note the prefix "xdefsc" means "Example Default Security Context".
 */

#include <qcbor/qcbor_encode.h>
#include <qcbor/qcbor_spiffy_decode.h>
#include <stdio.h>
#include <sys/types.h>
#include <time.h>

#include <bsl/BPSecLib_Private.h>
#include <bsl/crypto/CryptoInterface.h>
#include <bsl/dynamic/CBOR.h>

#include "DefaultSecContext.h"
#include "DefaultSecContext_Private.h"
#include "rfc9173.h"

bool BSLX_BIB_Validate(BSL_LibCtx_t *lib, BSL_BundleRef_t *bundle, BSL_SecOper_t *sec_oper) // NOSONAR
{
    // Note: Internal API distinction.
    // Called before the `_execute` function. This checks ahead of time whether it contains the necessary info in order
    // to perform the execution.
    ASSERT_ARG_NONNULL(lib);
    ASSERT_ARG_NONNULL(bundle);
    ASSERT_ARG_NONNULL(sec_oper);
    return true;
}

/**
 * Provides the mapping from the security-context-specific ID defined in RFC9173
 * to the local ID of the SHA variant used by the crypto engine (OpenSSL).
 */
static BSL_Crypto_SHAVariant_e map_rfc9173_sha_variant_to_crypto(uint64_t rfc9173_sha_variant)
{
    BSL_Crypto_SHAVariant_e crypto_sha_variant;
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
        crypto_sha_variant = -1;
    }
    BSL_LOG_DEBUG("Mapping RFC9173 SHA Variant %zu -> %d", rfc9173_sha_variant, crypto_sha_variant);
    return crypto_sha_variant;
}

/**
 * Populate the BIB parameters convenience struct from the security operation struct.
 */
int BSLX_BIB_InitFromSecOper(BSLX_BIB_t *self, const BSL_BundleRef_t *bundle, const BSL_SecOper_t *sec_oper)
{
    ASSERT_ARG_NONNULL(self);
    ASSERT_ARG_NONNULL(sec_oper);
    memset(self, 0, sizeof(*self));

    self->bundle          = bundle;
    self->is_source       = BSL_SecOper_IsRoleSource(sec_oper);
    self->err_count       = 0;
    self->opt_sha_variant = false;
    self->opt_ippt_scope  = false;
    self->keywrap         = -1;
    BSL_Data_Init(&self->wrapped_key);
    BSL_Data_Init(&self->hmac_result_val);

    const BSL_IdValPair_t *param;
    param = BSL_SecOper_FindOption(sec_oper, BSLX_BIB_OPT_KEY_ID);
    if (param)
    {
        const char *name;
        if (BSL_SUCCESS != BSL_IdValPair_GetAsTextstr(param, &name))
        {
            BSL_LOG_ERR("Invalid Key ID value");
            self->err_count++;
        }
        else
        {
            BSL_Data_SetViewCstr(&self->key_id, name);
        }
    }
    param = BSL_SecOper_FindOption(sec_oper, BSLX_BIB_OPT_SHA_VARIANT);
    if (param)
    {
        int64_t as_int;
        if (BSL_SUCCESS != BSL_IdValPair_GetAsInt64(param, &as_int))
        {
            BSL_LOG_ERR("Invalid SHA Varriant value");
            self->err_count++;
        }
        else
        {
            self->sha_variant     = as_int;
            self->opt_sha_variant = true;
        }
    }
    param = BSL_SecOper_FindOption(sec_oper, BSLX_BIB_OPT_SCOPE);
    if (param)
    {
        int64_t as_int;
        if (BSL_SUCCESS != BSL_IdValPair_GetAsInt64(param, &as_int))
        {
            BSL_LOG_ERR("Invalid SHA Varriant value");
            self->err_count++;
        }
        else
        {
            self->ippt_scope     = as_int;
            self->opt_ippt_scope = true;
        }
    }
    param = BSL_SecOper_FindOption(sec_oper, BSLX_BIB_OPT_WRAPPED_KEY);
    if (param)
    {
        BSL_LOG_DEBUG("BIB parsing Wrapped key parameter (optid=%" PRIu64 ")", BSL_IdValPair_GetId(param));
        BSL_Data_Deinit(&self->wrapped_key);
        if (BSL_SUCCESS != BSL_IdValPair_GetAsBytestr(param, &self->wrapped_key))
        {
            BSL_LOG_ERR("Invalid wrapped key value");
            self->err_count++;
        }
    }
    param = BSL_SecOper_FindOption(sec_oper, BSLX_BIB_OPT_USE_KEY_WRAP);
    if (param)
    {
        if (BSL_SUCCESS != BSL_IdValPair_GetAsInt64(param, &self->keywrap))
        {
            BSL_LOG_ERR("Invalid Key Wrap value");
            self->err_count++;
        }
        else
        {
            BSL_LOG_DEBUG("Param[%" PRIu64 "]: USE_WRAPPED_KEY value = %" PRIu64, BSL_IdValPair_GetId(param),
                          self->keywrap);
        }
    }

    if (self->keywrap < 0)
    {
        BSL_LOG_WARNING("BIB USE KEYWRAP option is required.");
        return BSL_ERR_PROPERTY_CHECK_FAILED;
    }

    if (!self->opt_sha_variant)
    {
        // Default is SHA384: https://www.rfc-editor.org/rfc/rfc9173.html#name-block-integrity-block
        BSL_LOG_DEBUG("No SHA Variant set, defaulting to SHA_HMAC384");
        self->sha_variant = RFC9173_BIB_SHA_HMAC384;
    }
    self->crypto_sha_variant = map_rfc9173_sha_variant_to_crypto(self->sha_variant);
    if (self->crypto_sha_variant < 0)
    {
        BSL_LOG_WARNING("BIB SHA varient required.");
        return BSL_ERR_PROPERTY_CHECK_FAILED;
    }

    if (!self->opt_ippt_scope)
    {
        // If none given, assume they must all be true per spec.
        BSL_LOG_DEBUG("No scope flag set, defaulting to everything (0x07)");
        self->ippt_scope = 0x07;
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
 * Computes the Integrity-Protected Plaintext (IPPT) according to
 * Section 3.7 of RFC 9173 @cite rfc9173.
 *
 * @param[in,out] ippt_space Storage for the output, or empty to calculate
 * the needed size.
 * @return A positive value to indicate the needed size, or negative for error.
 */
int BSLX_BIB_GenIPPT(const BSLX_BIB_t *self, BSL_Data_t *ippt_space)
{
    ASSERT_ARG_NONNULL(self);
    CHK_ARG_NONNULL(ippt_space);

    QCBORError cbor_err = QCBOR_ERR_UNSUPPORTED;

    UsefulBuf result_ub =
        ippt_space->ptr ? (UsefulBuf) { .ptr = ippt_space->ptr, ippt_space->len } : SizeCalculateUsefulBuf;

    QCBOREncodeContext encoder;
    QCBOREncode_Init(&encoder, result_ub);

    QCBOREncode_AddInt64(&encoder, self->ippt_scope);

    if (self->target_block.block_num > 0)
    {
        // Now begin process of computing IPPT
        if (self->ippt_scope & RFC9173_BIB_INTEGSCOPEFLAG_INC_PRIM)
        {
            QCBOREncode_AddEncoded(&encoder, UsefulBufC_FROM_BSL_Data(*(self->primary_block.encoded)));
        }
        if (self->ippt_scope & RFC9173_BIB_INTEGSCOPEFLAG_INC_TARGET_HDR)
        {
            BSLX_EncodeHeader(&self->target_block, &encoder);
        }
    }

    if (self->ippt_scope & RFC9173_BIB_INTEGSCOPEFLAG_INC_SEC_HDR)
    {
        BSLX_EncodeHeader(&self->sec_block, &encoder);
    }

    if (self->target_block.block_num > 0)
    {
        // IPPT needs the whole data now
        BSL_Data_t btsd_copy;
        BSL_Data_InitBuffer(&btsd_copy, self->target_block.btsd_len);

        BSL_SeqReader_t *btsd_read = BSL_BundleCtx_ReadBTSD(self->bundle, self->target_block.block_num);
        if (!btsd_read)
        {
            BSL_LOG_ERR("Failed to open BTSD reader on block %" PRIu64, self->target_block.block_num);
        }
        BSL_SeqReader_Get(btsd_read, btsd_copy.ptr, &btsd_copy.len);
        BSL_SeqReader_Destroy(btsd_read);
        if (btsd_copy.len != self->target_block.btsd_len)
        {
            BSL_LOG_ERR("Failed to read all %zu BTSD, got only %zu", self->target_block.btsd_len, btsd_copy.len);
        }

        QCBOREncode_AddBytes(&encoder, UsefulBufC_FROM_BSL_Data(btsd_copy));
        BSL_Data_Deinit(&btsd_copy);
    }
    else
    {
        QCBOREncode_AddBytes(&encoder, UsefulBufC_FROM_BSL_Data(*(self->primary_block.encoded)));
    }

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
 * @return BSL_SUCCESS if successful.
 */
int BSLX_BIB_GenHMAC(BSLX_BIB_t *self, const BSL_Data_t *ippt_data)
{
    CHK_ARG_NONNULL(self);
    CHK_ARG_NONNULL(ippt_data);

    BSL_AuthCtx_t hmac_ctx;
    int           res = 0;

    BSL_Crypto_KeyHandle_t key_id_handle;
    BSL_Crypto_KeyHandle_t cipher_key;
    if (BSL_SUCCESS != BSL_Crypto_GetRegistryKey(&self->key_id, &key_id_handle))
    {
        BSL_LOG_ERR("Cannot get registry key");
        return BSL_ERR_SECURITY_CONTEXT_FAILED;
    }

    if (!self->keywrap)
    {
        // Bypass, use the Key-Encryption-Key (KEK) as the Content-Encryption-Key (CEK)
        // This is legal per the RFC9173 spec, but not generally advised.
        BSL_LOG_WARNING("Skipping keywrap (this is not advised)");
        // Directly load key_id into content enc key
        cipher_key = key_id_handle;
    }
    else
    {
        if (self->is_source)
        {
            const size_t keysize = 16;
            BSL_LOG_DEBUG("Generating %zu bit AES key", keysize * 8);

            if (BSL_SUCCESS != BSL_Crypto_GenKey(keysize, &cipher_key))
            {
                BSL_LOG_ERR("Failed to generate AES key");
                BSL_Crypto_ReleaseKeyHandle(key_id_handle);
                BSL_Crypto_ReleaseKeyHandle(cipher_key);
                return BSL_ERR_SECURITY_CONTEXT_CRYPTO_FAILED;
            }

            int wrap_result = BSL_Crypto_WrapKey(key_id_handle, cipher_key, &self->wrapped_key);
            BSL_Crypto_ReleaseKeyHandle(key_id_handle);
            if (BSL_SUCCESS != wrap_result)
            {
                BSL_LOG_ERR("Failed to wrap key");
                BSL_Crypto_ReleaseKeyHandle(cipher_key);
                return BSL_ERR_SECURITY_CONTEXT_CRYPTO_FAILED;
            }
        }
        else
        {
            if (self->wrapped_key.len == 0)
            {
                BSL_LOG_ERR("Key wrapping enabled, but no wrapped key set");
                return BSL_ERR_SECURITY_CONTEXT_CRYPTO_FAILED;
            }

            int unwrap_result = BSL_Crypto_UnwrapKey(key_id_handle, &self->wrapped_key, &cipher_key);
            BSL_Crypto_ReleaseKeyHandle(key_id_handle);
            if (BSL_SUCCESS != unwrap_result)
            {
                BSL_LOG_ERR("Failed to unwrap key");
                BSL_Crypto_ReleaseKeyHandle(cipher_key);
                return BSL_ERR_SECURITY_CONTEXT_FAILED;
            }
        }
    }

    int retval = BSL_SUCCESS;

    res = BSL_AuthCtx_Init(&hmac_ctx, cipher_key, self->crypto_sha_variant);
    BSL_Crypto_ReleaseKeyHandle(cipher_key);
    cipher_key = NULL;
    if (BSL_SUCCESS != res)
    {
        BSL_LOG_ERR("bsl_hmac_ctx_init failed with code %d", res);
        BSL_AuthCtx_Deinit(&hmac_ctx);
        retval = BSL_ERR_SECURITY_CONTEXT_AUTH_FAILED;
    }

    if (BSL_SUCCESS == retval)
    {
        res = BSL_AuthCtx_DigestBuffer(&hmac_ctx, ippt_data->ptr, ippt_data->len);
        if (BSL_SUCCESS != res)
        {
            BSL_LOG_ERR("bsl_hmac_ctx_input_data_buffer failed with code %d", res);
            retval = BSL_ERR_SECURITY_CONTEXT_AUTH_FAILED;
        }
    }

    if (BSL_SUCCESS == retval)
    {
        res = BSL_AuthCtx_Finalize(&hmac_ctx, &self->hmac_result_val);
        if (BSL_SUCCESS != res)
        {
            BSL_LOG_ERR("bsl_hmac_ctx_finalize failed with code %d", res);
            retval = BSL_ERR_SECURITY_CONTEXT_AUTH_FAILED;
        }
    }

    BSL_AuthCtx_Deinit(&hmac_ctx);

    return retval;
}

int BSLX_BIB_Execute(BSL_LibCtx_t *lib, BSL_BundleRef_t *bundle, BSL_SecOper_t *sec_oper) // NOSONAR
{
    CHK_ARG_NONNULL(lib);
    CHK_ARG_NONNULL(bundle);
    CHK_ARG_NONNULL(sec_oper);
    CHK_PRECONDITION(BSL_SecOper_IsConsistent(sec_oper));

    BSLX_BIB_t bib_context;
    if (BSL_SUCCESS != BSLX_BIB_InitFromSecOper(&bib_context, bundle, sec_oper))
    {
        BSL_LOG_ERR("Failed to init bib context from security operation");
        BSLX_BIB_Deinit(&bib_context);
        return BSL_ERR_SECURITY_CONTEXT_FAILED;
    }

    if (!bib_context.is_source)
    {
        // find the existing parameters and results
        const BSL_IdValPair_t *param;

        param = BSL_SecOper_FindParam(sec_oper, RFC9173_BIB_PARAMID_SHA_VARIANT);
        if (param)
        {
            int64_t got;
            if (BSL_SUCCESS != BSL_IdValPair_GetAsInt64(param, &got))
            {
                BSL_LOG_ERR("SHA variant parameter is not valid");
                bib_context.err_count++;
            }
            else if (bib_context.opt_sha_variant && (got != bib_context.sha_variant))
            {
                BSL_LOG_ERR("SHA variant mismatch, needed %d got %d", bib_context.sha_variant, got);
                bib_context.err_count++;
            }
            else
            {
                bib_context.sha_variant = got;
            }
        }

        param = BSL_SecOper_FindParam(sec_oper, RFC9173_BIB_PARAMID_INTEG_SCOPE_FLAG);
        if (param)
        {
            int64_t got;
            if (BSL_SUCCESS != BSL_IdValPair_GetAsInt64(param, &got))
            {
                BSL_LOG_ERR("IPPT Scope parameter is not valid");
                bib_context.err_count++;
            }
            else
            {
                if (bib_context.opt_ippt_scope && (got != bib_context.ippt_scope))
                {
                    BSL_LOG_WARNING("IPPT Scope mismatch, needed %d got %d", bib_context.ippt_scope, got);
                }
                bib_context.ippt_scope = got;
            }
        }

        param = BSL_SecOper_FindParam(sec_oper, RFC9173_BIB_PARAMID_WRAPPED_KEY);
        if (param)
        {
            if (BSL_SUCCESS != BSL_IdValPair_GetAsBytestr(param, &bib_context.wrapped_key))
            {
                BSL_LOG_ERR("Wrapped key parameter is not valid");
                bib_context.err_count++;
            }
            BSL_LOG_DEBUG("Wrapped key parameter used");
        }
    }
    if (bib_context.err_count)
    {
        BSLX_BIB_Deinit(&bib_context);
        return BSL_ERR_SECURITY_CONTEXT_FAILED;
    }

    if (BSL_SUCCESS != BSL_BundleCtx_GetBundleMetadata(bundle, &bib_context.primary_block))
    {
        BSL_LOG_ERR("Failed to get bundle data");
        BSLX_BIB_Deinit(&bib_context);
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

    // first determine the size needed, then encode actual IPPT
    BSL_Data_t ippt_space = BSL_DATA_INIT_NULL;
    int        ippt_len   = BSLX_BIB_GenIPPT(&bib_context, &ippt_space);
    if (ippt_len <= 0)
    {
        BSL_LOG_ERR("GenIPPT returned %d", ippt_len);
        BSLX_BIB_Deinit(&bib_context);
        BSL_Data_Deinit(&ippt_space);
        return BSL_ERR_SECURITY_CONTEXT_FAILED;
    }
    BSL_Data_InitBuffer(&ippt_space, ippt_len);
    ippt_len = BSLX_BIB_GenIPPT(&bib_context, &ippt_space);
    if (ippt_len <= 0)
    {
        BSL_LOG_ERR("GenIPPT returned %d", ippt_len);
        BSLX_BIB_Deinit(&bib_context);
        BSL_Data_Deinit(&ippt_space);
        return BSL_ERR_SECURITY_CONTEXT_FAILED;
    }

    const int hmac_status = BSLX_BIB_GenHMAC(&bib_context, &ippt_space);
    if (hmac_status != BSL_SUCCESS)
    {
        BSL_LOG_ERR("Failed to generate BIB HMAC");
        BSLX_BIB_Deinit(&bib_context);
        BSL_Data_Deinit(&ippt_space);
        return BSL_ERR_SECURITY_CONTEXT_FAILED;
    }
    BSL_Data_Deinit(&ippt_space);

    if (bib_context.is_source)
    {
        {
            BSL_LOG_DEBUG("Appending SHA variant param");
            BSL_IdValPair_t *scope_flag_param = BSL_SecOper_AddParam(sec_oper, RFC9173_BIB_PARAMID_SHA_VARIANT);
            BSL_IdValPair_SetInt64(scope_flag_param, RFC9173_BIB_PARAMID_SHA_VARIANT, bib_context.sha_variant);
        }
        {
            BSL_LOG_DEBUG("Appending IPPT scope flag param");
            BSL_IdValPair_t *scope_flag_param = BSL_SecOper_AddParam(sec_oper, RFC9173_BIB_PARAMID_INTEG_SCOPE_FLAG);
            BSL_IdValPair_SetInt64(scope_flag_param, RFC9173_BIB_PARAMID_INTEG_SCOPE_FLAG, bib_context.ippt_scope);
        }
        {
            BSL_LOG_DEBUG("Appending BIB wrapped key param");
            BSL_IdValPair_t *bib_result = BSL_SecOper_AddResult(sec_oper, RFC9173_BIB_RESULTID_HMAC);
            BSL_IdValPair_SetBytestr(bib_result, RFC9173_BIB_RESULTID_HMAC, bib_context.hmac_result_val);
        }

        if (bib_context.wrapped_key.len > 0)
        {
            BSL_LOG_DEBUG("Appending BIB wrapped key param");
            BSL_IdValPair_t *wrapped_key_param = BSL_SecOper_AddParam(sec_oper, RFC9173_BIB_PARAMID_WRAPPED_KEY);
            BSL_IdValPair_SetBytestr(wrapped_key_param, RFC9173_BIB_PARAMID_WRAPPED_KEY, bib_context.wrapped_key);
        }
    }
    else
    {
        // verify the existing tag
        BSL_Data_t got_hmac = BSL_DATA_INIT_NULL;

        const BSL_IdValPair_t *result;
        result = BSL_SecOper_FindResult(sec_oper, RFC9173_BIB_RESULTID_HMAC);
        if (result)
        {
            if (BSL_IdValPair_IsBytestr(result))
            {
                BSL_IdValPair_GetAsBytestr(result, &got_hmac);
            }
            else
            {
                BSL_LOG_ERR("Auth tag result is not valid");
                BSLX_BIB_Deinit(&bib_context);
                return BSL_ERR_SECURITY_CONTEXT_FAILED;
            }
        }
        else
        {
            BSL_LOG_ERR("Auth tag result is not present");
            BSLX_BIB_Deinit(&bib_context);
            return BSL_ERR_SECURITY_CONTEXT_FAILED;
        }

        if (!BSL_Crypto_Compare(bib_context.hmac_result_val.ptr, bib_context.hmac_result_val.len, got_hmac.ptr,
                                got_hmac.len))
        {
            BSL_LOG_ERR("Auth tag result mismatched");
            BSLX_BIB_Deinit(&bib_context);
            return BSL_ERR_SECURITY_CONTEXT_FAILED;
        }
        BSL_LOG_DEBUG("Auth tag verified equal");
    }

    BSLX_BIB_Deinit(&bib_context);
    return BSL_SUCCESS;
}
