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
    assert(0);
    (void)lib;
    (void)bundle;
    (void)sec_oper;
    return false;
}

bool BSLX_BCB_Validate(BSL_LibCtx_t *lib, const BSL_BundleRef_t *bundle, const BSL_SecOper_t *sec_oper)
{
    assert(0);
    (void)lib;
    (void)bundle;
    (void)sec_oper;
    return false;
}

size_t BSLX_Bytestr_GetCapacity(void)
{
    return BSL_DEFAULT_BYTESTR_LEN;
}

BSL_Data_t BSLX_Bytestr_AsData(BSLX_Bytestr_t *self)
{
    BSL_Data_t result = { .owned = false, .len = self->bytelen, .ptr = self->_bytes };
    return result;
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
        BSL_LOG_ERR("Unknown RFC9173 SHA variant index: %lu", rfc9173_sha_variant);
        crypto_sha_variant = BSL_ERR_PROPERTY_CHECK_FAILED;
    }
    BSL_LOG_DEBUG("Mapping RFC9173 SHA Variant %lu -> %ld", rfc9173_sha_variant, crypto_sha_variant);
    return crypto_sha_variant;
}

/**
 * Populate the BIB parameters convenience struct from the security operation struct.
 *
 * TODO: move to common function.
 */
int BSLX_BIB_InitFromSecOper(BSLX_BIB_t *self, const BSL_SecOper_t *sec_oper)
{
    assert(self != NULL);
    assert(sec_oper != NULL);
    memset(self, 0, sizeof(*self));
    self->sha_variant           = -1;
    self->integrity_scope_flags = -1;
    self->key_id                = -1;

    for (size_t param_index = 0; param_index < BSL_SecOper_CountParams(sec_oper); param_index++)
    {
        const BSL_SecParam_t *param    = BSL_SecOper_GetParamAt(sec_oper, param_index);
        uint64_t              param_id = BSL_SecParam_GetId(param);
        bool     is_int  = BSL_SecParam_IsInt64(param);
        uint64_t int_val = -1;
        if (is_int)
        {
            int_val = BSL_SecParam_GetAsUInt64(param);
        }

        if (param_id == BSL_SECPARAM_TYPE_INT_KEY_ID)
        {
            assert(is_int);
            self->key_id = int_val;
        }
        else if (param_id == BSL_SECPARAM_TYPE_INT_FIXED_KEY)
        {
            assert(0);
            assert(!is_int);
            BSL_Data_t bytestr_data = BSLX_Bytestr_AsData(&self->override_key);
            BSL_SecParam_GetAsBytestr(param, &bytestr_data);
            self->override_key.bytelen = bytestr_data.len;
        }
        else if (param_id == RFC9173_BIB_PARAMID_SHA_VARIANT)
        {
            assert(is_int);
            self->sha_variant = int_val;
        }
        else if (param_id == RFC9173_BIB_PARAMID_INTEG_SCOPE_FLAG)
        {
            assert(is_int);
            self->integrity_scope_flags = int_val;
        }
        else if (param_id == RFC9173_BIB_PARAMID_WRAPPED_KEY)
        {
            assert(!is_int);
            BSL_Data_t bytestr_data = BSLX_Bytestr_AsData(&self->wrapped_key);
            BSL_SecParam_GetAsBytestr(param, &bytestr_data);
            self->wrapped_key.bytelen = bytestr_data.len;
        }
        else
        {
            BSL_LOG_WARNING("Unknown param id: %lu", param_id);
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
    if (self->integrity_scope_flags < 0)
    {
        // If none given, assume they must all be true per spec.
        BSL_LOG_DEBUG("No scope flag set, defaulting to everything (0x07)");
        self->integrity_scope_flags = 0x07;
    }
    return BSL_SUCCESS;
}

/**
 * Computes the Integrity-Protected Plaintext (IPPT) for a canonical bundle block (non-primary)
 */
int BSLX_BIB_GenIPPT(BSLX_BIB_t *self, BSL_Data_t ippt_space)
{
    assert(self != NULL);
    assert(ippt_space.len > 0);
    assert(ippt_space.ptr != NULL);

    int                res = BSL_ERR_FAILURE;
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
            UsefulBufC prim_encoded = { .ptr = self->primary_block.cbor,
                                        .len = self->primary_block.cbor_len };
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

    const uint8_t *target_cbor     = self->primary_block.cbor;
    size_t         target_cbor_len = self->primary_block.cbor_len;

    if (self->target_block.block_num > 0)
    {
        target_cbor     = self->target_block.btsd;
        target_cbor_len = self->target_block.btsd_len;
    }
    UsefulBufC target_blk_btsd = { .ptr = target_cbor, .len = target_cbor_len };
    QCBOREncode_AddBytes(&encoder, target_blk_btsd);
    UsefulBufC ippt_result;
    cbor_err = QCBOREncode_Finish(&encoder, &ippt_result);
    if (cbor_err != QCBOR_SUCCESS)
    {
        BSL_LOG_ERR("CBOR encoding IPPT failed, code=%" PRIu32 " (%s)", cbor_err, qcbor_err_to_str(cbor_err));
        res = BSL_ERR_ENCODING;
        goto error;
    }
    return (int)(ippt_result.len);

error:;
    return res;
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
    if ((res = BSL_AuthCtx_Init(&hmac_ctx, self->key_id, self->sha_variant)) != 0)
    {
        BSL_LOG_ERR("bsl_hmac_ctx_init failed with code %d", res);
        goto error;
    }
    if ((res = BSL_AuthCtx_DigestBuffer(&hmac_ctx, ippt_data.ptr, ippt_data.len)) != 0)
    {
        BSL_LOG_ERR("bsl_hmac_ctx_input_data_buffer failed with code %d", res);
        goto error;
    }

    void  *hmac_result_ptr = (void *)&self->hmac_result_val._bytes[0];
    size_t hmaclen = 0;
    if ((res = BSL_AuthCtx_Finalize(&hmac_ctx, &hmac_result_ptr, &hmaclen)) != 0)
    {
        BSL_LOG_ERR("bsl_hmac_ctx_finalize failed with code %d", res);
        goto error;
    }
    self->hmac_result_val.bytelen = hmaclen;

    if ((res = BSL_AuthCtx_Deinit(&hmac_ctx)) != 0)
    {
        BSL_LOG_ERR("bsl_hmac_ctx_deinit failed with code %d", res);
        goto error;
    }
    assert(hmaclen > 0);
    return (int)hmaclen;

error:
    BSL_AuthCtx_Deinit(&hmac_ctx);
    BSL_LOG_ERR("%s failed bsl_crypto code=%ld", __func__, res);
    return BSL_ERR_SECURITY_OPERATION_FAILED;
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
        goto error;
    }

    const uint64_t target_blk_num = BSL_SecOper_GetTargetBlockNum(sec_oper);
    if (target_blk_num > 0)
    {
        // If the target block num is 0 (the primary block), then we do not need to fetch this
        if (BSL_SUCCESS != BSL_BundleCtx_GetBlockMetadata(bundle, target_blk_num, &bib_context.target_block))
        {
            BSL_LOG_ERR("Failed to get block data");
            goto error;
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
        goto error;
    }
    assert(ippt_len > 0);
    ippt_space.len = (size_t)ippt_len;

    const int hmac_nbytes = BSLX_BIB_GenHMAC(&bib_context, ippt_space);
    if (hmac_nbytes < BSL_SUCCESS)
    {
        BSL_LOG_ERR("Failed to generate BIB HMAC");
        goto error;
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

    BSL_SecResult_t *bib_result = BSLX_ScratchSpace_take(&scratch, BSL_SecResult_Sizeof());
    BSL_SecResult_Init(bib_result, RFC9173_BIB_RESULTID_HMAC, RFC9173_CONTEXTID_BIB_HMAC_SHA2,
                       BSL_SecOper_GetTargetBlockNum(sec_oper), BSLX_Bytestr_AsData(&bib_context.hmac_result_val));
    BSL_SecOutcome_AppendResult(sec_outcome, bib_result);

    BSL_Data_Deinit(&scratch_buffer);
    return BSL_SUCCESS;

error:

    BSL_Data_Deinit(&scratch_buffer);
    return BSL_ERR_SECURITY_CONTEXT_FAILED;
}
