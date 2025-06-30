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
 * Header for the implementation of an example default security context (RFC 9173).
 * Note the prefix "xdefsc" means "Example Default Security Context".
 * @ingroup example_security_context
 */

#include "rfc9173.h"
#include "DefaultSecContext.h"
#include "DefaultSecContext_Private.h"
#include <BPSecLib.h>
#include <qcbor/qcbor_encode.h>
#include <qcbor/qcbor_spiffy_decode.h>
#include <time.h>
#include <stdio.h>

bool BSLX_ValidateBIB(BSL_LibCtx_t *lib, const BSL_BundleCtx_t *bundle, const BSL_SecOper_t *sec_oper)
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

bool BSLX_ValidateBCB(BSL_LibCtx_t *lib, const BSL_BundleCtx_t *bundle, const BSL_SecOper_t *sec_oper)
{
    assert(0);
    (void)lib;
    (void)bundle;
    (void)sec_oper;
    return false;
}

/**
 * Populate the given metadata result struct with metadata from the given block,
 * returns negative when the target block does not exist or not in a valid state.
 */
errcode_t get_target_block_metadata(BSLX_BlockMetadata_t *metadata_result, const BSL_BundleCtx_t *bundle,
                                    size_t target_block_num)
{
    assertNonNull(bundle);
    assertNonNull(metadata_result);
    const size_t max_blocks = 256;

    BSL_LOG_DEBUG("Searching for block #%lu", target_block_num);
    size_t blk_index;
    for (blk_index = 0; blk_index < max_blocks; blk_index++)
    {
        memset(metadata_result, 0, sizeof(*metadata_result));
        metadata_result->blk_num = blk_index;
        if (BSL_BundleContext_GetBlockMetadata(bundle, blk_index, &metadata_result->blk_type, &metadata_result->flags,
                                               &metadata_result->crc_type, &metadata_result->btsd)
            == 0)
        {
            BSL_LOG_DEBUG("Searching Block #%lu for key block #%lu", blk_index, target_block_num);
            if (blk_index == target_block_num)
            {
                assert(metadata_result->blk_num > 0);
                return 0;
            }
        }
    }
    BSL_LOG_WARNING("Cannot find target block #%lu in bundle", target_block_num);
    return -BSLX_SECCTXERR_ERR_DATA_INTEGRITY;
}

size_t BSLX_Bytestr_GetCapacity(void)
{
    return BSL_DEFAULT_BYTESTR_LEN;
}

void BSLX_Bytestr_Init(BSLX_Bytestr_t *bytestr, const uint8_t *srcptr, size_t srclen)
{
    assert(srcptr != NULL);
    assert(srclen < BSL_DEFAULT_BYTESTR_LEN);
    memset(bytestr, 0, sizeof(*bytestr));
    bytestr->bytelen = srclen;
    memcpy(bytestr->_bytes, srcptr, bytestr->bytelen);
}

BSL_Data_t BSLX_Bytestr_AsData(BSLX_Bytestr_t *bytestr)
{
    BSL_Data_t result = { .owned = false, .len = bytestr->bytelen, .ptr = bytestr->_bytes };
    return result;
}

bool BSLX_Bytestr_IsEmpty(const BSLX_Bytestr_t *bytestr)
{
    // Check here, bc if this is larger it may mean its uninitialized
    assert(bytestr->bytelen < BSLX_Bytestr_GetCapacity());

    BSLX_Bytestr_t zeroes;
    memset(&zeroes, 0, sizeof(zeroes));
    return memcmp(&zeroes, bytestr, sizeof(zeroes)) == 0 ? true : false;
}

/**
 * Provides the mapping from the security-context-specific ID defined in RFC9173
 * to the local ID of the SHA variant used by the crypto engine (OpenSSL).
 */
ssize_t map_rfc9173_sha_variant_to_crypto(size_t rfc9173_sha_variant)
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
        crypto_sha_variant = -BSLX_SECCTXERR_ERR_DATA_INTEGRITY;
    }
    BSL_LOG_DEBUG("Mapping RFC9173 SHA Variant %lu -> %ld", rfc9173_sha_variant, crypto_sha_variant);
    return crypto_sha_variant;
}

/**
 * Populate the BIB parameters convenience struct from the security operation struct.
 *
 * TODO: move to common function.
 */
int BSLX_BIBContext_InitFromSecOper(BSLX_BIBContext_t *bib_context, const BSL_SecOper_t *sec_oper)
{
    assert(bib_context != NULL);
    assert(sec_oper != NULL);
    memset(bib_context, 0, sizeof(*bib_context));
    bib_context->sha_variant           = -1;
    bib_context->integrity_scope_flags = -1;
    bib_context->key_id                = -1;

    BSL_LOG_DEBUG("Fetching BIB params");

    size_t param_index;
    for (param_index = 0; param_index < BSL_SecOper_GetParamLen(sec_oper); param_index++)
    {
        const BSL_SecParam_t *param = BSL_SecOper_GetParamAt(sec_oper, param_index);
        BSL_LOG_INFO("SEC PARAM: %lu", param->param_id);
        bool     is_int  = BSL_SecParam_IsInt64(param);
        uint64_t int_val = -1;
        if (is_int)
        {
            int_val = BSL_SecParam_GetAsUInt64(param);
        }

        if (param->param_id == BSL_SECPARAM_TYPE_INT_KEY_ID)
        {
            assert(is_int);
            bib_context->key_id = int_val;
        }
        else if (param->param_id == BSL_SECPARAM_TYPE_INT_FIXED_KEY)
        {
            assert(0);
            assert(!is_int);
            BSL_Data_t d = BSLX_Bytestr_AsData(&bib_context->override_key);
            BSL_SecParam_GetAsBytestr(param, &d);
            bib_context->override_key.bytelen = d.len;
        }
        else if (param->param_id == RFC9173_BIB_PARAMID_SHA_VARIANT)
        {
            assert(is_int);
            bib_context->sha_variant = int_val;
        }
        else if (param->param_id == RFC9173_BIB_PARAMID_INTEG_SCOPE_FLAG)
        {
            assert(is_int);
            bib_context->integrity_scope_flags = int_val;
        }
        else if (param->param_id == RFC9173_BIB_PARAMID_WRAPPED_KEY)
        {
            assert(!is_int);
            BSL_Data_t d = BSLX_Bytestr_AsData(&bib_context->wrapped_key);
            BSL_SecParam_GetAsBytestr(param, &d);
            bib_context->wrapped_key.bytelen = d.len;
        }
        else
        {
            BSL_LOG_WARNING("Unknown param id: %lu", param->param_id);
            return -BSLX_SECCTXERR_ERR_DATA_INTEGRITY;
        }
    }

    if (bib_context->sha_variant < 0)
    {
        // Default is SHA384: https://www.rfc-editor.org/rfc/rfc9173.html#name-block-integrity-block
        BSL_LOG_DEBUG("No SHA Variant set, defaulting to SHA_HMAC384");
        bib_context->sha_variant = RFC9173_BIB_SHA_HMAC384;
    }
    bib_context->sha_variant = map_rfc9173_sha_variant_to_crypto(bib_context->sha_variant);
    if (bib_context->sha_variant < 0)
    {
        BSL_LOG_WARNING("BIB SHA varient required.");
        return -BSLX_SECCTXERR_ERR_DATA_INTEGRITY;
    }
    if (bib_context->integrity_scope_flags < 0)
    {
        // If none given, assume they must all be true per spec.
        BSL_LOG_DEBUG("No scope flag set, defaulting to everything (0x07)");
        bib_context->integrity_scope_flags = 0x07;
    }

    BSL_LOG_DEBUG("BIB: Key ID       = %lu", bib_context->key_id);
    BSL_LOG_DEBUG("BIB: SHA Variant  = %lu", bib_context->sha_variant);
    BSL_LOG_DEBUG("BIB: Scope Flags  = %lu", bib_context->integrity_scope_flags);
    BSL_LOG_DEBUG("BIB: Target Block = %lu", bib_context->target_block.blk_num);
    BSL_LOG_DEBUG("BIB: Sec Block    = %lu", bib_context->sec_block.blk_num);
    return BSLX_SECCTXERR_ERR_NONE;
}

/**
 * Computes the Integrity-Protected Plaintext (IPPT) for a canonical bundle block (non-primary)
 */
// int BSLX_BIBContext_GenIPPT(BSL_Data_t result_ippt_buf, const BSL_BundleCtx_t *bundle, BSLX_BlockMetadata_t
// target_blk_meta, size_t target_blk_num, bib_params_t bib_params)
int BSLX_BIBContext_GenIPPT(BSLX_BIBContext_t *bib_context, BSL_Data_t ippt_space)
{
    assert(bib_context != NULL);
    assert(ippt_space.len > 0);
    assert(ippt_space.ptr != NULL);
    struct timespec time_start = BSL_Util_StartTimer();

    int                res = -BSLX_SECCTXERR_ERR_MISC;
    QCBOREncodeContext encoder;
    QCBORError         cbor_err  = QCBOR_ERR_UNSUPPORTED;
    UsefulBuf          result_ub = { .ptr = ippt_space.ptr, ippt_space.len };
    QCBOREncode_Init(&encoder, result_ub);
    QCBOREncode_AddInt64(&encoder, bib_context->integrity_scope_flags);

    // Now begin process of computing IPPT
    if (bib_context->integrity_scope_flags & RFC9173_BIB_INTEGSCOPEFLAG_INC_PRIM)
    {
        // NOT IMPLEMENTED
        BSL_LOG_ERR("BIB primary block fields in IPPT not yet implemented");
        res = -BSLX_SECCTXERR_ERR_UNIMPLEMENTED;
        goto error;
    }
    if (bib_context->integrity_scope_flags & RFC9173_BIB_INTEGSCOPEFLAG_INC_TARGET_HDR)
    {
        // NOT IMPLEMENTED
        BSL_LOG_ERR("BIB target header block fields in IPPT not yet implemented");
        res = -BSLX_SECCTXERR_ERR_UNIMPLEMENTED;
        goto error;
    }
    if (bib_context->integrity_scope_flags & RFC9173_BIB_INTEGSCOPEFLAG_INC_SEC_HDR)
    {
        // NOT IMPLEMENTED
        BSL_LOG_ERR("BIB security header block fields in IPPT not yet implemented");
        res = -BSLX_SECCTXERR_ERR_UNIMPLEMENTED;
        goto error;
    }

    UsefulBufC target_blk_btsd = { .ptr = bib_context->target_block.btsd.ptr,
                                   .len = bib_context->target_block.btsd.len };
    QCBOREncode_AddBytes(&encoder, target_blk_btsd);
    UsefulBufC ippt_result;
    cbor_err = QCBOREncode_Finish(&encoder, &ippt_result);
    if (cbor_err != QCBOR_SUCCESS)
    {
        BSL_LOG_ERR("CBOR encoding IPPT failed, code=%" PRIu32 " (%s)", cbor_err, qcbor_err_to_str(cbor_err));
        res = -BSLX_SECCTXERR_ERR_CBOR_ENCODING;
        goto error;
    }
    BSL_LOG_DEBUG("%s pass %lu millisec", __func__, BSL_Util_GetTimerElapsedMicros(time_start) / 1000);
    return (int)(ippt_result.len);

error:;
    BSL_LOG_ERR("%s fail %lu millisec", __func__, BSL_Util_GetTimerElapsedMicros(time_start) / 1000);
    return res;
}

/**
 * Performs the actual HMAC over the given IPPT, placing the result in `hmac_result`.
 * Returns the number of bytes written into hmac_result.
 * Negative indicates error.
 * NOTE: This does NOT resize the result, the caller must do so.
 */
int BSLX_BIBContext_GenHMAC(BSLX_BIBContext_t *bib_context, BSL_Data_t ippt_data)
{
    assert(bib_context != NULL);

    int                 res;
    BSL_CryptoHMACCtx_t hmac_ctx;
    struct timespec     hmac_start = BSL_Util_StartTimer();
    uint8_t             debugstr[200];

    // FIXME, we need to query the policy provider to give the key fo rthis.
    BSL_LOG_DEBUG("SHA VARIANT = %ld", bib_context->sha_variant);
    if ((res = BSL_CryptoHMACCtx_Init(&hmac_ctx, bib_context->key_id, bib_context->sha_variant)) != 0)
    {
        BSL_LOG_ERR("bsl_hmac_ctx_init failed with code %d", res);
        res = -BSLX_SECCTXERR_ERR_HMAC_GEN;
        goto error;
    }
    BSL_LOG_DEBUG("Consuming IPPT (len=%lu): %s", ippt_data.len,
                  BSL_Log_DumpAsHexString(debugstr, sizeof(debugstr), ippt_data.ptr, ippt_data.len));
    if ((res = BSL_CryptoHMACCtx_DigestBuffer(&hmac_ctx, ippt_data.ptr, ippt_data.len)) != 0)
    {
        BSL_LOG_ERR("bsl_hmac_ctx_input_data_buffer failed with code %d", res);
        res = -BSLX_SECCTXERR_ERR_HMAC_GEN;
        goto error;
    }

    void  *hmac_result_ptr = (void *)&bib_context->hmac_result_val._bytes[0];
    size_t hmaclen;
    if ((res = BSL_CryptoHMACCtx_Finalize(&hmac_ctx, &hmac_result_ptr, &hmaclen)) != 0)
    {
        BSL_LOG_ERR("bsl_hmac_ctx_finalize failed with code %d", res);
        res = -BSLX_SECCTXERR_ERR_HMAC_GEN;
        goto error;
    }
    bib_context->hmac_result_val.bytelen = hmaclen;
    BSL_LOG_DEBUG("HMAC digest (%lu bytes): %s", hmaclen,
                  BSL_Log_DumpAsHexString(debugstr, sizeof(debugstr), bib_context->hmac_result_val._bytes,
                                          bib_context->hmac_result_val.bytelen));

    if ((res = BSL_CryptoHMACCtx_Deinit(&hmac_ctx)) != 0)
    {
        BSL_LOG_ERR("bsl_hmac_ctx_deinit failed with code %d", res);
        res = -BSLX_SECCTXERR_ERR_HMAC_GEN;
        goto error;
    }
    BSL_LOG_DEBUG("%s PASS %lu millisec", __func__, BSL_Util_GetTimerElapsedMicros(hmac_start) / 1000);
    assert(hmaclen > 0);
    return hmaclen;

error:
    BSL_CryptoHMACCtx_Deinit(&hmac_ctx);
    BSL_LOG_DEBUG("%s FAIL %lu millisec", __func__, BSL_Util_GetTimerElapsedMicros(hmac_start) / 1000);
    BSL_LOG_ERR("%s failed bsl_crypto code=%ld", __func__, res);
    return -BSLX_SECCTXERR_ERR_HMAC_GEN;
}

int BSLX_ExecuteBIB(BSL_LibCtx_t *lib, const BSL_BundleCtx_t *bundle, const BSL_SecOper_t *sec_oper,
                    BSL_SecOutcome_t *sec_outcome)
{
    assert(lib != NULL);
    assert(bundle != NULL);
    assert(sec_oper != 0);

    BSLX_ScratchSpace_t scratch;
    scratch.buffer   = sec_outcome->allocation.ptr;
    scratch.size     = sec_outcome->allocation.len;
    scratch.position = 1;

    BSL_Data_t ippt_space = { .ptr = BSLX_ScratchSpace_take(&scratch, 5000), .len = 5000 };

    BSLX_BIBContext_t bib_context;
    BSLX_BIBContext_InitFromSecOper(&bib_context, sec_oper);
    int r = get_target_block_metadata(&(bib_context.target_block), bundle, sec_oper->target_block_num);
    assert(r == 0);
    int ippt_len = BSLX_BIBContext_GenIPPT(&bib_context, ippt_space);
    if (ippt_len <= 0)
    {
        BSL_LOG_ERR("GenIPPT returned %d", ippt_len);
        return -99;
    }
    assert(ippt_len > 0);
    ippt_space.len = (size_t)ippt_len;

    int hmac_status = BSLX_BIBContext_GenHMAC(&bib_context, ippt_space);
    assert(hmac_status > 0);

    // This gets all the parameters that need to be placed in the output
    size_t index;
    for (index = 0; index < BSL_SecOper_GetParamLen(sec_oper); index++)
    {
        const BSL_SecParam_t *sec_param = BSL_SecOper_GetParamAt(sec_oper, index);
        if (BSL_SecParam_IsParamIDOutput(sec_param->param_id))
        {
            BSL_SecParam_t *dst_param = BSLX_ScratchSpace_take(&scratch, sizeof(*dst_param));
            memcpy(dst_param, sec_param, sizeof(*dst_param));
            BSL_SecOutcome_AppendParam(sec_outcome, dst_param);
        }
    }

    BSL_SecResult_t *bib_result = BSLX_ScratchSpace_take(&scratch, sizeof(*bib_result));
    BSL_SecResult_Init(bib_result, RFC9173_BIB_RESULTID_HMAC, RFC9173_CONTEXTID_BIB_HMAC_SHA2,
                       sec_oper->target_block_num, BSLX_Bytestr_AsData(&bib_context.hmac_result_val));
    BSL_SecOutcome_AppendResult(sec_outcome, bib_result);

    sec_outcome->is_success = true;
    return 0;
}
