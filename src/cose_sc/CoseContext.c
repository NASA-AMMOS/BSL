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
 * @ingroup cose_sc
 * Implementation of the COSE context @cite draft-ietf-dtn-bpsec-cose.
 */
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include <m-bptree.h>

#include <BPSecLib_Private.h>
#include <CryptoInterface.h>
#include <backend/CBOR.h>

#include "CoseContext.h"
#include "CoseContext_Private.h"
#include "CoseMsg.h"

typedef struct
{
    /// Bundle context associated with this operation
    const BSL_BundleRef_t *bundle;
    /// Security source cache
    BSL_HostEID_t sec_src_eid;

    /// True if this operation is the source role
    bool is_source;
    /// Execution return value for procedure interruption
    int retval;

    /// True if #aad_scope came from an option
    bool opt_aad_scope;
    /// Required AAD scope, naturally sorted
    BSLX_CoseSc_AadScope_t aad_scope;

    /// True if #tgt_alg came from an option
    bool opt_tgt_alg;
    /// Required content algorithm
    int64_t tgt_alg;

    /// Required option for KID
    const BSL_IdValPair_t *kid;

    /// Metadata for primary block
    BSL_PrimaryBlock_t primary_block;
    /// Parent security block number
    uint64_t sec_blk_num;
    /// Metadata for target block
    BSL_CanonicalBlock_t target_block;

    /// Top-layer key to use
    void *keyhandle;

    /// MAC processing state, may be NULL
    BSL_AuthCtx_t *mac_ctx;
    /// Reading state for target BTSD
    BSL_SeqReader_t *target_read;

} BSLX_CoseSc_t;

static void BSLX_CoseSc_Init(BSLX_CoseSc_t *self)
{
    ASSERT_ARG_NONNULL(self);
    memset(self, 0, sizeof(*self));

    BSL_HostEID_Init(&self->sec_src_eid);
    BSLX_CoseSc_AadScope_init(self->aad_scope);
    self->mac_ctx = NULL;
    BSL_PrimaryBlock_init(&self->primary_block);
    self->retval = BSL_SUCCESS;
}

static void BSLX_CoseSc_Deinit(BSLX_CoseSc_t *self)
{
    ASSERT_ARG_NONNULL(self);

    if (self->target_read)
    {
        BSL_SeqReader_Destroy(self->target_read);
    }
    if (self->mac_ctx)
    {
        BSL_AuthCtx_Deinit(self->mac_ctx);
        BSL_free(self->mac_ctx);
    }

    BSL_PrimaryBlock_deinit(&self->primary_block);
    BSLX_CoseSc_AadScope_clear(self->aad_scope);
    BSL_HostEID_Deinit(&self->sec_src_eid);

    memset(self, 0, sizeof(*self));
}

static void BSLX_CoseSc_Prepare(BSLX_CoseSc_t *self, const BSL_BundleRef_t *bundle, const BSL_SecOper_t *sec_oper)
{
    self->bundle    = bundle;
    self->is_source = BSL_SecOper_IsRoleSource(sec_oper);

    // external data
    int res = BSL_Host_GetSecSrcEID(&self->sec_src_eid);
    if (BSL_SUCCESS != res)
    {
        BSL_LOG_ERR("Failed to get host EID");
        self->retval = res;
        return;
    }

    res = BSL_BundleCtx_GetBundleMetadata(bundle, &self->primary_block);
    if (BSL_SUCCESS != res)
    {
        BSL_LOG_ERR("Failed to get primary block data");
        self->retval = res;
        return;
    }

    self->sec_blk_num = BSL_SecOper_GetSecurityBlockNum(sec_oper);

    res = BSL_BundleCtx_GetBlockMetadata(bundle, BSL_SecOper_GetTargetBlockNum(sec_oper), &self->target_block);
    if (BSL_SUCCESS != res)
    {
        BSL_LOG_ERR("Failed to get target block data");
        self->retval = res;
        return;
    }

    BSL_LOG_DEBUG("operating on target block %" PRIu64, self->target_block.block_num);
}

static void BSLX_CoseSc_GetOptions(BSLX_CoseSc_t *self, const BSL_SecOper_t *sec_oper)
{
    const BSL_IdValPair_t *opt;

    opt = BSL_SecOper_FindOption(sec_oper, BSLX_COSESC_OPTION_KEYID);
    if (opt)
    {
        if (BSL_SUCCESS != BSL_IdValPair_GetAsBytestr(opt, NULL))
        {
            BSL_LOG_ERR("Invalid key ID value");
            self->retval = BSL_ERR_SECURITY_CONTEXT_FAILED;
        }
        else
        {
            self->kid = opt;
            if (BSL_SUCCESS != BSL_Crypto_GetRegistryKey("ExampleA.1", &self->keyhandle))
            {
                BSL_LOG_ERR("Unknown key ID");
                self->retval = BSL_ERR_SECURITY_CONTEXT_FAILED;
            }
        }
    }

    opt = BSL_SecOper_FindOption(sec_oper, BSLX_COSESC_OPTION_TGT_ALG);
    if (opt)
    {
        if (BSL_SUCCESS != BSL_IdValPair_GetAsInt64(opt, &self->tgt_alg))
        {
            BSL_LOG_ERR("Invalid target algorithm value");
            self->retval = BSL_ERR_SECURITY_CONTEXT_FAILED;
        }
        else
        {
            self->opt_tgt_alg = true;
        }
    }

    opt = BSL_SecOper_FindOption(sec_oper, BSLX_COSESC_OPTION_AAD_SCOPE);
    if (opt)
    {
        // FIXME real value
        if (BSL_SUCCESS != BSL_IdValPair_GetAsInt64(opt, NULL))
        {
            BSL_LOG_ERR("Invalid target algorithm value");
            self->retval = BSL_ERR_SECURITY_CONTEXT_FAILED;
        }
        else
        {
            BSLX_CoseSc_AadScope_reset(self->aad_scope);
            BSLX_CoseSc_AadScope_set_at(self->aad_scope, 0, 0x1);
            BSLX_CoseSc_AadScope_set_at(self->aad_scope, -1, 0x1);
            self->opt_aad_scope = true;
        }
    }
}

bool BSLX_CoseSc_Validate(BSL_LibCtx_t *lib, BSL_BundleRef_t *bundle, BSL_SecOper_t *sec_oper)
{
    (void)lib;
    (void)bundle;
    (void)sec_oper;
    return true;
}

static int BSLX_CoseSc_ExternalAad_Encode(QCBOREncodeContext *enc, const BSLX_CoseSc_t *ctx)
{
    int res;

    { // source-eid
        BSL_Data_t eid_data;
        BSL_Data_Init(&eid_data);
        int encode_result = BSL_HostEID_EncodeToCBOR(&ctx->sec_src_eid, &eid_data, NULL);
        if (encode_result != BSL_SUCCESS)
        {
            BSL_LOG_ERR("Failed to encode EID");
            BSL_Data_Deinit(&eid_data);
            return BSL_ERR_ENCODING;
        }
        QCBOREncode_AddEncoded(enc, UsefulBufC_FROM_BSL_Data(eid_data));
        BSL_Data_Deinit(&eid_data);
    }
    {
        // aad-scope map
        QCBOREncode_OpenMap(enc);

        BSLX_CoseSc_AadScope_it_t aads_it;
        for (BSLX_CoseSc_AadScope_it(aads_it, ctx->aad_scope); !BSLX_CoseSc_AadScope_end_p(aads_it);
             BSLX_CoseSc_AadScope_next(aads_it))
        {
            const BSLX_CoseSc_AadScope_subtype_ct *aads_pair = BSLX_CoseSc_AadScope_cref(aads_it);
            QCBOREncode_AddInt64(enc, *(aads_pair->key_ptr));
            QCBOREncode_AddInt64(enc, *(aads_pair->value_ptr));
        }

        QCBOREncode_CloseMap(enc);
    }

    BSLX_CoseSc_AadScope_it_t aads_it;
    for (BSLX_CoseSc_AadScope_it(aads_it, ctx->aad_scope); !BSLX_CoseSc_AadScope_end_p(aads_it);
         BSLX_CoseSc_AadScope_next(aads_it))
    {
        const BSLX_CoseSc_AadScope_subtype_ct *aads_pair = BSLX_CoseSc_AadScope_cref(aads_it);

        const int64_t blk_num = *(aads_pair->key_ptr);
        const int64_t aad_flags = *(aads_pair->value_ptr);

        // copy buffer
        BSL_CanonicalBlock_t aad_block;
        // true if aad_block is preset
        bool special_key = false;
        if (blk_num < 0)
        {
            special_key = true;
            // special key conversion
            switch (blk_num)
            {
                case -1:
                    aad_block = ctx->target_block;
                    break;
                case -2:
                    res = BSL_BundleCtx_GetBlockMetadata(ctx->bundle, ctx->sec_blk_num, &aad_block);
                    if (BSL_SUCCESS != res)
                    {
                        BSL_LOG_ERR("Failed to get AAD block data");
                        return res;
                    }
                    break;
                default:
                    BSL_LOG_ERR("Unhandled AAD Scope special key %" PRId64, blk_num);
                    return BSL_ERR_ENCODING;
            }
        }

        if (blk_num == 0)
        {
            // primary block
            if (aad_flags & BSLX_COSESC_AAD_FLAG_METADATA)
            {
                QCBOREncode_AddEncoded(enc, UsefulBufC_FROM_BSL_Data(*(ctx->primary_block.encoded)));
            }
            else
            {
                BSL_LOG_WARNING("AAD Scope flags ignored for primary block: 0x%"PRIx64, aad_flags);
            }
        }
        else
        {
            // canonical block
            if (!special_key)
            {
                res = BSL_BundleCtx_GetBlockMetadata(ctx->bundle, blk_num, &aad_block);
                if (BSL_SUCCESS != res)
                {
                    BSL_LOG_ERR("Failed to get AAD block data");
                    return res;
                }
            }

            if (aad_flags & BSLX_COSESC_AAD_FLAG_METADATA)
            {
                QCBOREncode_AddUInt64(enc, aad_block.type_code);
                QCBOREncode_AddUInt64(enc, aad_block.block_num);
                QCBOREncode_AddUInt64(enc, aad_block.flags);
            }
            if (aad_flags & BSLX_COSESC_AAD_FLAG_BTSD)
            {
                // TODO convert to sequential
                QCBOREncode_AddBytes(enc, UsefulBufC_FROM_BSL_Data(*(ctx->primary_block.encoded)));
            }
        }
    }

    // additional_protected
    // FIXME take input
    QCBOREncode_AddBytes(enc, (UsefulBufC) { .ptr = NULL, .len = 0 });

    return BSL_SUCCESS;
}

int BSLX_CoseSc_Execute(BSL_LibCtx_t *lib _U_, BSL_BundleRef_t *bundle, const BSL_SecOper_t *sec_oper,
                        BSL_SecOutcome_t *sec_outcome)
{
    BSLX_CoseSc_t ctx;
    BSLX_CoseSc_Init(&ctx);
    BSLX_CoseSc_Prepare(&ctx, bundle, sec_oper);

    if (BSL_SUCCESS == ctx.retval)
    {
        BSLX_CoseSc_GetOptions(&ctx, sec_oper);
    }

    // add results
    if (BSL_SUCCESS == ctx.retval)
    {
        if (ctx.is_source)
        {
            BSLX_CoseMsg_Mac0_t msg;
            BSLX_CoseMsg_Mac0_Init(&msg);
            {
                BSLB_IdValPairPtr_t *param_ptr = BSLB_IdValPairPtr_new();
                BSL_IdValPair_t     *param     = BSLB_IdValPairPtr_ref(param_ptr);

                BSL_IdValPair_SetInt64(param, BSLX_COSEMSG_HDR_ALG, ctx.tgt_alg);

                BSLX_CoseMsg_HdrMapTree_set_at(msg.phdr, param->id, param_ptr);
                BSLB_IdValPairPtr_release(param_ptr);
            }
            if (ctx.kid)
            {
                BSLB_IdValPairPtr_t *param_ptr = BSLB_IdValPairPtr_new();
                BSL_IdValPair_t     *param     = BSLB_IdValPairPtr_ref(param_ptr);

                BSL_IdValPair_Set(param, ctx.kid);
                param->id = BSLX_COSEMSG_HDR_KID;

                BSLX_CoseMsg_HdrMapTree_set_at(msg.uhdr, param->id, param_ptr);
                BSLB_IdValPairPtr_release(param_ptr);
            }

            // payload is streamed in
            ctx.target_read = BSL_BundleCtx_ReadBTSD(ctx.bundle, ctx.target_block.block_num);
            if (!ctx.target_read)
            {
                BSL_LOG_ERR("Failed to construct reader");
                return BSL_ERR_HOST_CALLBACK_FAILED;
            }

            BSLX_CoseMsg_Mac0_DerivePhdr(&msg);

            ctx.mac_ctx = BSL_malloc(sizeof(BSL_AuthCtx_t));
            if (BSL_SUCCESS != BSL_AuthCtx_Init(ctx.mac_ctx, ctx.keyhandle, BSL_CRYPTO_SHA_384)) // FIXME from config
            {
                BSL_LOG_ERR("Failed to construct MAC context");
                return BSL_ERR_HOST_CALLBACK_FAILED;
            }

            BSL_Data_t external_aad;
            BSL_Data_Init(&external_aad);
            BSL_LOG_DEBUG("Encoding external AAD");
            int res = BSL_CBOR_Encode_Twopass(&external_aad, (BSL_CBOR_Encode_f)&BSLX_CoseSc_ExternalAad_Encode, &ctx);
            if (BSL_SUCCESS != res)
            {
                BSL_LOG_ERR("Failed to encode external AAD");
                ctx.retval = res;
                return ctx.retval;
            }

            BSLX_CoseMsg_Mac_Structure_t mac_struct = {
                .context      = "MAC0",
                .phdr_bstr    = &msg.phdr_bstr,
                .external_aad = &external_aad,
                .payload_len  = ctx.target_block.btsd_len,
            };

            BSL_Data_t structure_enc;
            BSL_Data_Init(&structure_enc);
            BSL_LOG_DEBUG("Encoding MAC_Structure");
            res = BSL_CBOR_Encode_Twopass(&structure_enc, (BSL_CBOR_Encode_f)&BSLX_CoseMsg_Mac_Structure_Encode,
                                          &mac_struct);
            if (BSL_SUCCESS != res)
            {
                BSL_LOG_ERR("Failed to encode Mac_Structure");
                ctx.retval = res;
                return ctx.retval;
            }
            BSL_Data_Deinit(&external_aad);

            res = BSL_AuthCtx_DigestBuffer(ctx.mac_ctx, structure_enc.ptr, structure_enc.len);
            res = BSL_AuthCtx_DigestSeq(ctx.mac_ctx, ctx.target_read);

            BSL_Data_Deinit(&structure_enc);

            if (BSL_SUCCESS != (res = BSL_AuthCtx_Finalize(ctx.mac_ctx, &msg.tag)))
            {
                BSL_LOG_ERR("BSL_AuthCtx_Finalize failed with code %d", res);
                ctx.retval = res;
            }

            BSL_Data_t msg_enc;
            BSL_Data_Init(&msg_enc);
            res = BSL_CBOR_Encode_Twopass(&msg_enc, (BSL_CBOR_Encode_f)&BSLX_CoseMsg_Mac0_Encode, &msg);
            if (BSL_SUCCESS != res)
            {
                BSL_LOG_ERR("Failed to encode Mac0");
                ctx.retval = res;
            }
            else
            {
                BSL_IdValPair_t *result = BSL_SecOutcome_AppendResult(sec_outcome);
                BSL_IdValPair_SetBytestr(result, BSLX_COSESC_RESULT_COSE_MAC0, msg_enc);
            }
            BSL_Data_Deinit(&msg_enc);
            BSLX_CoseMsg_Mac0_Deinit(&msg);
        }
        else
        {
            // TODO fill out
        }
    }

    int ret = ctx.retval;
    BSLX_CoseSc_Deinit(&ctx);
    return ret;
}
