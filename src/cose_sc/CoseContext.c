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

#include <m-bstring.h>
#include <m-variant.h>
#include <m-deque.h>
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
    /// Operation source
    const BSL_SecOper_t *sec_oper;
    /// Operation outcome
    BSL_SecOutcome_t *sec_outcome;
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
    /// Required content layer algorithm
    int64_t tgt_alg;

    /// True if #recip_alg came from an option
    bool opt_recip_alg;
    /// Optional recipient layer algorithm
    int64_t recip_alg;

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

static void BSLX_CoseSc_Prepare(BSLX_CoseSc_t *self, const BSL_BundleRef_t *bundle, const BSL_SecOper_t *sec_oper,
                                BSL_SecOutcome_t *sec_outcome)
{
    self->bundle      = bundle;
    self->sec_oper    = sec_oper;
    self->sec_outcome = sec_outcome;
    self->is_source   = BSL_SecOper_IsRoleSource(sec_oper);

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
        BSL_Data_t kid;
        BSL_Data_Init(&kid);
        if (BSL_SUCCESS != BSL_IdValPair_GetAsBytestr(opt, &kid))
        {
            BSL_LOG_ERR("Invalid key ID value");
            self->retval = BSL_ERR_SECURITY_CONTEXT_FAILED;
        }
        else
        {
            self->kid = opt;

            // FIXME treat as null-terminated text for lookup
            BSL_Data_AppendFrom(&kid, 1, (BSL_DataConstPtr_t) "\0");
            if (BSL_SUCCESS != BSL_Crypto_GetRegistryKey((const char *)kid.ptr, &self->keyhandle))
            {
                BSL_LOG_ERR("Unknown key ID");
                self->retval = BSL_ERR_SECURITY_CONTEXT_FAILED;
            }
        }
        BSL_Data_Deinit(&kid);
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

    opt = BSL_SecOper_FindOption(sec_oper, BSLX_COSESC_OPTION_RECIP_ALG);
    if (opt)
    {
        if (BSL_SUCCESS != BSL_IdValPair_GetAsInt64(opt, &self->recip_alg))
        {
            BSL_LOG_ERR("Invalid target algorithm value");
            self->retval = BSL_ERR_SECURITY_CONTEXT_FAILED;
        }
        else
        {
            self->opt_recip_alg = true;
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

bool BSLX_CoseSc_Validate(BSL_LibCtx_t *lib _U_, BSL_BundleRef_t *bundle _U_, BSL_SecOper_t *sec_oper)
{
    BSLX_CoseSc_t ctx;
    BSLX_CoseSc_Init(&ctx);
    BSLX_CoseSc_Prepare(&ctx, bundle, sec_oper, NULL);

    if (BSL_SUCCESS == ctx.retval)
    {
        BSLX_CoseSc_GetOptions(&ctx, sec_oper);
    }

    bool valid = (ctx.retval == BSL_SUCCESS);
    BSLX_CoseSc_Deinit(&ctx);
    return valid;
}

static int BSLX_CoseSc_AadScope_Encode(QCBOREncodeContext *enc, const BSLX_CoseSc_AadScope_t *scope)
{
    // aad-scope map
    QCBOREncode_OpenMap(enc);

    BSLX_CoseSc_AadScope_it_t aads_it;
    for (BSLX_CoseSc_AadScope_it(aads_it, *scope); !BSLX_CoseSc_AadScope_end_p(aads_it);
         BSLX_CoseSc_AadScope_next(aads_it))
    {
        const BSLX_CoseSc_AadScope_subtype_ct *aads_pair = BSLX_CoseSc_AadScope_cref(aads_it);
        QCBOREncode_AddInt64(enc, *(aads_pair->key_ptr));
        QCBOREncode_AddInt64(enc, *(aads_pair->value_ptr));
    }

    QCBOREncode_CloseMap(enc);
    return BSL_SUCCESS;
}

/** @struct BSLX_CoseSc_ChunkItem_t
 * A variant which can be either:
 *  - @c data An instance of @c m_bstring_t
 *  - @c seq An POD instance of ::BSL_SeqReader_s
 */
/** @struct BSLX_CoseSc_ChunkList_t
 * A list of ::BSLX_CoseSc_ChunkItem_t for MAC and AAD processing.
 */
/// @cond Doxygen_Suppress
// GCOV_EXCL_START
M_VARIANT_DEF2(BSLX_CoseSc_ChunkItem, (data, m_bstring_t, M_BSTRING_OPLIST), (seq, BSL_SeqReader_t *, M_PTR_OPLIST))
#define M_OPL_BSLX_CoseSc_ChunkItem_t() M_VARIANT_OPLIST(BSLX_CoseSc_ChunkItem, M_BSTRING_OPLIST, M_PTR_OPLIST)

M_DEQUE_DEF(BSLX_CoseSc_ChunkList, BSLX_CoseSc_ChunkItem_t)
// GCOV_EXCL_STOP
/// @endcond

/** Append a CBOR head only.
 */
static size_t BSLX_CoseSc_bstring_AppendHead(m_bstring_t data, uint8_t major, uint64_t argument)
{
    // Largest possible COSE head
    uint8_t head_buffer[QCBOR_HEAD_BUFFER_SIZE];

    UsefulBufC head_used = QCBOREncode_EncodeHead(UsefulBuf_FROM_BYTE_ARRAY(head_buffer), major, 0, argument);

    m_bstring_push_back_bytes(data, head_used.len, head_used.ptr);
    return head_used.len;
}

/** Append raw CBOR encoded data.
 */
static size_t BSLX_CoseSc_bstring_AppendRaw(m_bstring_t data, const BSL_Data_t *chunk)
{
    m_bstring_push_back_bytes(data, chunk->len, chunk->ptr);
    return chunk->len;
}

/** Handle the external AAD content as appending to a list of chunks.
 *
 * @param[in] ctx The context to read from.
 * @param[in,out] chunklist The list to append to.
 * @param[in,out] total The total size accumulator to add to.
 */
static int BSLX_CoseSc_ExternalAad_Chunked(const BSLX_CoseSc_t *ctx, BSLX_CoseSc_ChunkList_t chunklist, size_t *total)
{
    ASSERT_ARG_NONNULL(ctx);
    ASSERT_ARG_NONNULL(chunklist);
    ASSERT_ARG_NONNULL(total);
    int res;

    *total = 0;
    { // small encoded top
        BSLX_CoseSc_ChunkItem_t *item = BSLX_CoseSc_ChunkList_push_back_new(chunklist);
        BSLX_CoseSc_ChunkItem_init_data(*item);
        m_bstring_t *data = BSLX_CoseSc_ChunkItem_get_data(*item);

        BSL_Data_t chunk;
        BSL_Data_Init(&chunk);

        // source-eid
        res = BSL_HostEID_EncodeToCBOR(&ctx->sec_src_eid, &chunk, NULL);
        if (res != BSL_SUCCESS)
        {
            BSL_LOG_ERR("Failed to encode Security Source");
            BSL_Data_Deinit(&chunk);
            return BSL_ERR_ENCODING;
        }
        *total += BSLX_CoseSc_bstring_AppendRaw(*data, &chunk);

        // aad-scope canonicalized
        res = BSL_CBOR_Encode_Twopass(&chunk, (BSL_CBOR_Encode_f)&BSLX_CoseSc_AadScope_Encode, &ctx->aad_scope);
        if (BSL_SUCCESS != res)
        {
            BSL_LOG_ERR("Failed to encode AAD Scope");
            BSL_Data_Deinit(&chunk);
            return BSL_ERR_ENCODING;
        }
        *total += BSLX_CoseSc_bstring_AppendRaw(*data, &chunk);

        BSL_Data_Deinit(&chunk);
    }

    BSLX_CoseSc_AadScope_it_t aads_it;
    for (BSLX_CoseSc_AadScope_it(aads_it, ctx->aad_scope); !BSLX_CoseSc_AadScope_end_p(aads_it);
         BSLX_CoseSc_AadScope_next(aads_it))
    {
        const BSLX_CoseSc_AadScope_subtype_ct *aads_pair = BSLX_CoseSc_AadScope_cref(aads_it);

        const int64_t blk_num   = *(aads_pair->key_ptr);
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
                BSLX_CoseSc_ChunkItem_t *item = BSLX_CoseSc_ChunkList_push_back_new(chunklist);
                BSLX_CoseSc_ChunkItem_init_data(*item);
                m_bstring_t *data = BSLX_CoseSc_ChunkItem_get_data(*item);

                // copy of primary
                m_bstring_push_back_bytes(*data, ctx->primary_block.encoded->len, ctx->primary_block.encoded->ptr);
                *total += ctx->primary_block.encoded->len;
            }
            else
            {
                BSL_LOG_WARNING("AAD Scope flags ignored for primary block: 0x%" PRIx64, aad_flags);
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
                BSLX_CoseSc_ChunkItem_t *item = BSLX_CoseSc_ChunkList_push_back_new(chunklist);
                BSLX_CoseSc_ChunkItem_init_data(*item);
                m_bstring_t *data = BSLX_CoseSc_ChunkItem_get_data(*item);

                // three items from the canonical block header
                *total += BSLX_CoseSc_bstring_AppendHead(*data, CBOR_MAJOR_TYPE_POSITIVE_INT, aad_block.type_code);
                *total += BSLX_CoseSc_bstring_AppendHead(*data, CBOR_MAJOR_TYPE_POSITIVE_INT, aad_block.block_num);
                *total += BSLX_CoseSc_bstring_AppendHead(*data, CBOR_MAJOR_TYPE_POSITIVE_INT, aad_block.flags);
            }
            if (aad_flags & BSLX_COSESC_AAD_FLAG_BTSD)
            {
                // CBOR head and seq stream
                {
                    BSLX_CoseSc_ChunkItem_t *item = BSLX_CoseSc_ChunkList_push_back_new(chunklist);
                    BSLX_CoseSc_ChunkItem_init_data(*item);
                    m_bstring_t *data = BSLX_CoseSc_ChunkItem_get_data(*item);

                    *total += BSLX_CoseSc_bstring_AppendHead(*data, CBOR_MAJOR_TYPE_BYTE_STRING, 0);
                }
                {
                    BSLX_CoseSc_ChunkItem_t *item = BSLX_CoseSc_ChunkList_push_back_new(chunklist);
                    BSLX_CoseSc_ChunkItem_init_seq(*item);
                    BSL_SeqReader_t **seq = BSLX_CoseSc_ChunkItem_get_seq(*item);

                    *seq = BSL_BundleCtx_ReadBTSD(ctx->bundle, blk_num);
                    if (!*seq)
                    {
                        BSL_LOG_ERR("Failed to construct reader");
                        return BSL_ERR_ENCODING;
                    }
                    *total += aad_block.btsd_len;
                }
            }
        }
    }

    { // additional_protected
        BSLX_CoseSc_ChunkItem_t *item = BSLX_CoseSc_ChunkList_push_back_new(chunklist);
        BSLX_CoseSc_ChunkItem_init_data(*item);
        m_bstring_t *data = BSLX_CoseSc_ChunkItem_get_data(*item);

        // FIXME take input
        *total += BSLX_CoseSc_bstring_AppendHead(*data, CBOR_MAJOR_TYPE_BYTE_STRING, 0);
    }

    return BSL_SUCCESS;
}

/** Internal processing to source a COSE_Mac0 message.
 */
static void BSLX_CoseSc_Mac0_Source(BSLX_CoseSc_t *ctx)
{
    int res;

    BSLX_CoseMsg_Mac0_t msg;
    BSLX_CoseMsg_Mac0_Init(&msg);
    {
        BSLB_IdValPairPtr_t *param_ptr = BSLB_IdValPairPtr_new();
        BSL_IdValPair_t     *param     = BSLB_IdValPairPtr_ref(param_ptr);

        BSL_IdValPair_SetInt64(param, BSLX_COSEMSG_HDR_ALG, ctx->tgt_alg);

        BSLX_CoseMsg_HdrMapTree_set_at(msg.phdr, param->id, param_ptr);
        BSLB_IdValPairPtr_release(param_ptr);
    }
    if (ctx->kid)
    {
        BSLB_IdValPairPtr_t *param_ptr = BSLB_IdValPairPtr_new();
        BSL_IdValPair_t     *param     = BSLB_IdValPairPtr_ref(param_ptr);

        BSL_IdValPair_Set(param, ctx->kid);
        param->id = BSLX_COSEMSG_HDR_KID;

        BSLX_CoseMsg_HdrMapTree_set_at(msg.uhdr, param->id, param_ptr);
        BSLB_IdValPairPtr_release(param_ptr);
    }

    BSLX_CoseMsg_Mac0_DerivePhdr(&msg);

    if (BSL_SUCCESS == ctx->retval)
    {
        ctx->mac_ctx = BSL_malloc(sizeof(BSL_AuthCtx_t));
        if (BSL_SUCCESS != BSL_AuthCtx_Init(ctx->mac_ctx, ctx->keyhandle, BSL_CRYPTO_SHA_384)) // FIXME from config
        {
            BSL_LOG_ERR("Failed to construct MAC context");
            ctx->retval = BSL_ERR_HOST_CALLBACK_FAILED;
        }
    }

    BSLX_CoseSc_ChunkList_t chunklist;
    BSLX_CoseSc_ChunkList_init(chunklist);

    if (BSL_SUCCESS == ctx->retval)
    {
        /// CBOR array head with context "MAC0"
        static const uint8_t cose_mac0_header[] = { 0x84, 0x64, 0x4D, 0x41, 0x43, 0x30 };

        { // context and protected bytes
            BSLX_CoseSc_ChunkItem_t *item = BSLX_CoseSc_ChunkList_push_back_new(chunklist);
            BSLX_CoseSc_ChunkItem_init_data(*item);
            m_bstring_t *data = BSLX_CoseSc_ChunkItem_get_data(*item);

            m_bstring_push_back_bytes(*data, sizeof(cose_mac0_header), cose_mac0_header);

            BSLX_CoseSc_bstring_AppendHead(*data, CBOR_MAJOR_TYPE_BYTE_STRING, msg.phdr_bstr.len);
            BSLX_CoseSc_bstring_AppendRaw(*data, &msg.phdr_bstr);
        }
        { // external AAD bstr wrapped
            BSLX_CoseSc_ChunkItem_t *item = BSLX_CoseSc_ChunkList_push_back_new(chunklist);
            BSLX_CoseSc_ChunkItem_init_data(*item);
            m_bstring_t *data = BSLX_CoseSc_ChunkItem_get_data(*item);

            size_t ext_aad_len;
            res = BSLX_CoseSc_ExternalAad_Chunked(ctx, chunklist, &ext_aad_len);
            if (BSL_SUCCESS != res)
            {
                ctx->retval = res;
                // continue processing
            }

            // after external AAD size is known, inject bstr head above
            BSLX_CoseSc_bstring_AppendHead(*data, CBOR_MAJOR_TYPE_BYTE_STRING, ext_aad_len);
        }
        { // length of payload
            BSLX_CoseSc_ChunkItem_t *item = BSLX_CoseSc_ChunkList_push_back_new(chunklist);
            BSLX_CoseSc_ChunkItem_init_data(*item);
            m_bstring_t *data = BSLX_CoseSc_ChunkItem_get_data(*item);
            BSLX_CoseSc_bstring_AppendHead(*data, CBOR_MAJOR_TYPE_BYTE_STRING, ctx->target_block.btsd_len);
        }
        { // the target BTSD as payload
            BSLX_CoseSc_ChunkItem_t *item = BSLX_CoseSc_ChunkList_push_back_new(chunklist);
            BSLX_CoseSc_ChunkItem_init_seq(*item);
            BSL_SeqReader_t **seq = BSLX_CoseSc_ChunkItem_get_seq(*item);

            *seq = BSL_BundleCtx_ReadBTSD(ctx->bundle, ctx->target_block.block_num);
            if (!*seq)
            {
                BSL_LOG_ERR("Failed to construct reader");
                ctx->retval = BSL_ERR_ENCODING;
                return;
            }
        }
    }

    if (BSL_SUCCESS == ctx->retval)
    {
        BSLX_CoseSc_ChunkList_it_t chunk_it;
        for (BSLX_CoseSc_ChunkList_it(chunk_it, chunklist); !BSLX_CoseSc_ChunkList_end_p(chunk_it);
             BSLX_CoseSc_ChunkList_next(chunk_it))
        {
            const BSLX_CoseSc_ChunkItem_t *item = BSLX_CoseSc_ChunkList_cref(chunk_it);

            const m_bstring_t      *data;
            BSL_SeqReader_t *const *seq;
            if ((data = BSLX_CoseSc_ChunkItem_cget_data(*item)))
            {
                size_t         size = m_bstring_size(*data);
                const uint8_t *ptr  = m_bstring_view(*data, 0, size);

                res = BSL_AuthCtx_DigestBuffer(ctx->mac_ctx, ptr, size);
                if (BSL_SUCCESS != res)
                {
                    BSL_LOG_ERR("Failed to process MAC");
                }
            }
            else if ((seq = BSLX_CoseSc_ChunkItem_cget_seq(*item)))
            {
                res = BSL_AuthCtx_DigestSeq(ctx->mac_ctx, *seq);
                if (BSL_SUCCESS != res)
                {
                    BSL_LOG_ERR("Failed to process MAC");
                }
            }
            else
            {
                BSL_LOG_WARNING("Ignoring empty chunk");
            }
        }
    }
    { // unconditionally cleanup
        BSLX_CoseSc_ChunkList_it_t chunk_it;
        for (BSLX_CoseSc_ChunkList_it(chunk_it, chunklist); !BSLX_CoseSc_ChunkList_end_p(chunk_it);
             BSLX_CoseSc_ChunkList_next(chunk_it))
        {
            BSLX_CoseSc_ChunkItem_t *item = BSLX_CoseSc_ChunkList_ref(chunk_it);

            BSL_SeqReader_t **seq = BSLX_CoseSc_ChunkItem_get_seq(*item);
            if (seq)
            {
                BSL_SeqReader_Destroy(*seq);
                *seq = NULL;
            }
        }
    }
    BSLX_CoseSc_ChunkList_clear(chunklist);

    if (BSL_SUCCESS == ctx->retval)
    {
        if (BSL_SUCCESS != (res = BSL_AuthCtx_Finalize(ctx->mac_ctx, &msg.tag)))
        {
            BSL_LOG_ERR("BSL_AuthCtx_Finalize failed with code %d", res);
            ctx->retval = res;
        }
    }

    BSL_Data_t aad_scope_enc;
    BSL_Data_Init(&aad_scope_enc);
    if (BSL_SUCCESS == ctx->retval)
    {
        res = BSL_CBOR_Encode_Twopass(&aad_scope_enc, (BSL_CBOR_Encode_f)&BSLX_CoseSc_AadScope_Encode, &ctx->aad_scope);
        if (BSL_SUCCESS != res)
        {
            BSL_LOG_ERR("Failed to encode AAD Scope");
            ctx->retval = res;
        }
    }
    BSL_Data_t msg_enc;
    BSL_Data_Init(&msg_enc);
    if (BSL_SUCCESS == ctx->retval)
    {
        res = BSL_CBOR_Encode_Twopass(&msg_enc, (BSL_CBOR_Encode_f)&BSLX_CoseMsg_Mac0_Encode, &msg);
        if (BSL_SUCCESS != res)
        {
            BSL_LOG_ERR("Failed to encode Mac0");
            ctx->retval = res;
        }
    }
    if (BSL_SUCCESS == ctx->retval)
    {
        {
            BSL_IdValPair_t *param = BSL_SecOutcome_AppendParam(ctx->sec_outcome);
            BSL_IdValPair_SetRaw(param, BSLX_COSESC_PARAM_AAD_SCOPE, aad_scope_enc.ptr, aad_scope_enc.len);
        }
        {
            BSL_IdValPair_t *result = BSL_SecOutcome_AppendResult(ctx->sec_outcome);
            BSL_IdValPair_SetBytestr(result, BSLX_COSESC_RESULT_COSE_MAC0, msg_enc);
        }
    }
    BSL_Data_Deinit(&msg_enc);
    BSL_Data_Deinit(&aad_scope_enc);

    BSLX_CoseMsg_Mac0_Deinit(&msg);
}

int BSLX_CoseSc_Execute(BSL_LibCtx_t *lib _U_, BSL_BundleRef_t *bundle, const BSL_SecOper_t *sec_oper,
                        BSL_SecOutcome_t *sec_outcome)
{
    BSLX_CoseSc_t ctx;
    BSLX_CoseSc_Init(&ctx);
    BSLX_CoseSc_Prepare(&ctx, bundle, sec_oper, sec_outcome);

    if (BSL_SUCCESS == ctx.retval)
    {
        BSLX_CoseSc_GetOptions(&ctx, sec_oper);
    }

    // add results
    if (BSL_SUCCESS == ctx.retval)
    {
        if (ctx.is_source)
        {
            if (ctx.opt_recip_alg)
            {
                // TODO has recipient layer
            }
            else
            {
                // only one content layer
                BSLX_CoseSc_Mac0_Source(&ctx);
            }
        }
        else
        {
            // TODO verify or accept
        }
    }

    int ret = ctx.retval;
    BSLX_CoseSc_Deinit(&ctx);
    return ret;
}
