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

/// Acceptable target algorithms for MAC
static const int64_t cose_bib_cnt_algs[] = {
    5, 6, 7, // HMAC-SHA2
};
/// Acceptable target algorithms for Encrypt
static const int64_t cose_bcb_cnt_algs[] = {
    1, 2, 3, // AES-GCM
};
#if 0
/// Acceptable recipient algorithms for MAC and Encrypt
static const int64_t cose_recip_algs[] = {
    -13, -12, -11, -10, // direct+HKDF
    -5, -4, -3, // AES-KW
};
#endif

/// Matches signature for @c bsearch()
static int local_cmp_int64(const void *lhs, const void *rhs)
{
    return M_CMP_BASIC(*(const int64_t *)lhs, *(const int64_t *)rhs);
}

typedef struct
{
    /// Bundle context associated with this operation
    BSL_BundleRef_t *bundle;
    /// Operation source
    const BSL_SecOper_t *sec_oper;
    /// Operation outcome
    BSL_SecOutcome_t *sec_outcome;
    /// Security source cache
    BSL_HostEID_t sec_src_eid;

    /// True if this operation is integrity, false for confidentiality
    bool is_bib;
    /// True if this operation is the source role
    bool is_source;
    /// Rolling return value for procedure interruption
    int status;

    /// True if #kid came from an option
    bool opt_kid;
    /// Required option for KID
    BSL_Data_t kid;

    /// Optional additional header parameter bytes
    BSL_Data_t addl_phdr_bstr;
    /// Optional additional header map, represented by #addl_phdr_bstr
    BSLX_CoseMsg_HdrMapTree_t addl_phdr;
    /// Optional additional header map
    BSLX_CoseMsg_HdrMapTree_t addl_uhdr;

    /// True if #aad_scope came from an option
    bool opt_aad_scope;
    /// Required AAD scope, naturally sorted
    BSLX_CoseSc_AadScope_t aad_scope;

    /// True if #key_alg came from an option
    bool opt_key_alg;
    /// True if #key_alg came from a header
    bool hdr_key_alg;
    /// Optional key use algorithm from ::BSLX_CoseMsg_Alg_e
    int64_t key_alg;

    /// True if #tgt_alg came from an option
    bool opt_tgt_alg;
    /// True if #tgt_alg came from a header
    bool hdr_tgt_alg;
    /// Required content layer algorithm from ::BSLX_CoseMsg_Alg_e
    int64_t tgt_alg;
    /// Key length for #tgt_alg
    size_t tgt_keylen;

    /// True if #iv_offset came from an option
    bool opt_iv_offset;
    /// Optional offset to use when generating IV or Partial IV bytes
    int64_t iv_offset;
    /// Direct or derived full IV
    BSL_Data_t full_iv;
    /// Optional partial IV when key supports it
    BSL_Data_t partial_iv;

    /// Metadata for primary block
    BSL_PrimaryBlock_t primary_block;
    /// Parent security block number
    uint64_t sec_blk_num;
    /// Metadata for target block
    BSL_CanonicalBlock_t target_block;
    /// True if this is a source or acceptor role and target BTSD is replaced for encryption
    bool overwrite_btsd;

    /// Top-layer key to use
    BSL_Crypto_KeyHandle_t keyhandle;

    /// Optional content key
    BSL_Crypto_KeyHandle_t cekhandle;
    /// Optional wrapped content key
    BSL_Data_t wrapped_cek;

    /// MAC processing state, may be NULL
    BSL_AuthCtx_t *mac_ctx;

    /// Encrypt processing state, may be NULL
    BSL_Cipher_t *enc_ctx;

} BSLX_CoseSc_t;

static void BSLX_CoseSc_Init(BSLX_CoseSc_t *self)
{
    ASSERT_ARG_NONNULL(self);
    memset(self, 0, sizeof(*self));

    BSL_HostEID_Init(&self->sec_src_eid);
    BSL_Data_Init(&self->kid);
    BSLX_CoseSc_AadScope_init(self->aad_scope);
    BSL_Data_Init(&self->addl_phdr_bstr);
    BSLX_CoseMsg_HdrMapTree_init(self->addl_phdr);
    BSLX_CoseMsg_HdrMapTree_init(self->addl_uhdr);
    BSL_Data_Init(&self->full_iv);
    BSL_Data_Init(&self->partial_iv);
    self->cekhandle = NULL;
    BSL_Data_Init(&self->wrapped_cek);
    self->mac_ctx = NULL;
    self->enc_ctx = NULL;
    BSL_PrimaryBlock_Init(&self->primary_block);
    self->status = BSL_SUCCESS;
}

static void BSLX_CoseSc_Deinit(BSLX_CoseSc_t *self)
{
    ASSERT_ARG_NONNULL(self);

    if (self->mac_ctx)
    {
        BSL_AuthCtx_Deinit(self->mac_ctx);
        BSL_free(self->mac_ctx);
    }
    if (self->enc_ctx)
    {
        BSL_Cipher_Deinit(self->enc_ctx);
        BSL_free(self->enc_ctx);
    }

    BSL_PrimaryBlock_deinit(&self->primary_block);
    BSL_Data_Deinit(&self->wrapped_cek);
    if (self->cekhandle)
    {
        BSL_Crypto_ClearGeneratedKeyHandle(self->cekhandle);
    }
    BSL_Data_Deinit(&self->partial_iv);
    BSL_Data_Deinit(&self->full_iv);
    BSLX_CoseMsg_HdrMapTree_clear(self->addl_uhdr);
    BSLX_CoseMsg_HdrMapTree_clear(self->addl_phdr);
    BSL_Data_Deinit(&self->addl_phdr_bstr);
    BSLX_CoseSc_AadScope_clear(self->aad_scope);
    BSL_Data_Deinit(&self->kid);
    BSL_HostEID_Deinit(&self->sec_src_eid);

    memset(self, 0, sizeof(*self));
}

static void BSLX_CoseSc_Prepare(BSLX_CoseSc_t *self, BSL_BundleRef_t *bundle, const BSL_SecOper_t *sec_oper,
                                BSL_SecOutcome_t *sec_outcome)
{
    self->bundle         = bundle;
    self->sec_oper       = sec_oper;
    self->sec_outcome    = sec_outcome;
    self->is_bib         = BSL_SecOper_IsBIB(sec_oper);
    self->is_source      = BSL_SecOper_IsRoleSource(sec_oper);
    self->overwrite_btsd = !BSL_SecOper_IsRoleVerifier(sec_oper);

    // external data
    int res = BSL_Host_GetSecSrcEID(&self->sec_src_eid);
    // GCOV_EXCL_START
    if (BSL_SUCCESS != res)
    {
        BSL_LOG_ERR("Failed to get host EID");
        self->status = res;
        return;
    }
    // GCOV_EXCL_STOP

    res = BSL_BundleCtx_GetBundleMetadata(bundle, &self->primary_block);
    // GCOV_EXCL_START
    if (BSL_SUCCESS != res)
    {
        BSL_LOG_ERR("Failed to get primary block data");
        self->status = res;
        return;
    }
    // GCOV_EXCL_STOP

    self->sec_blk_num = BSL_SecOper_GetSecurityBlockNum(sec_oper);

    res = BSL_BundleCtx_GetBlockMetadata(bundle, BSL_SecOper_GetTargetBlockNum(sec_oper), &self->target_block);
    // GCOV_EXCL_START
    if (BSL_SUCCESS != res)
    {
        BSL_LOG_ERR("Failed to get target block data");
        self->status = res;
        return;
    }
    // GCOV_EXCL_STOP
    BSL_LOG_DEBUG("operating on target block %" PRIu64, self->target_block.block_num);
}

static void BSLX_CoseSc_GetOptions(BSLX_CoseSc_t *self, const BSL_SecOper_t *sec_oper)
{
    const BSL_IdValPair_t *opt;

    opt = BSL_SecOper_FindOption(sec_oper, BSLX_COSESC_OPTION_KEY_ID);
    if (opt)
    {
        BSL_Data_t kid_view;
        BSL_Data_Init(&kid_view);
        if (BSL_SUCCESS != BSL_IdValPair_GetAsBytestr(opt, &kid_view))
        {
            BSL_LOG_ERR("Invalid key ID value");
            self->status = BSL_ERR_SECURITY_CONTEXT_FAILED;
        }
        else
        {
            BSL_Data_CopyFrom(&self->kid, kid_view.len, kid_view.ptr);
            self->opt_kid = true;
        }
        BSL_Data_Deinit(&kid_view);
    }

    opt = BSL_SecOper_FindOption(sec_oper, BSLX_COSESC_OPTION_TGT_ALG);
    if (opt)
    {
        if (BSL_SUCCESS != BSL_IdValPair_GetAsInt64(opt, &self->tgt_alg))
        {
            BSL_LOG_ERR("Invalid target algorithm value");
            self->status = BSL_ERR_SECURITY_CONTEXT_FAILED;
        }
        else
        {
            self->opt_tgt_alg = true;
        }
    }

    opt = BSL_SecOper_FindOption(sec_oper, BSLX_COSESC_OPTION_KEY_ALG);
    if (opt)
    {
        if (BSL_SUCCESS != BSL_IdValPair_GetAsInt64(opt, &self->key_alg))
        {
            BSL_LOG_ERR("Invalid target algorithm value");
            self->status = BSL_ERR_SECURITY_CONTEXT_FAILED;
        }
        else
        {
            self->opt_key_alg = true;
        }
    }

    opt = BSL_SecOper_FindOption(sec_oper, BSLX_COSESC_OPTION_AAD_SCOPE);
    if (opt)
    {
        BSL_Data_t enc_data;
        if (BSL_SUCCESS != BSL_IdValPair_GetAsRaw(opt, &enc_data))
        {
            BSL_LOG_ERR("Invalid AAD Scope value");
            self->status = BSL_ERR_SECURITY_CONTEXT_FAILED;
        }
        else
        {
            int res = BSL_CBOR_Decode(&enc_data, (BSL_CBOR_Decode_f)&BSLX_CoseSc_AadScope_Decode, &self->aad_scope);
            if (BSL_SUCCESS != res)
            {
                BSL_LOG_ERR("Failed to decode AAD Scope");
                self->status = BSL_ERR_SECURITY_CONTEXT_FAILED;
            }
            else
            {
                self->opt_aad_scope = true;
            }
        }
    }

    opt = BSL_SecOper_FindOption(sec_oper, BSLX_COSESC_OPTION_IV_COUNTER_OFFSET);
    if (opt)
    {
        if (BSL_SUCCESS != BSL_IdValPair_GetAsInt64(opt, &self->iv_offset))
        {
            BSL_LOG_ERR("Invalid target algorithm value");
            self->status = BSL_ERR_SECURITY_CONTEXT_FAILED;
        }
        else
        {
            self->opt_iv_offset = true;
        }
    }

    // validation between options and key / param state
    if (self->is_source && !self->opt_kid)
    {
        BSL_LOG_ERR("key ID option is required");
        self->status = BSL_ERR_SECURITY_CONTEXT_FAILED;
    }

    if (self->is_source && !self->opt_tgt_alg)
    {
        BSL_LOG_ERR("COSE target alg option is required");
        self->status = BSL_ERR_SECURITY_CONTEXT_FAILED;
    }

    if (self->opt_tgt_alg)
    {
        // restrict use locally
        const uint64_t *found;
        if (self->is_bib)
        {
            found = bsearch(&self->tgt_alg, cose_bib_cnt_algs, sizeof(cose_bib_cnt_algs) / sizeof(int64_t),
                            sizeof(int64_t), &local_cmp_int64);
        }
        else
        {
            found = bsearch(&self->tgt_alg, cose_bcb_cnt_algs, sizeof(cose_bcb_cnt_algs) / sizeof(int64_t),
                            sizeof(int64_t), &local_cmp_int64);
        }
        if (!found)
        {
            BSL_LOG_ERR("COSE target alg option is unacceptable for this security service");
            self->status = BSL_ERR_SECURITY_CONTEXT_FAILED;
        }
    }
}

bool BSLX_CoseSc_Validate(BSL_LibCtx_t *lib _U_, BSL_BundleRef_t *bundle, BSL_SecOper_t *sec_oper) // NOSONAR
{
    BSLX_CoseSc_t ctx;
    BSLX_CoseSc_Init(&ctx);
    BSLX_CoseSc_Prepare(&ctx, bundle, sec_oper, NULL);

    if (BSL_SUCCESS == ctx.status)
    {
        BSLX_CoseSc_GetOptions(&ctx, sec_oper);
    }

    bool valid = (ctx.status == BSL_SUCCESS);
    BSLX_CoseSc_Deinit(&ctx);
    return valid;
}

int BSLX_CoseSc_AadScope_Encode(QCBOREncodeContext *enc, const BSLX_CoseSc_AadScope_t *scope)
{
    // aad-scope map
    QCBOREncode_OpenMap(enc);

    BSLX_CoseSc_AadScope_it_t aads_it;
    for (BSLX_CoseSc_AadScope_it(aads_it, *scope); !BSLX_CoseSc_AadScope_end_p(aads_it);
         BSLX_CoseSc_AadScope_next(aads_it))
    {
        const BSLX_CoseSc_AadScope_subtype_ct *aads_pair = BSLX_CoseSc_AadScope_cref(aads_it);
        QCBOREncode_AddInt64(enc, *(aads_pair->key_ptr));
        QCBOREncode_AddUInt64(enc, *(aads_pair->value_ptr));
    }

    QCBOREncode_CloseMap(enc);
    return BSL_SUCCESS;
}

int BSLX_CoseSc_AadScope_Decode(QCBORDecodeContext *dec, BSLX_CoseSc_AadScope_t *scope)
{
    BSLX_CoseSc_AadScope_reset(*scope);

    QCBORItem item;
    QCBORDecode_EnterArray(dec, &item); // using QCBOR_DECODE_MODE_MAP_AS_ARRAY

    while (QCBOR_SUCCESS == QCBORDecode_PeekNext(dec, &item))
    {
        int64_t blk_num;
        QCBORDecode_GetInt64(dec, &blk_num);
        if (QCBOR_SUCCESS != QCBORDecode_GetError(dec))
        {
            BSL_LOG_ERR("Invalid AAD Scope map key");
            break;
        }

        uint64_t aad_flags;
        QCBORDecode_GetUInt64(dec, &aad_flags);
        if (QCBOR_SUCCESS != QCBORDecode_GetError(dec))
        {
            BSL_LOG_ERR("Invalid AAD Scope map value");
            break;
        }

        BSLX_CoseSc_AadScope_set_at(*scope, blk_num, aad_flags);
    }

    QCBORDecode_ExitArray(dec);
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
// Workaround for https://github.com/P-p-H-d/mlib/issues/162
#undef M_PTR_OPLIST
#define M_PTR_OPLIST                                                                              \
    (INIT(M_INIT_DEFAULT), INIT_SET(M_SET_DEFAULT), SET(M_SET_DEFAULT), CLEAR(M_NOTHING_DEFAULT), \
     EQUAL(M_EQUAL_DEFAULT), SWAP(M_SWAP_DEFAULT), INIT_MOVE(M_SET_DEFAULT), MOVE(M_SET_DEFAULT))

M_VARIANT_DEF2(BSLX_CoseSc_ChunkItem, (data, m_bstring_t, M_BSTRING_OPLIST), (seq, BSL_SeqReader_t *, M_PTR_OPLIST))
#define M_OPL_BSLX_CoseSc_ChunkItem_t() M_VARIANT_OPLIST(BSLX_CoseSc_ChunkItem, M_BSTRING_OPLIST, M_PTR_OPLIST)

M_DEQUE_DEF(BSLX_CoseSc_ChunkList, BSLX_CoseSc_ChunkItem_t, M_OPL_BSLX_CoseSc_ChunkItem_t())
// GCOV_EXCL_STOP
/// @endcond

/** Get the last bytes chunk to append to, or add one if needed.
 */
static m_bstring_t *BSLX_CoseSc_ChunkList_GetBstring(BSLX_CoseSc_ChunkList_t chunklist)
{
    m_bstring_t *data = NULL;
    if (!BSLX_CoseSc_ChunkList_empty_p(chunklist))
    {
        BSLX_CoseSc_ChunkItem_t *item = BSLX_CoseSc_ChunkList_back(chunklist);
        // will leave as NULL if not present
        data = BSLX_CoseSc_ChunkItem_get_data(*item);
    }
    if (!data)
    {
        BSLX_CoseSc_ChunkItem_t *item = BSLX_CoseSc_ChunkList_push_back_new(chunklist);
        // new data
        m_bstring_t start;
        m_bstring_init(start);
        BSLX_CoseSc_ChunkItem_move_data(*item, start);
        data = BSLX_CoseSc_ChunkItem_get_data(*item);
    }
    return data;
}

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
        m_bstring_t *data = BSLX_CoseSc_ChunkList_GetBstring(chunklist);

        BSL_Data_t chunk;
        BSL_Data_Init(&chunk);

        // source-eid
        res = BSL_HostEID_EncodeToCBOR(&ctx->sec_src_eid, &chunk, NULL);
        // GCOV_EXCL_START
        if (res != BSL_SUCCESS)
        {
            BSL_LOG_ERR("Failed to encode Security Source");
            BSL_Data_Deinit(&chunk);
            return BSL_ERR_ENCODING;
        }
        // GCOV_EXCL_STOP
        *total += BSLX_CoseSc_bstring_AppendRaw(*data, &chunk);

        // aad-scope canonicalized
        res = BSL_CBOR_Encode_Twopass(&chunk, (BSL_CBOR_Encode_f)&BSLX_CoseSc_AadScope_Encode, &ctx->aad_scope);
        // GCOV_EXCL_START
        if (BSL_SUCCESS != res)
        {
            BSL_LOG_ERR("Failed to encode AAD Scope");
            BSL_Data_Deinit(&chunk);
            return BSL_ERR_ENCODING;
        }
        // GCOV_EXCL_STOP
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
                m_bstring_t *data = BSLX_CoseSc_ChunkList_GetBstring(chunklist);

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
                m_bstring_t *data = BSLX_CoseSc_ChunkList_GetBstring(chunklist);

                // three items from the canonical block header
                *total += BSLX_CoseSc_bstring_AppendHead(*data, CBOR_MAJOR_TYPE_POSITIVE_INT, aad_block.type_code);
                *total += BSLX_CoseSc_bstring_AppendHead(*data, CBOR_MAJOR_TYPE_POSITIVE_INT, aad_block.block_num);
                *total += BSLX_CoseSc_bstring_AppendHead(*data, CBOR_MAJOR_TYPE_POSITIVE_INT, aad_block.flags);
            }
            if (aad_flags & BSLX_COSESC_AAD_FLAG_BTSD)
            {
                // CBOR head and seq stream
                {
                    m_bstring_t *data = BSLX_CoseSc_ChunkList_GetBstring(chunklist);

                    *total += BSLX_CoseSc_bstring_AppendHead(*data, CBOR_MAJOR_TYPE_BYTE_STRING, 0);
                }
                {
                    BSLX_CoseSc_ChunkItem_t *item = BSLX_CoseSc_ChunkList_push_back_new(chunklist);
                    BSLX_CoseSc_ChunkItem_move_seq(*item, NULL);
                    BSL_SeqReader_t **seq = BSLX_CoseSc_ChunkItem_get_seq(*item);

                    *seq = BSL_BundleCtx_ReadBTSD(ctx->bundle, blk_num);
                    // GCOV_EXCL_START
                    if (!*seq)
                    {
                        BSL_LOG_ERR("Failed to construct reader");
                        return BSL_ERR_ENCODING;
                    }
                    // GCOV_EXCL_STOP
                    *total += aad_block.btsd_len;
                }
            }
        }
    }

    { // additional_protected, even if empty
        m_bstring_t *data = BSLX_CoseSc_ChunkList_GetBstring(chunklist);

        *total += BSLX_CoseSc_bstring_AppendHead(*data, CBOR_MAJOR_TYPE_BYTE_STRING, ctx->addl_phdr_bstr.len);
        *total += BSLX_CoseSc_bstring_AppendRaw(*data, &ctx->addl_phdr_bstr);
    }

    return BSL_SUCCESS;
}

/** Common COSE AAD composition for MAC, Encrypt, and Sign.
 * This relies on the outer array head to already be present in the list.
 */
static void BSLX_CoseSc_BuildAad(BSLX_CoseSc_t *ctx, BSLX_CoseSc_ChunkList_t chunklist,
                                 const BSLX_CoseMsg_Headers_t *headers, const char *context)
{
    m_bstring_t *data = BSLX_CoseSc_ChunkList_GetBstring(chunklist);

    { // context text
        size_t ctx_len = strlen(context);
        BSLX_CoseSc_bstring_AppendHead(*data, CBOR_MAJOR_TYPE_TEXT_STRING, ctx_len);
        m_bstring_push_back_bytes(*data, ctx_len, context);
    }

    // protected bytes
    BSLX_CoseSc_bstring_AppendHead(*data, CBOR_MAJOR_TYPE_BYTE_STRING, headers->phdr_bstr.len);
    BSLX_CoseSc_bstring_AppendRaw(*data, &headers->phdr_bstr);

    // external AAD bstr wrapped
    {
        BSLX_CoseSc_ChunkItem_t *item = BSLX_CoseSc_ChunkList_push_back_new(chunklist);
        // force a new bstring item for external_aad content
        m_bstring_t start;
        m_bstring_init(start);
        BSLX_CoseSc_ChunkItem_move_data(*item, start);
    }
    size_t ext_aad_len;
    // compute total size of what would be produced by chunks
    int res = BSLX_CoseSc_ExternalAad_Chunked(ctx, chunklist, &ext_aad_len);
    if (BSL_SUCCESS != res)
    {
        ctx->status = BSL_ERR_SECURITY_CONTEXT_VALIDATION_FAILED;
        // continue processing
    }

    // after external AAD size is known, inject bstr head above
    BSLX_CoseSc_bstring_AppendHead(*data, CBOR_MAJOR_TYPE_BYTE_STRING, ext_aad_len);
}

/** Internal processing according to Section 6.3 of RFC 9052.
 */
static void BSLX_CoseSc_Mac_Compute(BSLX_CoseSc_t *ctx, const BSLX_CoseMsg_Headers_t *headers, const char *context,
                                    BSL_Data_t *tag)
{
    int res;

    BSL_CryptoCipherSHAVariant_e bsl_sha_var;
    switch (ctx->tgt_alg)
    {
        case BSLX_COSEMSG_ALG_HMAC_SHA_256_256:
            bsl_sha_var = BSL_CRYPTO_SHA_256;
            break;
        case BSLX_COSEMSG_ALG_HMAC_SHA_384_384:
            bsl_sha_var = BSL_CRYPTO_SHA_384;
            break;
        case BSLX_COSEMSG_ALG_HMAC_SHA_512_512:
            bsl_sha_var = BSL_CRYPTO_SHA_512;
            break;
        default:
            BSL_LOG_ERR("Invalid COSE algorithm %" PRId64, ctx->tgt_alg);
            ctx->status = BSL_ERR_SECURITY_CONTEXT_VALIDATION_FAILED;
            return;
    }

    // Chunks of MAC_Structure
    BSLX_CoseSc_ChunkList_t chunklist;
    BSLX_CoseSc_ChunkList_init(chunklist);

    { // 4-item array
        m_bstring_t *data = BSLX_CoseSc_ChunkList_GetBstring(chunklist);
        BSLX_CoseSc_bstring_AppendHead(*data, CBOR_MAJOR_TYPE_ARRAY, 4);
    }
    BSLX_CoseSc_BuildAad(ctx, chunklist, headers, context);
    { // length of payload
        m_bstring_t *data = BSLX_CoseSc_ChunkList_GetBstring(chunklist);
        BSLX_CoseSc_bstring_AppendHead(*data, CBOR_MAJOR_TYPE_BYTE_STRING, ctx->target_block.btsd_len);
    }
    { // the target BTSD as payload
        BSLX_CoseSc_ChunkItem_t *item = BSLX_CoseSc_ChunkList_push_back_new(chunklist);
        BSLX_CoseSc_ChunkItem_move_seq(*item, NULL);
        BSL_SeqReader_t **seq = BSLX_CoseSc_ChunkItem_get_seq(*item);

        *seq = BSL_BundleCtx_ReadBTSD(ctx->bundle, ctx->target_block.block_num);
        // GCOV_EXCL_START
        if (!*seq)
        {
            BSL_LOG_ERR("Failed to construct reader");
            ctx->status = BSL_ERR_SECURITY_CONTEXT_VALIDATION_FAILED;
            return;
        }
        // GCOV_EXCL_STOP
    }

    if (BSL_SUCCESS == ctx->status)
    {
        ctx->mac_ctx = BSL_malloc(sizeof(BSL_AuthCtx_t));
        // use separate content key when available
        BSL_Crypto_KeyHandle_t content_key = ctx->cekhandle ? ctx->cekhandle : ctx->keyhandle;

        res = BSL_AuthCtx_Init(ctx->mac_ctx, content_key, bsl_sha_var);
        // GCOV_EXCL_START
        if (BSL_SUCCESS != res)
        {
            BSL_LOG_ERR("Failed to construct MAC context");
            ctx->status = BSL_ERR_SECURITY_CONTEXT_VALIDATION_FAILED;
        }
        // GCOV_EXCL_STOP
    }

    if (BSL_SUCCESS == ctx->status)
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
                // GCOV_EXCL_START
                if (BSL_SUCCESS != res)
                {
                    BSL_LOG_ERR("Failed to process MAC");
                    ctx->status = BSL_ERR_SECURITY_CONTEXT_VALIDATION_FAILED;
                }
                // GCOV_EXCL_STOP
            }
            else if ((seq = BSLX_CoseSc_ChunkItem_cget_seq(*item)))
            {
                res = BSL_AuthCtx_DigestSeq(ctx->mac_ctx, *seq);
                // GCOV_EXCL_START
                if (BSL_SUCCESS != res)
                {
                    BSL_LOG_ERR("Failed to process MAC");
                    ctx->status = BSL_ERR_SECURITY_CONTEXT_VALIDATION_FAILED;
                }
                // GCOV_EXCL_STOP
            }
            // GCOV_EXCL_START
            else
            {
                BSL_LOG_WARNING("Ignoring empty chunk");
            }
            // GCOV_EXCL_STOP
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

    if (BSL_SUCCESS == ctx->status)
    {
        res = BSL_AuthCtx_Finalize(ctx->mac_ctx, tag);
        // GCOV_EXCL_START
        if (BSL_SUCCESS != res)
        {
            BSL_LOG_ERR("BSL_AuthCtx_Finalize failed with code %d", res);
            ctx->status = BSL_ERR_SECURITY_CONTEXT_VALIDATION_FAILED;
        }
        // GCOV_EXCL_STOP
    }
}

static void BSLX_CoseSc_GetAndValidateTarget(BSLX_CoseSc_t *self, const BSLX_CoseMsg_Headers_t *headers)
{
    bool    hdr_alg     = false;
    int64_t hdr_alg_val = 0;

    if (headers)
    {
        const BSL_IdValPair_t *hdr = BSLX_CoseMsg_Headers_Get(headers, BSLX_COSEMSG_HDR_ALG, true);
        if (hdr)
        {
            if (BSL_SUCCESS != BSL_IdValPair_GetAsInt64(hdr, &hdr_alg_val))
            {
                BSL_LOG_ERR("Invalid header alg value");
                self->status = BSL_ERR_SECURITY_CONTEXT_FAILED;
                return;
            }
            else
            {
                hdr_alg = true;
            }
        }
    }

    if (hdr_alg && self->opt_tgt_alg)
    {
        if (hdr_alg_val != self->tgt_alg)
        {
            BSL_LOG_ERR("Mismatched key alg value, op has %" PRId64 " key has %" PRId64, self->tgt_alg, hdr_alg_val);
            self->status = BSL_ERR_SECURITY_CONTEXT_FAILED;
            return;
        }
    }
    else if (hdr_alg)
    {
        self->tgt_alg = hdr_alg_val;
        // came from unconstrained header
        self->hdr_tgt_alg = true;
    }
    else if (headers && !self->opt_tgt_alg)
    {
        BSL_LOG_ERR("No source of content alg available");
        self->status = BSL_ERR_SECURITY_CONTEXT_FAILED;
        return;
    }

    switch (self->tgt_alg)
    {
        case BSLX_COSEMSG_ALG_AES_GCM_128:
            self->tgt_keylen = 16;
            break;
        case BSLX_COSEMSG_ALG_AES_GCM_192:
            self->tgt_keylen = 24;
            break;
        case BSLX_COSEMSG_ALG_AES_GCM_256:
            self->tgt_keylen = 32;
            break;
        case BSLX_COSEMSG_ALG_HMAC_SHA_256_256:
            self->tgt_keylen = 32;
            break;
        case BSLX_COSEMSG_ALG_HMAC_SHA_384_384:
            self->tgt_keylen = 48;
            break;
        case BSLX_COSEMSG_ALG_HMAC_SHA_512_512:
            self->tgt_keylen = 64;
            break;
        default:
            BSL_LOG_CRIT("Unhandled content alg %" PRId64, self->tgt_alg);
            self->tgt_keylen = 0;
            break;
    }
}

/** Combine options and received headers to validate end key.
 */
static void BSLX_CoseSc_GetAndValidateKey(BSLX_CoseSc_t *self, const BSLX_CoseMsg_Headers_t *headers)
{
    bool       hdr_kid = false;
    BSL_Data_t hdr_kid_view;
    bool       hdr_alg     = false;
    int64_t    hdr_alg_val = 0;
    if (headers)
    {
        const BSL_IdValPair_t *hdr = BSLX_CoseMsg_Headers_Get(headers, BSLX_COSEMSG_HDR_KID, false);
        if (hdr)
        {
            if (BSL_SUCCESS != BSL_IdValPair_GetAsBytestr(hdr, &hdr_kid_view))
            {
                BSL_LOG_ERR("Invalid header key ID value");
                self->status = BSL_ERR_SECURITY_CONTEXT_FAILED;
                return;
            }
            else
            {
                hdr_kid = true;
            }
        }

        // being loose here about unprotected key alg for cases like AESKW
        hdr = BSLX_CoseMsg_Headers_Get(headers, BSLX_COSEMSG_HDR_ALG, false);
        if (hdr)
        {
            if (BSL_SUCCESS != BSL_IdValPair_GetAsInt64(hdr, &hdr_alg_val))
            {
                BSL_LOG_ERR("Invalid header alg value");
                self->status = BSL_ERR_SECURITY_CONTEXT_FAILED;
                return;
            }
            else
            {
                hdr_alg = true;
            }
        }
    }

    // Check for conflict and find key or fail
    if (hdr_kid && self->opt_kid)
    {
        if (BSL_Data_Cmp(&self->kid, &hdr_kid_view) != 0)
        {
            BSL_LOG_ERR("Mismatched key ID value");
            self->status = BSL_ERR_SECURITY_CONTEXT_FAILED;
            return;
        }
    }
    else if (hdr_kid)
    {
        BSL_Data_CopyFrom(&self->kid, hdr_kid_view.len, hdr_kid_view.ptr);
    }
    else if (!self->opt_kid)
    {
        BSL_LOG_ERR("No source of key ID available");
        self->status = BSL_ERR_SECURITY_CONTEXT_FAILED;
        return;
    }

    if (BSL_SUCCESS != BSL_Crypto_GetRegistryKey(&self->kid, &self->keyhandle))
    {
        BSL_LOG_ERR("Unknown key from ID");
        self->status = BSL_ERR_SECURITY_CONTEXT_FAILED;
        return;
    }

    if (hdr_alg && self->opt_key_alg)
    {
        if (hdr_alg_val != self->key_alg)
        {
            BSL_LOG_ERR("Mismatched key alg value, op has %" PRId64 " header has %" PRId64, self->key_alg, hdr_alg_val);
            self->status = BSL_ERR_SECURITY_CONTEXT_FAILED;
            return;
        }
    }
    else if (hdr_alg)
    {
        self->key_alg     = hdr_alg_val;
        self->hdr_key_alg = true;
    }
    else if (headers && !self->opt_key_alg)
    {
        BSL_LOG_ERR("No source of key alg available");
        self->status = BSL_ERR_SECURITY_CONTEXT_FAILED;
        return;
    }

    // Key itself must agree with chosen alg
    const BSL_IdValPair_t *param = BSL_Crypto_GetKeyParameter(self->keyhandle, BSLX_COSEMSG_KEY_PARAM_ALG);
    if (param)
    {
        int64_t key_alg_int;
        if (BSL_SUCCESS != BSL_IdValPair_GetAsInt64(param, &key_alg_int))
        {
            BSL_LOG_ERR("Invalid key algorithm value");
            self->status = BSL_ERR_SECURITY_CONTEXT_FAILED;
        }
        else if ((self->opt_key_alg || self->hdr_key_alg) && (self->key_alg != key_alg_int))
        {
            BSL_LOG_ERR("Option key algorithm value %" PRId64 " differs from key store %" PRId64, self->key_alg,
                        key_alg_int);
            self->status = BSL_ERR_SECURITY_CONTEXT_FAILED;
        }
        else
        {
            self->key_alg = key_alg_int;
        }
    }
    else if (!(self->opt_key_alg))
    {
        BSL_LOG_ERR("Option for key algorithm not supplied and key has no alg parameter");
        self->status = BSL_ERR_SECURITY_CONTEXT_FAILED;
    }
    BSL_LOG_DEBUG("Using key algorithm code %" PRId64, self->key_alg);
}

static void BSLX_CoseSc_GetAndValidateAddlHeaders(BSLX_CoseSc_t *self)
{
    const BSL_IdValPair_t *param = BSL_SecOper_FindParam(self->sec_oper, BSLX_COSESC_PARAM_ADDL_PHDR);
    if (param)
    {
        BSL_Data_t view;
        if (BSL_SUCCESS != BSL_IdValPair_GetAsBytestr(param, &view))
        {
            BSL_LOG_ERR("Invalid Additional Protected parameter");
            self->status = BSL_ERR_SECURITY_CONTEXT_FAILED;
        }
        else
        {
            // keep copy and decode
            BSL_Data_CopyFrom(&self->addl_phdr_bstr, view.len, view.ptr);

            int res = BSL_CBOR_Decode(&view, (BSL_CBOR_Decode_f)&BSLX_CoseMsg_Headers_Decode_Map, &self->addl_phdr);
            if (BSL_SUCCESS != res)
            {
                BSL_LOG_ERR("Failed to decode Additional Protected parameter");
                self->status = BSL_ERR_SECURITY_CONTEXT_FAILED;
            }
        }
    }

    param = BSL_SecOper_FindParam(self->sec_oper, BSLX_COSESC_PARAM_ADDL_UHDR);
    if (param)
    {
        BSL_Data_t view;
        if (BSL_SUCCESS != BSL_IdValPair_GetAsBytestr(param, &view))
        {
            BSL_LOG_ERR("Invalid Additional Protected parameter");
            self->status = BSL_ERR_SECURITY_CONTEXT_FAILED;
        }
        else
        {
            int res = BSL_CBOR_Decode(&view, (BSL_CBOR_Decode_f)&BSLX_CoseMsg_Headers_Decode_Map, &self->addl_uhdr);
            if (BSL_SUCCESS != res)
            {
                BSL_LOG_ERR("Failed to decode Additional Protected parameter");
                self->status = BSL_ERR_SECURITY_CONTEXT_FAILED;
            }
        }
    }
}

static void BSLX_CoseSc_GetAndValidateAadScope(BSLX_CoseSc_t *self)
{
    const BSL_IdValPair_t *param = BSL_SecOper_FindParam(self->sec_oper, BSLX_COSESC_PARAM_AAD_SCOPE);
    if (param)
    {
        BSL_Data_t enc_data;
        if (BSL_SUCCESS != BSL_IdValPair_GetAsRaw(param, &enc_data))
        {
            BSL_LOG_ERR("Invalid AAD Scope parameter");
            self->status = BSL_ERR_SECURITY_CONTEXT_FAILED;
        }
        else
        {
            BSLX_CoseSc_AadScope_t msg_scope;
            BSLX_CoseSc_AadScope_init(msg_scope);
            int res = BSL_CBOR_Decode(&enc_data, (BSL_CBOR_Decode_f)&BSLX_CoseSc_AadScope_Decode, &msg_scope);
            if (BSL_SUCCESS != res)
            {
                BSL_LOG_ERR("Failed to decode AAD Scope parameter");
                BSLX_CoseSc_AadScope_clear(msg_scope);
                self->status = BSL_ERR_SECURITY_CONTEXT_FAILED;
            }
            else
            {
                if (self->opt_aad_scope && !BSLX_CoseSc_AadScope_equal_p(self->aad_scope, msg_scope))
                {
                    BSL_LOG_ERR("Mismatch of AAD Scope parameter");
                    BSLX_CoseSc_AadScope_clear(msg_scope);
                    self->status = BSL_ERR_SECURITY_CONTEXT_FAILED;
                }
                else
                {
                    BSLX_CoseSc_AadScope_move(self->aad_scope, msg_scope);
                }
            }
        }
    }
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

        BSLX_CoseMsg_HdrMapTree_set_at(msg.headers.phdr, param->id, param_ptr);
        BSLB_IdValPairPtr_release(param_ptr);
    }
    if (ctx->kid.len)
    {
        BSLB_IdValPairPtr_t *param_ptr = BSLB_IdValPairPtr_new();
        BSL_IdValPair_t     *param     = BSLB_IdValPairPtr_ref(param_ptr);

        BSL_IdValPair_SetBytestr(param, BSLX_COSEMSG_HDR_KID, ctx->kid);

        BSLX_CoseMsg_HdrMapTree_set_at(msg.headers.uhdr, param->id, param_ptr);
        BSLB_IdValPairPtr_release(param_ptr);
    }

    BSLX_CoseMsg_Headers_DerivePhdr(&msg.headers);

    if (BSL_SUCCESS == ctx->status)
    {
        BSLX_CoseSc_Mac_Compute(ctx, &msg.headers, "MAC0", &msg.tag);
    }

    BSL_Data_t aad_scope_enc;
    BSL_Data_Init(&aad_scope_enc);
    if (BSL_SUCCESS == ctx->status)
    {
        res = BSL_CBOR_Encode_Twopass(&aad_scope_enc, (BSL_CBOR_Encode_f)&BSLX_CoseSc_AadScope_Encode, &ctx->aad_scope);
        // GCOV_EXCL_START
        if (BSL_SUCCESS != res)
        {
            BSL_LOG_ERR("Failed to encode AAD Scope");
            ctx->status = res;
        }
        // GCOV_EXCL_STOP
    }

    BSL_Data_t msg_enc;
    BSL_Data_Init(&msg_enc);
    if (BSL_SUCCESS == ctx->status)
    {
        res = BSL_CBOR_Encode_Twopass(&msg_enc, (BSL_CBOR_Encode_f)&BSLX_CoseMsg_Mac0_Encode, &msg);
        // GCOV_EXCL_START
        if (BSL_SUCCESS != res)
        {
            BSL_LOG_ERR("Failed to encode Mac0");
            ctx->status = res;
        }
        // GCOV_EXCL_STOP
    }
    if (BSL_SUCCESS == ctx->status)
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

/** Internal processing to verify a COSE_Mac0 message.
 */
static void BSLX_CoseSc_Mac0_VerifyAccept(BSLX_CoseSc_t *ctx, const BSL_IdValPair_t *result)
{
    int res;

    BSLX_CoseSc_GetAndValidateAddlHeaders(ctx);
    BSLX_CoseSc_GetAndValidateAadScope(ctx);
    if (BSL_SUCCESS != ctx->status)
    {
        // early exit
        return;
    }

    BSLX_CoseMsg_Mac0_t msg;
    BSLX_CoseMsg_Mac0_Init(&msg);
    {
        BSL_Data_t msg_enc;
        BSL_Data_Init(&msg_enc);
        if (BSL_SUCCESS != BSL_IdValPair_GetAsBytestr(result, &msg_enc))
        {
            BSL_LOG_ERR("Failed to get encoded message");
            ctx->status = BSL_ERR_SECURITY_CONTEXT_VALIDATION_FAILED;
        }
        else
        {
            res = BSL_CBOR_Decode(&msg_enc, (BSL_CBOR_Decode_f)&BSLX_CoseMsg_Mac0_Decode, &msg);
            if (BSL_SUCCESS != res)
            {
                BSL_LOG_ERR("Failed to decode COSE_Mac0");
                ctx->status = BSL_ERR_SECURITY_CONTEXT_VALIDATION_FAILED;
            }
            else
            {
                if (BSL_SUCCESS != BSLX_CoseMsg_Headers_CheckCrit(&msg.headers))
                {
                    BSL_LOG_ERR("Failed crit header check");
                    ctx->status = BSL_ERR_SECURITY_CONTEXT_CRYPTO_FAILED;
                }
            }
        }
        BSL_Data_Deinit(&msg_enc);
    }
    if (BSL_SUCCESS != ctx->status)
    {
        return;
    }
    // synthesize additional headers
    BSLX_CoseMsg_HdrMapTree_update(msg.headers.uhdr, ctx->addl_phdr);
    BSLX_CoseMsg_HdrMapTree_update(msg.headers.uhdr, ctx->addl_uhdr);

    BSLX_CoseSc_GetAndValidateKey(ctx, &msg.headers);
    BSLX_CoseSc_GetAndValidateTarget(ctx, &msg.headers);

    if (BSL_SUCCESS == ctx->status)
    {
        BSL_Data_t tag;
        BSL_Data_Init(&tag);
        BSLX_CoseSc_Mac_Compute(ctx, &msg.headers, "MAC0", &tag);

        bool tag_valid = BSL_Crypto_Compare(msg.tag.ptr, msg.tag.len, tag.ptr, tag.len);
        if (tag_valid)
        {
            BSL_LOG_DEBUG("MAC tag verified");
        }
        else
        {
            BSL_LOG_ERR("MAC tag failed");
            ctx->status = BSL_ERR_SECURITY_CONTEXT_AUTH_FAILED;
        }
        BSL_Data_Deinit(&tag);
    }

    BSLX_CoseMsg_Mac0_Deinit(&msg);
}

static void BSLX_CoseSc_GenerateContentKey(BSLX_CoseSc_t *ctx, BSLX_CoseMsg_Recipient_t *recip)
{
  int res;
  
    switch (ctx->key_alg)
    {
        case BSLX_COSEMSG_ALG_AES_KW_128:
        case BSLX_COSEMSG_ALG_AES_KW_192:
        case BSLX_COSEMSG_ALG_AES_KW_256:
        {
            BSL_LOG_DEBUG("Generating %zu bit content key", ctx->tgt_keylen * 8);

            if (BSL_SUCCESS != BSL_Crypto_GenKey(ctx->tgt_keylen, &ctx->cekhandle))
            {
                BSL_LOG_ERR("Failed to generate content key");
                ctx->status = BSL_ERR_SECURITY_CONTEXT_CRYPTO_FAILED;
            }

            res = BSL_Crypto_WrapKey(ctx->keyhandle, ctx->cekhandle, &recip->ciphertext, NULL);
            if (BSL_SUCCESS != res)
            {
                BSL_LOG_ERR("Failed to wrap content key");
                ctx->status = BSL_ERR_SECURITY_CONTEXT_CRYPTO_FAILED;
            }

            break;
        }
        case BSLX_COSEMSG_ALG_DIRECT_HKDF_SHA_256:
        case BSLX_COSEMSG_ALG_DIRECT_HKDF_SHA_512:
            BSL_LOG_CRIT("Not implemented");
            ctx->status = BSL_ERR_SECURITY_CONTEXT_FAILED;
            break;
        default:
            BSL_LOG_ERR("Unsupported recipient algorithm %" PRId64, ctx->key_alg);
            ctx->status = BSL_ERR_SECURITY_CONTEXT_FAILED;
            break;
    }
}

/** Internal processing to source a COSE_Mac message.
 */
static void BSLX_CoseSc_Mac_Source(BSLX_CoseSc_t *ctx)
{
    int res;

    BSLX_CoseMsg_Mac_t msg;
    BSLX_CoseMsg_Mac_Init(&msg);
    {
        BSLB_IdValPairPtr_t *param_ptr = BSLB_IdValPairPtr_new();
        BSL_IdValPair_t     *param     = BSLB_IdValPairPtr_ref(param_ptr);

        BSL_IdValPair_SetInt64(param, BSLX_COSEMSG_HDR_ALG, ctx->tgt_alg);

        BSLX_CoseMsg_HdrMapTree_set_at(msg.headers.phdr, param->id, param_ptr);
        BSLB_IdValPairPtr_release(param_ptr);
    }
    // exactly one recipient
    BSLX_CoseMsg_RecipientList_ResizeNew(msg.recipients, 1);
    BSLX_CoseMsg_Recipient_t *recip = BSLX_CoseMsg_RecipientPtr_ref(*BSLX_CoseMsg_RecipientList_front(msg.recipients));

    {
        BSLB_IdValPairPtr_t *param_ptr = BSLB_IdValPairPtr_new();
        BSL_IdValPair_t     *param     = BSLB_IdValPairPtr_ref(param_ptr);

        BSL_IdValPair_SetInt64(param, BSLX_COSEMSG_HDR_ALG, ctx->key_alg);

        BSLX_CoseMsg_HdrMapTree_set_at(recip->headers.uhdr, param->id, param_ptr);
        BSLB_IdValPairPtr_release(param_ptr);
    }
    {
        BSLB_IdValPairPtr_t *param_ptr = BSLB_IdValPairPtr_new();
        BSL_IdValPair_t     *param     = BSLB_IdValPairPtr_ref(param_ptr);

        BSL_IdValPair_SetBytestr(param, BSLX_COSEMSG_HDR_KID, ctx->kid);

        BSLX_CoseMsg_HdrMapTree_set_at(recip->headers.uhdr, param->id, param_ptr);
        BSLB_IdValPairPtr_release(param_ptr);
    }

    if (BSL_SUCCESS == ctx->status)
    {
        BSLX_CoseSc_GenerateContentKey(ctx, recip);
    }

    BSLX_CoseMsg_Headers_DerivePhdr(&msg.headers);
    BSLX_CoseMsg_Headers_DerivePhdr(&recip->headers);

    if (BSL_SUCCESS == ctx->status)
    {
        BSLX_CoseSc_Mac_Compute(ctx, &msg.headers, "MAC", &msg.tag);
    }

    BSL_Data_t aad_scope_enc;
    BSL_Data_Init(&aad_scope_enc);
    if (BSL_SUCCESS == ctx->status)
    {
        res = BSL_CBOR_Encode_Twopass(&aad_scope_enc, (BSL_CBOR_Encode_f)&BSLX_CoseSc_AadScope_Encode, &ctx->aad_scope);
        // GCOV_EXCL_START
        if (BSL_SUCCESS != res)
        {
            BSL_LOG_ERR("Failed to encode AAD Scope");
            ctx->status = res;
        }
        // GCOV_EXCL_STOP
    }

    BSL_Data_t msg_enc;
    BSL_Data_Init(&msg_enc);
    if (BSL_SUCCESS == ctx->status)
    {
        res = BSL_CBOR_Encode_Twopass(&msg_enc, (BSL_CBOR_Encode_f)&BSLX_CoseMsg_Mac_Encode, &msg);
        // GCOV_EXCL_START
        if (BSL_SUCCESS != res)
        {
            BSL_LOG_ERR("Failed to encode Mac0");
            ctx->status = res;
        }
        // GCOV_EXCL_STOP
    }
    if (BSL_SUCCESS == ctx->status)
    {
        {
            BSL_IdValPair_t *param = BSL_SecOutcome_AppendParam(ctx->sec_outcome);
            BSL_IdValPair_SetRaw(param, BSLX_COSESC_PARAM_AAD_SCOPE, aad_scope_enc.ptr, aad_scope_enc.len);
        }
        {
            BSL_IdValPair_t *result = BSL_SecOutcome_AppendResult(ctx->sec_outcome);
            BSL_IdValPair_SetBytestr(result, BSLX_COSESC_RESULT_COSE_MAC, msg_enc);
        }
    }
    BSL_Data_Deinit(&msg_enc);
    BSL_Data_Deinit(&aad_scope_enc);

    BSLX_CoseMsg_Mac_Deinit(&msg);
}

/** Internal processing according to Section 5.3 of RFC 9052.
 */
static void BSLX_CoseSc_Encrypt_Compute(BSLX_CoseSc_t *ctx, const BSLX_CoseMsg_Headers_t *headers, const char *context,
                                        BSL_CipherMode_e mode)
{
    ASSERT_PRECONDITION(ctx->full_iv.len > 0);
    int res;

    BSL_CryptoCipherAESVariant_e bsl_aes_var;
    switch (ctx->tgt_alg)
    {
        case BSLX_COSEMSG_ALG_AES_GCM_128:
            bsl_aes_var = BSL_CRYPTO_AES_128;
            break;
        case BSLX_COSEMSG_ALG_AES_GCM_192:
            bsl_aes_var = BSL_CRYPTO_AES_192;
            break;
        case BSLX_COSEMSG_ALG_AES_GCM_256:
            bsl_aes_var = BSL_CRYPTO_AES_256;
            break;
        default:
            BSL_LOG_ERR("Invalid COSE algorithm %" PRId64, ctx->tgt_alg);
            ctx->status = BSL_ERR_SECURITY_CONTEXT_VALIDATION_FAILED;
            return;
    }

    // Chunks of Enc_Structure
    BSLX_CoseSc_ChunkList_t chunklist;
    BSLX_CoseSc_ChunkList_init(chunklist);

    { // 3-item array
        m_bstring_t *data = BSLX_CoseSc_ChunkList_GetBstring(chunklist);
        BSLX_CoseSc_bstring_AppendHead(*data, CBOR_MAJOR_TYPE_ARRAY, 3);
    }
    BSLX_CoseSc_BuildAad(ctx, chunklist, headers, context);

    if (BSL_SUCCESS == ctx->status)
    {
        ctx->enc_ctx = BSL_malloc(sizeof(BSL_Cipher_t));
        // use separate content key when available
        BSL_Crypto_KeyHandle_t content_key = ctx->cekhandle ? ctx->cekhandle : ctx->keyhandle;

        res = BSL_Cipher_Init(ctx->enc_ctx, mode, bsl_aes_var, &ctx->full_iv, content_key);
        // GCOV_EXCL_START
        if (BSL_SUCCESS != res)
        {
            BSL_LOG_ERR("Failed to construct ENC context");
            ctx->status = BSL_ERR_SECURITY_CONTEXT_CRYPTO_FAILED;
        }
        // GCOV_EXCL_STOP
    }

    if (BSL_SUCCESS == ctx->status)
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

                res = BSL_Cipher_AddAadBuffer(ctx->enc_ctx, ptr, size);
                if (BSL_SUCCESS != res)
                {
                    BSL_LOG_ERR("Failed to process AAD");
                    ctx->status = BSL_ERR_SECURITY_CONTEXT_VALIDATION_FAILED;
                }
            }
            else if ((seq = BSLX_CoseSc_ChunkItem_cget_seq(*item)))
            {
                res = BSL_Cipher_AddAadSeq(ctx->enc_ctx, *seq);
                // GCOV_EXCL_START
                if (BSL_SUCCESS != res)
                {
                    BSL_LOG_ERR("Failed to process AAD");
                    ctx->status = BSL_ERR_SECURITY_CONTEXT_VALIDATION_FAILED;
                }
                // GCOV_EXCL_STOP
            }
            // GCOV_EXCL_START
            else
            {
                BSL_LOG_WARNING("Ignoring empty chunk");
            }
            // GCOV_EXCL_STOP
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

    const size_t tag_len = BSL_Cipher_TagLen(ctx->enc_ctx);
    BSL_LOG_DEBUG("using authentication tag length %zu", tag_len);
    // ciphertext has tag appended to it
    size_t read_len, write_len;
    if (mode == BSL_CRYPTO_ENCRYPT)
    {
        read_len  = ctx->target_block.btsd_len;
        write_len = read_len + tag_len;
    }
    else
    {
        read_len  = ctx->target_block.btsd_len - tag_len;
        write_len = read_len;
    }

    // Process the plaintext
    BSL_SeqReader_t *btsd_read  = NULL;
    BSL_SeqWriter_t *btsd_write = NULL;
    if (BSL_SUCCESS == ctx->status)
    {
        btsd_read = BSL_BundleCtx_ReadBTSD(ctx->bundle, ctx->target_block.block_num);
        // GCOV_EXCL_START
        if (!btsd_read)
        {
            BSL_LOG_ERR("Failed to construct reader");
            ctx->status = BSL_ERR_HOST_CALLBACK_FAILED;
        }
        // GCOV_EXCL_STOP

        if (ctx->overwrite_btsd)
        {
            btsd_write = BSL_BundleCtx_WriteBTSD(ctx->bundle, ctx->target_block.block_num, write_len);
            // GCOV_EXCL_START
            if (!btsd_write)
            {
                BSL_LOG_ERR("Failed to construct writer");
                ctx->status = BSL_ERR_HOST_CALLBACK_FAILED;
            }
            // GCOV_EXCL_STOP
        }
    }

    if (BSL_SUCCESS == ctx->status)
    {
        res = BSL_Cipher_AddSeq(ctx->enc_ctx, btsd_read, btsd_write, read_len);
        if (BSL_SUCCESS != res)
        {
            BSL_LOG_ERR("Encrypting plaintext BTSD failed");
            ctx->status = BSL_ERR_SECURITY_CONTEXT_CRYPTO_FAILED;
        }
    }

    if ((BSL_SUCCESS == ctx->status) && (mode == BSL_CRYPTO_DECRYPT))
    {
        // decryption pops off the auth tag
        size_t block_size = tag_len;
        BSL_SeqReader_Get(btsd_read, ctx->enc_ctx->in_buf.ptr, &block_size);
        if (block_size < tag_len)
        {
            BSL_LOG_ERR("Failed reading ciphertext tag");
            ctx->status = BSL_ERR_SECURITY_CONTEXT_CRYPTO_FAILED;
        }
        ctx->enc_ctx->in_buf.len = block_size;

        res = BSL_Cipher_SetTag(ctx->enc_ctx, &ctx->enc_ctx->in_buf);
        // GCOV_EXCL_START
        if (BSL_SUCCESS != res)
        {
            BSL_LOG_ERR("Failed to set auth tag");
            ctx->status = BSL_ERR_SECURITY_CONTEXT_CRYPTO_FAILED;
        }
        // GCOV_EXCL_STOP
    }

    if (BSL_SUCCESS == ctx->status)
    {
        res = BSL_Cipher_FinalizeSeq(ctx->enc_ctx, btsd_write);
        // GCOV_EXCL_START
        if (BSL_SUCCESS != res)
        {
            BSL_LOG_ERR("Finalizing AES failed");
            ctx->status = BSL_ERR_SECURITY_CONTEXT_CRYPTO_FAILED;
        }
        // GCOV_EXCL_STOP
    }

    if ((BSL_SUCCESS == ctx->status) && (mode == BSL_CRYPTO_ENCRYPT))
    {
        BSL_Data_t tag;
        BSL_Data_Init(&tag);

        res = BSL_Cipher_GetTag(ctx->enc_ctx, &tag);
        // GCOV_EXCL_START
        if (BSL_SUCCESS != res)
        {
            BSL_LOG_ERR("BSL_Cipher_Finalize failed with code %d", res);
            ctx->status = BSL_ERR_SECURITY_CONTEXT_VALIDATION_FAILED;
        }
        // GCOV_EXCL_STOP
        else
        {
            if (btsd_write)
            {
                BSL_SeqWriter_Put(btsd_write, tag.ptr, tag.len);
            }
        }
        BSL_Data_Deinit(&tag);
    }

    // close write after read
    BSL_SeqReader_Destroy(btsd_read);
    if (btsd_write)
    {
        BSL_SeqWriter_Destroy(btsd_write, ctx->status == BSL_SUCCESS);
    }
}

/** Generate optional partial IV depending on key Base IV.
 */
static void BSLX_CoseSc_GenerateIV(BSLX_CoseSc_t *ctx, BSLX_CoseMsg_Headers_t *headers)
{
    // create IV bytes
    BSL_Data_Resize(&ctx->full_iv, BSLX_COSEMSG_AESGCM_IV_LEN);

    if (ctx->opt_iv_offset)
    { // generate the IV from an offset
        BSL_Crypto_KeyStats_t stats;
        BSL_Crypto_GetKeyStatistics(ctx->keyhandle, &stats);
        uint64_t iv_int = (uint64_t)ctx->iv_offset + stats.stats[BSL_CRYPTO_KEYSTATS_TIMES_USED];

        // Network byte order right aligned
        const size_t ctr_len = 8;
        uint8_t      iv_bytes[ctr_len];
        for (size_t ix = 0; ix < ctr_len; ++ix)
        {
            iv_bytes[ctr_len - ix - 1] = iv_int & 0xFF;
            iv_int >>= 8;
        }
        const size_t pad = ctx->full_iv.len - ctr_len;
        memset(ctx->full_iv.ptr, 0, pad);
        memcpy(ctx->full_iv.ptr + pad, iv_bytes, ctr_len);
    }
    else
    { // no option, use random IV
        int res = BSL_Crypto_GenIV(&ctx->full_iv);
        if (BSL_SUCCESS != res)
        {
            BSL_LOG_ERR("Failed to generate IV");
            ctx->status = res;
        }
    }

    const BSL_IdValPair_t *keyparam = BSL_Crypto_GetKeyParameter(ctx->keyhandle, BSLX_COSEMSG_KEY_PARAM_BASEIV);
    if (keyparam)
    {
        BSL_Data_t baseiv_val;
        if (BSL_SUCCESS != BSL_IdValPair_GetAsBytestr(keyparam, &baseiv_val))
        {
            BSL_LOG_ERR("Invalid Base IV value");
            ctx->status = BSL_ERR_SECURITY_CONTEXT_CRYPTO_FAILED;
        }
        else if (ctx->full_iv.len != baseiv_val.len)
        {
            BSL_LOG_ERR("Invalid Base IV length, need %zu got %zu", ctx->full_iv.len, baseiv_val.len);
            ctx->status = BSL_ERR_SECURITY_CONTEXT_CRYPTO_FAILED;
        }
        else
        {
            // skip leading zeros, leaving at least one byte
            size_t skip = 0;
            while ((skip < ctx->full_iv.len - 1) && (ctx->full_iv.ptr[skip] == 0))
            {
                ++skip;
            }
            BSL_Data_CopyFrom(&ctx->partial_iv, ctx->full_iv.len - skip, ctx->full_iv.ptr + skip);

            // actually combine with the base
            for (size_t ix = 0; ix < ctx->full_iv.len; ++ix)
            {
                ctx->full_iv.ptr[ix] ^= baseiv_val.ptr[ix];
            }
        }
    }

    // prefer partial when defined
    if (ctx->partial_iv.len > 0)
    {
        BSLB_IdValPairPtr_t *param_ptr = BSLB_IdValPairPtr_new();
        {
            BSL_IdValPair_t *param = BSLB_IdValPairPtr_ref(param_ptr);
            BSL_IdValPair_SetBytestr(param, BSLX_COSEMSG_HDR_PARTIALIV, ctx->partial_iv);
        }
        BSLX_CoseMsg_HdrMapTree_set_at(headers->uhdr, BSLX_COSEMSG_HDR_PARTIALIV, param_ptr);
        BSLB_IdValPairPtr_release(param_ptr);
    }
    else
    {
        BSLB_IdValPairPtr_t *param_ptr = BSLB_IdValPairPtr_new();
        {
            BSL_IdValPair_t *param = BSLB_IdValPairPtr_ref(param_ptr);
            BSL_IdValPair_SetBytestr(param, BSLX_COSEMSG_HDR_IV, ctx->full_iv);
        }
        BSLX_CoseMsg_HdrMapTree_set_at(headers->uhdr, BSLX_COSEMSG_HDR_IV, param_ptr);
        BSLB_IdValPairPtr_release(param_ptr);
    }
}

/** Extract IV header parameters and augment with key data.
 */
static void BSLX_CoseSc_ExtractIV(BSLX_CoseSc_t *ctx, const BSLX_CoseMsg_Headers_t *headers)
{
    const BSL_IdValPair_t *head_iv = BSLX_CoseMsg_Headers_Get(headers, BSLX_COSEMSG_HDR_IV, false);
    if (head_iv)
    {
        if (BSL_SUCCESS != BSL_IdValPair_GetAsBytestr(head_iv, &ctx->full_iv))
        {
            BSL_LOG_ERR("Invalid IV header");
            ctx->status = BSL_ERR_SECURITY_CONTEXT_CRYPTO_FAILED;
        }
        else if (BSLX_COSEMSG_AESGCM_IV_LEN != ctx->full_iv.len)
        {
            BSL_LOG_ERR("Invalid IV length, need %zu got %zu", BSLX_COSEMSG_AESGCM_IV_LEN, ctx->full_iv.len);
            ctx->status = BSL_ERR_SECURITY_CONTEXT_CRYPTO_FAILED;
        }
    }
    else if ((head_iv = BSLX_CoseMsg_Headers_Get(headers, BSLX_COSEMSG_HDR_PARTIALIV, false)))
    {
        BSL_Data_Resize(&ctx->full_iv, BSLX_COSEMSG_AESGCM_IV_LEN);

        BSL_Data_t partialiv_val;
        if (BSL_SUCCESS != BSL_IdValPair_GetAsBytestr(head_iv, &partialiv_val))
        {
            BSL_LOG_ERR("Invalid IV header");
            ctx->status = BSL_ERR_SECURITY_CONTEXT_CRYPTO_FAILED;
        }
        else if (partialiv_val.len > ctx->full_iv.len)
        {
            BSL_LOG_ERR("Invalid Partial IV length, no more than %zu got %zu", ctx->full_iv.len, partialiv_val.len);
            ctx->status = BSL_ERR_SECURITY_CONTEXT_CRYPTO_FAILED;
        }

        BSL_Data_t baseiv_val;
        // need to combine with key Base IV
        const BSL_IdValPair_t *keyparam = BSL_Crypto_GetKeyParameter(ctx->keyhandle, BSLX_COSEMSG_KEY_PARAM_BASEIV);
        if (!keyparam)
        {
            BSL_LOG_ERR("Key is missing Base IV");
            ctx->status = BSL_ERR_SECURITY_CONTEXT_CRYPTO_FAILED;
        }
        else if (BSL_SUCCESS != BSL_IdValPair_GetAsBytestr(keyparam, &baseiv_val))
        {
            BSL_LOG_ERR("Invalid Base IV value");
            ctx->status = BSL_ERR_SECURITY_CONTEXT_CRYPTO_FAILED;
        }
        else if (ctx->full_iv.len != baseiv_val.len)
        {
            BSL_LOG_ERR("Invalid Base IV length, need %zu got %zu", ctx->full_iv.len, baseiv_val.len);
            ctx->status = BSL_ERR_SECURITY_CONTEXT_CRYPTO_FAILED;
        }
        else
        {
            // right-align the partial IV first
            const size_t pad = ctx->full_iv.len - partialiv_val.len;
            memset(ctx->full_iv.ptr, 0, pad);
            memcpy(ctx->full_iv.ptr + pad, partialiv_val.ptr, partialiv_val.len);

            for (size_t ix = 0; ix < ctx->full_iv.len; ++ix)
            {
                ctx->full_iv.ptr[ix] ^= baseiv_val.ptr[ix];
            }
        }
    }
}

/** Internal processing to source a COSE_Encrypt0 message.
 */
static void BSLX_CoseSc_Encrypt0_Source(BSLX_CoseSc_t *ctx)
{
    int res;

    BSLX_CoseMsg_Encrypt0_t msg;
    BSLX_CoseMsg_Encrypt0_Init(&msg);
    {
        BSLB_IdValPairPtr_t *param_ptr = BSLB_IdValPairPtr_new();
        BSL_IdValPair_t     *param     = BSLB_IdValPairPtr_ref(param_ptr);

        BSL_IdValPair_SetInt64(param, BSLX_COSEMSG_HDR_ALG, ctx->tgt_alg);

        BSLX_CoseMsg_HdrMapTree_set_at(msg.headers.phdr, param->id, param_ptr);
        BSLB_IdValPairPtr_release(param_ptr);
    }
    {
        BSLB_IdValPairPtr_t *param_ptr = BSLB_IdValPairPtr_new();
        BSL_IdValPair_t     *param     = BSLB_IdValPairPtr_ref(param_ptr);

        BSL_IdValPair_SetBytestr(param, BSLX_COSEMSG_HDR_KID, ctx->kid);

        BSLX_CoseMsg_HdrMapTree_set_at(msg.headers.uhdr, param->id, param_ptr);
        BSLB_IdValPairPtr_release(param_ptr);
    }

    if (BSL_SUCCESS == ctx->status)
    {
        // optional partial IV depending on key Base IV
        BSLX_CoseSc_GenerateIV(ctx, &msg.headers);
    }

    BSLX_CoseMsg_Headers_DerivePhdr(&msg.headers);

    if (BSL_SUCCESS == ctx->status)
    {
        BSLX_CoseSc_Encrypt_Compute(ctx, &msg.headers, "Encrypt0", BSL_CRYPTO_ENCRYPT);
    }

    BSL_Data_t aad_scope_enc;
    BSL_Data_Init(&aad_scope_enc);
    if (BSL_SUCCESS == ctx->status)
    {
        res = BSL_CBOR_Encode_Twopass(&aad_scope_enc, (BSL_CBOR_Encode_f)&BSLX_CoseSc_AadScope_Encode, &ctx->aad_scope);
        // GCOV_EXCL_START
        if (BSL_SUCCESS != res)
        {
            BSL_LOG_ERR("Failed to encode AAD Scope");
            ctx->status = res;
        }
        // GCOV_EXCL_STOP
    }
    BSL_Data_t msg_enc;
    BSL_Data_Init(&msg_enc);
    if (BSL_SUCCESS == ctx->status)
    {
        res = BSL_CBOR_Encode_Twopass(&msg_enc, (BSL_CBOR_Encode_f)&BSLX_CoseMsg_Encrypt0_Encode, &msg);
        // GCOV_EXCL_START
        if (BSL_SUCCESS != res)
        {
            BSL_LOG_ERR("Failed to encode Encrypt0");
            ctx->status = res;
        }
        // GCOV_EXCL_STOP
    }
    if (BSL_SUCCESS == ctx->status)
    {
        {
            BSL_IdValPair_t *param = BSL_SecOutcome_AppendParam(ctx->sec_outcome);
            BSL_IdValPair_SetRaw(param, BSLX_COSESC_PARAM_AAD_SCOPE, aad_scope_enc.ptr, aad_scope_enc.len);
        }
        {
            BSL_IdValPair_t *result = BSL_SecOutcome_AppendResult(ctx->sec_outcome);
            BSL_IdValPair_SetBytestr(result, BSLX_COSESC_RESULT_COSE_ENCRYPT0, msg_enc);
        }
    }
    BSL_Data_Deinit(&msg_enc);
    BSL_Data_Deinit(&aad_scope_enc);

    BSLX_CoseMsg_Encrypt0_Deinit(&msg);
}

/** Internal processing to verify a COSE_Encrypt0 message.
 */
static void BSLX_CoseSc_Encrypt0_VerifyAccept(BSLX_CoseSc_t *ctx, const BSL_IdValPair_t *result)
{
    int res;

    BSLX_CoseSc_GetAndValidateAddlHeaders(ctx);
    BSLX_CoseSc_GetAndValidateAadScope(ctx);
    if (BSL_SUCCESS != ctx->status)
    {
        // early exit
        return;
    }

    BSLX_CoseMsg_Encrypt0_t msg;
    BSLX_CoseMsg_Encrypt0_Init(&msg);
    {
        BSL_Data_t msg_enc;
        BSL_Data_Init(&msg_enc);
        if (BSL_SUCCESS != BSL_IdValPair_GetAsBytestr(result, &msg_enc))
        {
            BSL_LOG_ERR("Failed to get encoded message");
            ctx->status = BSL_ERR_SECURITY_CONTEXT_CRYPTO_FAILED;
        }
        else
        {
            res = BSL_CBOR_Decode(&msg_enc, (BSL_CBOR_Decode_f)&BSLX_CoseMsg_Encrypt0_Decode, &msg);
            if (BSL_SUCCESS != res)
            {
                BSL_LOG_ERR("Failed to decode COSE_Encrypt0");
                ctx->status = BSL_ERR_SECURITY_CONTEXT_CRYPTO_FAILED;
            }
            else
            {
                if (BSL_SUCCESS != BSLX_CoseMsg_Headers_CheckCrit(&msg.headers))
                {
                    BSL_LOG_ERR("Failed crit header check");
                    ctx->status = BSL_ERR_SECURITY_CONTEXT_CRYPTO_FAILED;
                }
            }
        }
        BSL_Data_Deinit(&msg_enc);
    }
    if (BSL_SUCCESS != ctx->status)
    {
        return;
    }
    // synthesize additional headers
    BSLX_CoseMsg_HdrMapTree_update(msg.headers.uhdr, ctx->addl_phdr);
    BSLX_CoseMsg_HdrMapTree_update(msg.headers.uhdr, ctx->addl_uhdr);

    BSLX_CoseSc_GetAndValidateKey(ctx, &msg.headers);
    BSLX_CoseSc_GetAndValidateTarget(ctx, &msg.headers);

    if (BSL_SUCCESS == ctx->status)
    {
        BSLX_CoseSc_ExtractIV(ctx, &msg.headers);
    }

    if (BSL_SUCCESS == ctx->status)
    {
        BSLX_CoseSc_Encrypt_Compute(ctx, &msg.headers, "Encrypt0", BSL_CRYPTO_DECRYPT);
    }

    BSLX_CoseMsg_Encrypt0_Deinit(&msg);
}

/** Internal processing to source a COSE_Encrypt message.
 */
static void BSLX_CoseSc_Encrypt_Source(BSLX_CoseSc_t *ctx)
{
    int res;

    BSLX_CoseMsg_Encrypt_t msg;
    BSLX_CoseMsg_Encrypt_Init(&msg);
    {
        BSLB_IdValPairPtr_t *param_ptr = BSLB_IdValPairPtr_new();
        BSL_IdValPair_t     *param     = BSLB_IdValPairPtr_ref(param_ptr);

        BSL_IdValPair_SetInt64(param, BSLX_COSEMSG_HDR_ALG, ctx->tgt_alg);

        BSLX_CoseMsg_HdrMapTree_set_at(msg.headers.phdr, param->id, param_ptr);
        BSLB_IdValPairPtr_release(param_ptr);
    }
    // exactly one recipient
    BSLX_CoseMsg_RecipientList_ResizeNew(msg.recipients, 1);
    BSLX_CoseMsg_Recipient_t *recip = BSLX_CoseMsg_RecipientPtr_ref(*BSLX_CoseMsg_RecipientList_front(msg.recipients));

    {
        BSLB_IdValPairPtr_t *param_ptr = BSLB_IdValPairPtr_new();
        BSL_IdValPair_t     *param     = BSLB_IdValPairPtr_ref(param_ptr);

        BSL_IdValPair_SetInt64(param, BSLX_COSEMSG_HDR_ALG, ctx->key_alg);

        BSLX_CoseMsg_HdrMapTree_set_at(recip->headers.uhdr, param->id, param_ptr);
        BSLB_IdValPairPtr_release(param_ptr);
    }
    {
        BSLB_IdValPairPtr_t *param_ptr = BSLB_IdValPairPtr_new();
        BSL_IdValPair_t     *param     = BSLB_IdValPairPtr_ref(param_ptr);

        BSL_IdValPair_SetBytestr(param, BSLX_COSEMSG_HDR_KID, ctx->kid);

        BSLX_CoseMsg_HdrMapTree_set_at(recip->headers.uhdr, param->id, param_ptr);
        BSLB_IdValPairPtr_release(param_ptr);
    }
    if (BSL_SUCCESS == ctx->status)
    {
        // optional partial IV depending on key Base IV
        BSLX_CoseSc_GenerateIV(ctx, &msg.headers);
    }

    if (BSL_SUCCESS == ctx->status)
    {
        BSLX_CoseSc_GenerateContentKey(ctx, recip);
    }

    BSLX_CoseMsg_Headers_DerivePhdr(&msg.headers);
    BSLX_CoseMsg_Headers_DerivePhdr(&recip->headers);

    if (BSL_SUCCESS == ctx->status)
    {
        BSLX_CoseSc_Encrypt_Compute(ctx, &msg.headers, "Encrypt", BSL_CRYPTO_ENCRYPT);
    }

    BSL_Data_t aad_scope_enc;
    BSL_Data_Init(&aad_scope_enc);
    if (BSL_SUCCESS == ctx->status)
    {
        res = BSL_CBOR_Encode_Twopass(&aad_scope_enc, (BSL_CBOR_Encode_f)&BSLX_CoseSc_AadScope_Encode, &ctx->aad_scope);
        // GCOV_EXCL_START
        if (BSL_SUCCESS != res)
        {
            BSL_LOG_ERR("Failed to encode AAD Scope");
            ctx->status = res;
        }
        // GCOV_EXCL_STOP
    }
    BSL_Data_t msg_enc;
    BSL_Data_Init(&msg_enc);
    if (BSL_SUCCESS == ctx->status)
    {
        res = BSL_CBOR_Encode_Twopass(&msg_enc, (BSL_CBOR_Encode_f)&BSLX_CoseMsg_Encrypt_Encode, &msg);
        // GCOV_EXCL_START
        if (BSL_SUCCESS != res)
        {
            BSL_LOG_ERR("Failed to encode COSE_Encrypt");
            ctx->status = res;
        }
        // GCOV_EXCL_STOP
    }
    if (BSL_SUCCESS == ctx->status)
    {
        {
            BSL_IdValPair_t *param = BSL_SecOutcome_AppendParam(ctx->sec_outcome);
            BSL_IdValPair_SetRaw(param, BSLX_COSESC_PARAM_AAD_SCOPE, aad_scope_enc.ptr, aad_scope_enc.len);
        }
        {
            BSL_IdValPair_t *result = BSL_SecOutcome_AppendResult(ctx->sec_outcome);
            BSL_IdValPair_SetBytestr(result, BSLX_COSESC_RESULT_COSE_ENCRYPT, msg_enc);
        }
    }
    BSL_Data_Deinit(&msg_enc);
    BSL_Data_Deinit(&aad_scope_enc);

    BSLX_CoseMsg_Encrypt_Deinit(&msg);
}

/** Internal processing to verify a COSE_Encrypt message.
 */
static void BSLX_CoseSc_Encrypt_VerifyAccept(BSLX_CoseSc_t *ctx, const BSL_IdValPair_t *result)
{
    int res;

    BSLX_CoseSc_GetAndValidateAddlHeaders(ctx);
    BSLX_CoseSc_GetAndValidateAadScope(ctx);
    if (BSL_SUCCESS != ctx->status)
    {
        // early exit
        return;
    }

    BSLX_CoseMsg_Encrypt_t msg;
    BSLX_CoseMsg_Encrypt_Init(&msg);
    {
        BSL_Data_t msg_enc;
        BSL_Data_Init(&msg_enc);
        if (BSL_SUCCESS != BSL_IdValPair_GetAsBytestr(result, &msg_enc))
        {
            BSL_LOG_ERR("Failed to get encoded message");
            ctx->status = BSL_ERR_SECURITY_CONTEXT_CRYPTO_FAILED;
        }
        else
        {
            res = BSL_CBOR_Decode(&msg_enc, (BSL_CBOR_Decode_f)&BSLX_CoseMsg_Encrypt_Decode, &msg);
            if (BSL_SUCCESS != res)
            {
                BSL_LOG_ERR("Failed to decode COSE_Encrypt");
                ctx->status = BSL_ERR_SECURITY_CONTEXT_CRYPTO_FAILED;
            }
            else
            {
                if (BSL_SUCCESS != BSLX_CoseMsg_Headers_CheckCrit(&msg.headers))
                {
                    BSL_LOG_ERR("Failed crit header check");
                    ctx->status = BSL_ERR_SECURITY_CONTEXT_CRYPTO_FAILED;
                }
            }
        }
        BSL_Data_Deinit(&msg_enc);
    }
    if (BSL_SUCCESS != ctx->status)
    {
        return;
    }
    // synthesize additional headers
    BSLX_CoseMsg_HdrMapTree_update(msg.headers.uhdr, ctx->addl_phdr);
    BSLX_CoseMsg_HdrMapTree_update(msg.headers.uhdr, ctx->addl_uhdr);

    // key is from a recpient
    BSLX_CoseMsg_Recipient_t *recip = NULL;
    if (BSLX_CoseMsg_RecipientList_size(msg.recipients) != 1)
    {
        BSL_LOG_CRIT("Can only handle one recipient for now");
        ctx->status = BSL_ERR_SECURITY_CONTEXT_CRYPTO_FAILED;
    }
    else
    {
        recip = BSLX_CoseMsg_RecipientPtr_ref(*BSLX_CoseMsg_RecipientList_front(msg.recipients));
        BSLX_CoseSc_GetAndValidateKey(ctx, &recip->headers);
    }
    BSLX_CoseSc_GetAndValidateTarget(ctx, &msg.headers);

    // get content key from recipient
    if (BSL_SUCCESS == ctx->status)
    {
        switch (ctx->key_alg)
        {
            case BSLX_COSEMSG_ALG_AES_KW_128:
            case BSLX_COSEMSG_ALG_AES_KW_192:
            case BSLX_COSEMSG_ALG_AES_KW_256:
            {
                res = BSL_Crypto_UnwrapKey(ctx->keyhandle, &recip->ciphertext, &ctx->cekhandle);
                if (BSL_SUCCESS != res)
                {
                    BSL_LOG_ERR("Failed to wrap content key");
                    ctx->status = BSL_ERR_SECURITY_CONTEXT_CRYPTO_FAILED;
                }

                break;
            }
            case BSLX_COSEMSG_ALG_DIRECT_HKDF_SHA_256:
            case BSLX_COSEMSG_ALG_DIRECT_HKDF_SHA_512:
                BSL_LOG_CRIT("Not implemented");
                ctx->status = BSL_ERR_SECURITY_CONTEXT_FAILED;
                break;
            default:
                BSL_LOG_ERR("Unsupported recipient algorithm %" PRId64, ctx->key_alg);
                ctx->status = BSL_ERR_SECURITY_CONTEXT_FAILED;
                break;
        }
    }

    if (BSL_SUCCESS == ctx->status)
    {
        BSLX_CoseSc_ExtractIV(ctx, &msg.headers);
    }

    if (BSL_SUCCESS == ctx->status)
    {
        BSLX_CoseSc_Encrypt_Compute(ctx, &msg.headers, "Encrypt", BSL_CRYPTO_DECRYPT);
    }

    BSLX_CoseMsg_Encrypt_Deinit(&msg);
}

int BSLX_CoseSc_Execute(BSL_LibCtx_t *lib _U_, BSL_BundleRef_t *bundle, const BSL_SecOper_t *sec_oper, // NOSONAR
                        BSL_SecOutcome_t *sec_outcome)
{
    BSLX_CoseSc_t ctx;
    BSLX_CoseSc_Init(&ctx);
    BSLX_CoseSc_Prepare(&ctx, bundle, sec_oper, sec_outcome);

    if (BSL_SUCCESS == ctx.status)
    {
        BSLX_CoseSc_GetOptions(&ctx, sec_oper);
    }

    // add results
    if (BSL_SUCCESS == ctx.status)
    {
        if (ctx.is_source)
        {
            BSLX_CoseSc_GetAndValidateKey(&ctx, NULL);
            BSLX_CoseSc_GetAndValidateTarget(&ctx, NULL);

            if (ctx.key_alg != ctx.tgt_alg)
            {
                // has a recipient layer
                if (ctx.is_bib)
                {
                    BSLX_CoseSc_Mac_Source(&ctx);
                }
                else
                {
                    BSLX_CoseSc_Encrypt_Source(&ctx);
                }
            }
            else
            {
                // only one content layer
                if (ctx.is_bib)
                {
                    BSLX_CoseSc_Mac0_Source(&ctx);
                }
                else
                {
                    BSLX_CoseSc_Encrypt0_Source(&ctx);
                }
            }
        }
        else
        { // verify or accept
            size_t nresult = BSL_SecOper_ResultCount(ctx.sec_oper);
            if (1 != nresult)
            {
                BSL_LOG_ERR("Exactly one result must be present for this target, have %zu", nresult);
                ctx.status = BSL_ERR_SECURITY_CONTEXT_FAILED;
            }
            else
            {
                if (ctx.is_bib)
                {
                    const BSL_IdValPair_t *result_mac0 =
                        BSL_SecOper_FindResult(ctx.sec_oper, BSLX_COSESC_RESULT_COSE_MAC0);
                    const BSL_IdValPair_t *result_mac =
                        BSL_SecOper_FindResult(ctx.sec_oper, BSLX_COSESC_RESULT_COSE_MAC);
                    if (result_mac0)
                    {
                        BSLX_CoseSc_Mac0_VerifyAccept(&ctx, result_mac0);
                    }
                    else if (result_mac)
                    {
                        BSL_LOG_CRIT("Not implemented");
                        ctx.status = BSL_ERR_SECURITY_CONTEXT_FAILED;
                    }
                    else
                    {
                        BSL_LOG_ERR("Need either a COSE_Mac0 or COSE_Mac result");
                        ctx.status = BSL_ERR_SECURITY_CONTEXT_FAILED;
                    }
                }
                else
                {
                    const BSL_IdValPair_t *result_enc0 =
                        BSL_SecOper_FindResult(ctx.sec_oper, BSLX_COSESC_RESULT_COSE_ENCRYPT0);
                    const BSL_IdValPair_t *result_enc =
                        BSL_SecOper_FindResult(ctx.sec_oper, BSLX_COSESC_RESULT_COSE_ENCRYPT);
                    if (result_enc0)
                    {
                        BSLX_CoseSc_Encrypt0_VerifyAccept(&ctx, result_enc0);
                    }
                    else if (result_enc)
                    {
                        BSLX_CoseSc_Encrypt_VerifyAccept(&ctx, result_enc);
                    }
                    else
                    {
                        BSL_LOG_ERR("Need either a COSE_Encrypt0 or COSE_Encrypt result");
                        ctx.status = BSL_ERR_SECURITY_CONTEXT_FAILED;
                    }
                }
            }
        }
    }

    int ret = ctx.status;
    BSLX_CoseSc_Deinit(&ctx);
    return ret;
}
