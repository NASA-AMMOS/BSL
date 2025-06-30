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
 * Definitions for bundle and block encoding.
 * @ingroup mock_bpa
 */
#include <BundleContext.h>
#include "bsl_mock_bpa_encode.h"
#include "bsl_mock_bpa_crc.h"
#include <Logging.h>
#include <TypeDefintions.h>

int bsl_mock_encode_eid(QCBOREncodeContext *enc, const BSL_HostEID_t *eid)
{
    bsl_mock_eid_t *obj = (bsl_mock_eid_t *)eid->handle;
    CHKERR1(obj);

    QCBOREncode_OpenArray(enc);

    QCBOREncode_AddUInt64(enc, obj->scheme);
    switch (obj->scheme)
    {
        case BSL_MOCK_EID_IPN:
        {
            const bsl_eid_ipn_ssp_t *ipn = &(obj->ssp.as_ipn);
            QCBOREncode_OpenArray(enc);
            switch (ipn->ncomp)
            {
                case 2:
                    QCBOREncode_AddUInt64(enc, (ipn->auth_num << 32) | ipn->node_num);
                    QCBOREncode_AddUInt64(enc, ipn->svc_num);
                    break;
                case 3:
                    QCBOREncode_AddUInt64(enc, ipn->auth_num);
                    QCBOREncode_AddUInt64(enc, ipn->node_num);
                    QCBOREncode_AddUInt64(enc, ipn->svc_num);
                    break;
                default:
                    // nothing to really do here
                    break;
            }
            QCBOREncode_CloseArray(enc);
            break;
        }
        default:
        {
            const BSL_Data_t *raw = &(obj->ssp.as_raw);
            QCBOREncode_AddEncoded(enc, (UsefulBufC) { raw->ptr, raw->len });
            break;
        }
    }

    QCBOREncode_CloseArray(enc);
    return 0;
}

static const uint8_t zero_crc[] = { 0, 0, 0, 0 };

int bsl_mock_encode_primary(QCBOREncodeContext *enc, const BSL_BundlePrimaryBlock_t *blk)
{
    const size_t begin = QCBOREncode_Tell(enc);
    QCBOREncode_OpenArray(enc);

    QCBOREncode_AddUInt64(enc, blk->version);
    QCBOREncode_AddUInt64(enc, blk->flags);
    QCBOREncode_AddUInt64(enc, blk->crc_type);

    bsl_mock_encode_eid(enc, &(blk->dest_eid));
    bsl_mock_encode_eid(enc, &(blk->src_node_id));
    bsl_mock_encode_eid(enc, &(blk->report_to_eid));

    QCBOREncode_OpenArray(enc);
    QCBOREncode_AddUInt64(enc, blk->timestamp.bundle_creation_time);
    QCBOREncode_AddUInt64(enc, blk->timestamp.seq_num);
    QCBOREncode_CloseArray(enc);

    QCBOREncode_AddUInt64(enc, blk->lifetime);

    if (blk->flags & BSL_BUNDLE_IS_FRAGMENT)
    {
        QCBOREncode_AddUInt64(enc, blk->frag_offset);
        QCBOREncode_AddUInt64(enc, blk->adu_length);
    }

    switch (blk->crc_type)
    {
        case BSL_BUNDLECRCTYPE_16:
            QCBOREncode_AddBytes(enc, (UsefulBufC) { zero_crc, 2 });
            break;
        case BSL_BUNDLECRCTYPE_32:
            QCBOREncode_AddBytes(enc, (UsefulBufC) { zero_crc, 4 });
            break;
        default:
            // nothing
            break;
    }

    QCBOREncode_CloseArray(enc);
    const size_t end = QCBOREncode_Tell(enc);

    mock_bpa_crc_apply(QCBOREncode_RetrieveOutputStorage(enc), begin, end, blk->crc_type);

    return 0;
}

int bsl_mock_encode_canonical(QCBOREncodeContext *enc, const BSL_BundleBlock_t *blk)
{
    const size_t begin = QCBOREncode_Tell(enc);
    QCBOREncode_OpenArray(enc);

    QCBOREncode_AddUInt64(enc, blk->blk_type);
    QCBOREncode_AddUInt64(enc, blk->blk_num);
    QCBOREncode_AddUInt64(enc, blk->flags);
    QCBOREncode_AddUInt64(enc, blk->crc_type);

    QCBOREncode_AddBytes(enc, (UsefulBufC) { blk->btsd.ptr, blk->btsd.len });

    switch (blk->crc_type)
    {
        case BSL_BUNDLECRCTYPE_16:
            QCBOREncode_AddBytes(enc, (UsefulBufC) { zero_crc, 2 });
            break;
        case BSL_BUNDLECRCTYPE_32:
            QCBOREncode_AddBytes(enc, (UsefulBufC) { zero_crc, 4 });
            break;
        default:
            // nothing
            break;
    }

    QCBOREncode_CloseArray(enc);
    const size_t end = QCBOREncode_Tell(enc);

    mock_bpa_crc_apply(QCBOREncode_RetrieveOutputStorage(enc), begin, end, blk->crc_type);

    return 0;
}

// TODO(bvb,brian?) - Ensure deterministic encoding of blocks persuant to RFC9171 rules
static int _cmp(const void *a, const void *b)
{
    // Be careful! This dereferencing took a long time to figure out!
    // Note, when calling qsort, size must be sizeof(BSL_BundleBlock_t*)
    const BSL_BundleBlock_t * block_a = *(const BSL_BundleBlock_t * const *)a;
    const BSL_BundleBlock_t * block_b = *(const BSL_BundleBlock_t * const *)b;
    return block_b->blk_type - block_a->blk_type;
}

int bsl_mock_encode_bundle(QCBOREncodeContext *enc, const BSL_BundleCtx_t *bundle)
{
    QCBOREncode_OpenArrayIndefiniteLength(enc);

    bsl_mock_encode_primary(enc, BSL_BundleCtx_CGetPrimaryBlock(bundle));

    const BSL_BundleBlock_t *block_ref_array [40] = { 0 };
    size_t block_id_nitems = 0;

    // Direct access using the dynamic backend
    // Note, This is a little akward, but..
    // We need to get all the block id's and encode them in ascending order
    BSL_BundleBlockList_it_t it;
    for (BSL_BundleBlockList_it(it, bundle->blks); !BSL_BundleBlockList_end_p(it); BSL_BundleBlockList_next(it))
    {
        const BSL_BundleBlock_t *info = BSL_BundleBlockList_cref(it);
        block_ref_array[block_id_nitems++] = info;
    }
    
    // Sort so that payload block comes at the end/
    // BCB > BIB > exts > Payload
    qsort(block_ref_array, block_id_nitems, sizeof(const BSL_BundleBlock_t *), _cmp);

    // Encode according to the above order.
    for (size_t index=0; index<block_id_nitems; index++)
    {
        const BSL_BundleBlock_t *info = block_ref_array[index];
        bsl_mock_encode_canonical(enc, info);
    }

    QCBOREncode_CloseArrayIndefiniteLength(enc);
    return 0;
}
