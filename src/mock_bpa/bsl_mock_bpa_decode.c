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
 * Definitions for bundle and block decoding.
 * @ingroup mock_bpa
 */
#include "bsl_mock_bpa_decode.h"
#include "bsl_mock_bpa_crc.h"
#include "Logging.h"
#include <TypeDefintions.h>
#include <qcbor/qcbor_spiffy_decode.h>

int bsl_mock_decode_eid(QCBORDecodeContext *dec, BSL_HostEID_t *eid)
{
    assert(dec != NULL);
    assert(eid != NULL);
    assert(eid->handle != NULL);
    bsl_mock_eid_t *obj = (bsl_mock_eid_t *)eid->handle;
    assert(obj != NULL);
    CHKERR1(dec);
    CHKERR1(obj);

    bsl_mock_eid_deinit(obj);
    bsl_mock_eid_init(obj);

    QCBORItem decitem;
    QCBORDecode_EnterArray(dec, NULL);

    QCBORDecode_GetUInt64(dec, &(obj->scheme));
    if (QCBOR_SUCCESS != QCBORDecode_GetError(dec))
    {
        return 2;
    }

    switch (obj->scheme)
    {
        case BSL_MOCK_EID_IPN:
        {
            bsl_eid_ipn_ssp_t *ipn = &(obj->ssp.as_ipn);
            assert(ipn != NULL);
            QCBORDecode_EnterArray(dec, &decitem);
            if (decitem.val.uCount == 2)
            {
                ipn->ncomp = 2;
                uint64_t qnode;
                QCBORDecode_GetUInt64(dec, &qnode);
                ipn->auth_num = qnode >> 32;
                ipn->node_num = qnode & 0xFFFFFFFF;
                QCBORDecode_GetUInt64(dec, &(ipn->svc_num));
            }
            else if (decitem.val.uCount == 3)
            {
                ipn->ncomp = 3;
                QCBORDecode_GetUInt64(dec, &(ipn->auth_num));
                QCBORDecode_GetUInt64(dec, &(ipn->node_num));
                QCBORDecode_GetUInt64(dec, &(ipn->svc_num));

                if ((ipn->auth_num > UINT32_MAX) || (ipn->node_num > UINT32_MAX))
                {
                    // parts larger than allowed
                    return 4;
                }
            }
            else
            {
                return 2;
            }
            QCBORDecode_ExitArray(dec);
            break;
        }
        default:
        {
            // skip over item and store its encoded form
            const size_t begin = QCBORDecode_Tell(dec);
            QCBORDecode_VGetNextConsume(dec, &decitem);
            const size_t end = QCBORDecode_Tell(dec);
            if (end > begin)
            {
                BSL_Data_t *raw = &(obj->ssp.as_raw);
                assert(raw != NULL);
                BSL_Data_Init(raw);
                // FIXME expose this from the decoder
                BSL_Data_CopyFrom(raw, end - begin, (uint8_t *)dec->InBuf.UB.ptr + begin);
            }
            break;
        }
    }

    QCBORDecode_ExitArray(dec);
    return 0;
}

int bsl_mock_decode_primary(QCBORDecodeContext *dec, BSL_BundlePrimaryBlock_t *blk)
{
    CHKERR1(dec);
    CHKERR1(blk);

    const size_t begin = QCBORDecode_Tell(dec);
    QCBORDecode_EnterArray(dec, NULL);

    QCBORDecode_GetUInt64(dec, &(blk->version));
    if ((QCBOR_SUCCESS != QCBORDecode_GetError(dec)) || (blk->version != 7))
    {
        return 2;
    }

    QCBORDecode_GetUInt64(dec, &(blk->flags));
    QCBORDecode_GetUInt64(dec, &(blk->crc_type));

    bsl_mock_decode_eid(dec, &(blk->dest_eid));
    bsl_mock_decode_eid(dec, &(blk->src_node_id));
    bsl_mock_decode_eid(dec, &(blk->report_to_eid));

    QCBORDecode_EnterArray(dec, NULL);
    QCBORDecode_GetUInt64(dec, &(blk->timestamp.bundle_creation_time));
    QCBORDecode_GetUInt64(dec, &(blk->timestamp.seq_num));
    QCBORDecode_ExitArray(dec);

    QCBORDecode_GetUInt64(dec, &(blk->lifetime));

    if (blk->flags & BSL_BUNDLE_IS_FRAGMENT)
    {
        QCBORDecode_GetUInt64(dec, &(blk->frag_offset));
        QCBORDecode_GetUInt64(dec, &(blk->adu_length));
    }
    else
    {
        blk->frag_offset = blk->adu_length = 0;
    }

    UsefulBufC view;
    switch (blk->crc_type)
    {
        case BSL_BUNDLECRCTYPE_16:
        case BSL_BUNDLECRCTYPE_32:
            // just ignore the bytes
            QCBORDecode_GetByteString(dec, &view);
            break;
        default:
            // nothing
            break;
    }

    QCBORDecode_ExitArray(dec);
    const size_t end = QCBORDecode_Tell(dec);

    if (!mock_bpa_crc_check(QCBORDecode_RetrieveUndecodedInput(dec), begin, end, blk->crc_type))
    {
        return 4;
    }

    return 0;
}

int bsl_mock_decode_canonical(QCBORDecodeContext *dec, BSL_BundleBlock_t *blk)
{
    CHKERR1(dec);
    CHKERR1(blk);

    const size_t begin = QCBORDecode_Tell(dec);
    QCBORDecode_EnterArray(dec, NULL);

    QCBORDecode_GetUInt64(dec, &(blk->blk_type));
    QCBORDecode_GetUInt64(dec, &(blk->blk_num));
    QCBORDecode_GetUInt64(dec, &(blk->flags));
    QCBORDecode_GetUInt64(dec, &(blk->crc_type));

    UsefulBufC view;
    QCBORDecode_GetByteString(dec, &view);
    if (QCBOR_SUCCESS == QCBORDecode_GetError(dec))
    {
        BSL_Data_CopyFrom(&(blk->btsd), view.len, view.ptr);
    }

    switch (blk->crc_type)
    {
        case BSL_BUNDLECRCTYPE_16:
        case BSL_BUNDLECRCTYPE_32:
            // just ignore the bytes
            QCBORDecode_GetByteString(dec, &view);
            break;
        default:
            // nothing
            break;
    }

    QCBORDecode_ExitArray(dec);
    const size_t end = QCBORDecode_Tell(dec);

    if (!mock_bpa_crc_check(QCBORDecode_RetrieveUndecodedInput(dec), begin, end, blk->crc_type))
    {
        return 4;
    }

    return 0;
}

int bsl_mock_decode_bundle(QCBORDecodeContext *dec, BSL_BundleCtx_t *bundle)
{
    CHKERR1(dec);
    CHKERR1(bundle);

    QCBORItem decitem;
    QCBORDecode_EnterArray(dec, &decitem);
    if (decitem.val.uCount != QCBOR_COUNT_INDICATES_INDEFINITE_LENGTH)
    {
        // FIXME warn but still process
    }

    if (bsl_mock_decode_primary(dec, &(bundle->prim_blk)))
    {
        return 2;
    }

    // iterate until failure of CBOR, not block decoder
    while (QCBOR_SUCCESS == QCBORDecode_PeekNext(dec, &decitem))
    {
        BSL_BundleBlock_t blk;
        BSL_BundleBlock_Init(&blk);
        int parse_res = bsl_mock_decode_canonical(dec, &blk);
        if (parse_res)
        {
            return 3;
        }

        uint64_t blk_num = blk.blk_num;
        // state is taken by the bundle
        BSL_BundleBlockList_push_move(bundle->blks, &blk);

        const size_t blk_list_len = BSL_BundleBlockList_size(bundle->blks);
        BSL_BundleBlock_t *found;
        size_t i;
        for (i = 0; i < blk_list_len; i++)
        {
            found = BSL_BundleBlockList_get(bundle->blks, i);
            if (found != NULL && (found->blk_num == blk_num))
            {
                break;
            }
        }

        BSL_BundleBlockIdMap_set_at(bundle->blk_num, blk_num, found);

    }

    QCBORDecode_ExitArray(dec);
    return 0;
}

#if 0

int bsl_mock_encode_bundle(QCBOREncodeContext *enc, const BSL_BundleCtx_t *bundle)
{
    static uint8_t indef_head[] = { 0x9F };
    static uint8_t indef_tail[] = { 0xFF };

    // don't use QCBOR write-back for indefinite array
    QCBOREncode_AddEncoded(enc, UsefulBuf_FROM_BYTE_ARRAY_LITERAL(indef_head));

    UsefulBufC crc_buf = {NULL, 0};             //TODO dummy crc

    bsl_mock_encode_primary(enc, BSL_BundleCtx_CGetPrimaryBlock(bundle), crc_buf);

    // Direct access using the dynamic backend
    BSL_BundleBlockList_it_t it;
    for (BSL_BundleBlockList_it(it, bundle->blks); !BSL_BundleBlockList_end_p(it); BSL_BundleBlockList_next(it))
    {
        const BSL_BundleBlock_t *info = BSL_BundleBlockList_cref(it);
        bsl_mock_encode_canonical(enc, info, crc_buf);
    }

    QCBOREncode_AddEncoded(enc, UsefulBuf_FROM_BYTE_ARRAY_LITERAL(indef_tail));
    return 0;
}
#endif
