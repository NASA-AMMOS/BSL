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
 * Definitions for bundle and block encoding.
 * @ingroup mock_bpa
 */
#include <BPSecLib_Private.h>

#include "encode.h"
#include "agent.h"
#include "crc.h"

int bsl_mock_encode_eid(const BSL_HostEID_t *eid, BSL_Data_t *encoded_bytes)
{
    bsl_mock_eid_t *obj = (bsl_mock_eid_t *)eid->handle;
    CHKERR1(obj);

    QCBOREncodeContext enc;
    UsefulBuf qcbor_buf = encoded_bytes != NULL ? (UsefulBuf) { .ptr = encoded_bytes->ptr, .len = encoded_bytes->len }
                                                : SizeCalculateUsefulBuf;
    QCBOREncode_Init(&enc, qcbor_buf);

    QCBOREncode_OpenArray(&enc);

    QCBOREncode_AddUInt64(&enc, obj->scheme);
    switch (obj->scheme)
    {
        case BSL_MOCK_EID_IPN:
        {
            const bsl_eid_ipn_ssp_t *ipn = &(obj->ssp.as_ipn);
            QCBOREncode_OpenArray(&enc);
            switch (ipn->ncomp)
            {
                case 2:
                    QCBOREncode_AddUInt64(&enc, (ipn->auth_num << 32) | ipn->node_num);
                    QCBOREncode_AddUInt64(&enc, ipn->svc_num);
                    break;
                case 3:
                    QCBOREncode_AddUInt64(&enc, ipn->auth_num);
                    QCBOREncode_AddUInt64(&enc, ipn->node_num);
                    QCBOREncode_AddUInt64(&enc, ipn->svc_num);
                    break;
                default:
                    // nothing to really do here
                    break;
            }
            QCBOREncode_CloseArray(&enc);
            break;
        }
        default:
        {
            const BSL_Data_t *raw = &(obj->ssp.as_raw);
            QCBOREncode_AddEncoded(&enc, (UsefulBufC) { raw->ptr, raw->len });
            break;
        }
    }

    QCBOREncode_CloseArray(&enc);

    size_t     encode_sz;
    QCBORError qcbor_err = QCBOREncode_FinishGetSize(&enc, &encode_sz);
    if (qcbor_err != QCBOR_SUCCESS)
    {
        BSL_LOG_ERR("Encoding host eid FAIL: %s", qcbor_err_to_str(qcbor_err));
        return BSL_ERR_ENCODING;
    }
    BSL_LOG_DEBUG("QCBOR ENCODE SIZE: %zu", encode_sz);
    return (ssize_t)encode_sz;
}

int bsl_mock_encode_eid_from_ctx(QCBOREncodeContext *enc, const BSL_HostEID_t *eid)
{
    ssize_t encode_result = BSL_HostEID_EncodeToCBOR(eid, NULL);
    if (encode_result <= 0)
    {
        BSL_LOG_ERR("Failed to calculate EID size");
        return BSL_ERR_ENCODING;
    }

    BSL_Data_t eid_data;
    BSL_Data_InitBuffer(&eid_data, (size_t)encode_result);
    encode_result = BSL_HostEID_EncodeToCBOR(eid, &eid_data);
    if (encode_result <= BSL_SUCCESS)
    {
        BSL_LOG_ERR("Failed to encode EID");
        return BSL_ERR_ENCODING;
    }

    UsefulBufC eid_buf = (UsefulBufC) { .ptr = eid_data.ptr, .len = eid_data.len };
    QCBOREncode_AddEncoded(enc, eid_buf);

    BSL_Data_Deinit(&eid_data);
    return 0;
}

static const uint8_t zero_crc[] = { 0, 0, 0, 0 };

int bsl_mock_encode_primary(QCBOREncodeContext *enc, const MockBPA_PrimaryBlock_t *blk)
{
    const size_t begin = QCBOREncode_Tell(enc);
    QCBOREncode_OpenArray(enc);

    QCBOREncode_AddUInt64(enc, blk->version);
    QCBOREncode_AddUInt64(enc, blk->flags);
    QCBOREncode_AddUInt64(enc, blk->crc_type);

    bsl_mock_encode_eid_from_ctx(enc, &(blk->dest_eid));
    bsl_mock_encode_eid_from_ctx(enc, &(blk->src_node_id));
    bsl_mock_encode_eid_from_ctx(enc, &(blk->report_to_eid));

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

int bsl_mock_encode_canonical(QCBOREncodeContext *enc, const MockBPA_CanonicalBlock_t *blk)
{
    const size_t begin = QCBOREncode_Tell(enc);
    QCBOREncode_OpenArray(enc);

    QCBOREncode_AddUInt64(enc, blk->blk_type);
    QCBOREncode_AddUInt64(enc, blk->blk_num);
    QCBOREncode_AddUInt64(enc, blk->flags);
    QCBOREncode_AddUInt64(enc, blk->crc_type);
    QCBOREncode_AddBytes(enc, (UsefulBufC) { blk->btsd, blk->btsd_len });

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

int bsl_mock_encode_bundle(QCBOREncodeContext *enc, const MockBPA_Bundle_t *bundle)
{
    QCBOREncode_OpenArrayIndefiniteLength(enc);

    bsl_mock_encode_primary(enc, &bundle->primary_block);

    // Encode according to the existing order
    MockBPA_BlockList_it_t bit;
    for (MockBPA_BlockList_it(bit, bundle->blocks); !MockBPA_BlockList_end_p(bit); MockBPA_BlockList_next(bit))
    {
        const MockBPA_CanonicalBlock_t *blk = MockBPA_BlockList_cref(bit);
        bsl_mock_encode_canonical(enc, blk);
    }

    QCBOREncode_CloseArrayIndefiniteLength(enc);
    return 0;
}
