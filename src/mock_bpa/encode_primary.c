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
#include "encode_primary.h"

// TODO this function needs return checking / err handling
static int encode_EID(bsl_eid_h eid, QCBOREncodeContext *eid_encode)
{
    QCBOREncode_OpenArray(eid_encode);

    // TODO get eid specific data
    (void)eid;

    // For now, dummy data
    uint64_t eid_scheme_name = 1;
    char     eid_SSP[]       = "test";

    QCBOREncode_AddUInt64(eid_encode, eid_scheme_name);

    if (!strcmp("none", eid_SSP))
    {
        QCBOREncode_AddUInt64(eid_encode, 0);
    }
    else
    {
        QCBOREncode_AddText(eid_encode, UsefulBuf_FROM_SZ_LITERAL(eid_SSP));
    }

    QCBOREncode_CloseArray(eid_encode);

    return 0;
}

int bsl_bundle_ctx_prim_blk_encode(const BSL_BundlePrimaryBlock_t *prim_blk, UsefulBuf buf, UsefulBufC crc,
                                   UsefulBufC *out)
{
    QCBOREncodeContext prim_encode;

    QCBOREncode_Init(&prim_encode, buf);
    QCBOREncode_OpenArray(&prim_encode);
    QCBOREncode_AddUInt64(&prim_encode, prim_blk->version);
    QCBOREncode_AddUInt64(&prim_encode, prim_blk->flags);
    QCBOREncode_AddUInt64(&prim_encode, prim_blk->crc_type);

    encode_EID(prim_blk->dest_eid, &prim_encode);
    encode_EID(prim_blk->src_node_id, &prim_encode);
    encode_EID(prim_blk->report_to_eid, &prim_encode);

    QCBOREncode_OpenArray(&prim_encode);
    QCBOREncode_AddUInt64(&prim_encode, prim_blk->timestamp.bundle_creation_time);
    QCBOREncode_AddUInt64(&prim_encode, prim_blk->timestamp.seq_num);
    QCBOREncode_CloseArray(&prim_encode);

    QCBOREncode_AddUInt64(&prim_encode, prim_blk->lifetime);

    if (prim_blk->frag_offset)
    {
        QCBOREncode_AddUInt64(&prim_encode, prim_blk->frag_offset);
    }
    if (prim_blk->adu_length)
    {
        QCBOREncode_AddUInt64(&prim_encode, prim_blk->adu_length);
    }
    if (prim_blk->crc_type == 1 || prim_blk->crc_type == 2)
    {
        QCBOREncode_AddBytes(&prim_encode, crc);
    }

    QCBOREncode_CloseArray(&prim_encode);
    QCBORError err = QCBOREncode_Finish(&prim_encode, out);
    if (err != QCBOR_SUCCESS)
    {
        BSL_LOG_WARNING("Primary Block Encoding Error %" PRIu32 " (%s)", err, qcbor_err_to_str(err));
        return 0;
    }

    return 1;
}
