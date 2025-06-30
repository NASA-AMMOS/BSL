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
#include "mock_bpa_ctr.h"
#include "bsl_mock_bpa_decode.h"
#include "bsl_mock_bpa_encode.h"
#include <Logging.h>
#include <TypeDefintions.h>

static const size_t SMALLBUF_SIZE = 1024;

void mock_bpa_ctr_init(mock_bpa_ctr_t *ctr)
{
    CHKVOID(ctr);
    BSL_Data_Init(&(ctr->encoded));
    ctr->bundle = NULL;
}

void mock_bpa_ctr_init_move(mock_bpa_ctr_t *ctr, mock_bpa_ctr_t *src)
{
    CHKVOID(ctr);
    CHKVOID(src);
    BSL_Data_InitMove(&(ctr->encoded), &(src->encoded));
    ctr->bundle = src->bundle;
    src->bundle = NULL;
}

void mock_bpa_ctr_deinit(mock_bpa_ctr_t *ctr)
{
    CHKVOID(ctr);
    BSL_Data_Deinit(&(ctr->encoded));

    if (ctr->bundle)
    {
        BSL_BundleCtx_Deinit(ctr->bundle);
        M_MEMORY_DEL(ctr->bundle);
    }
}

int mock_bpa_decode(mock_bpa_ctr_t *ctr, BSL_LibCtx_t *bsl)
{
    CHKERR1(ctr);
    if (ctr->bundle)
    {
        BSL_BundleCtx_Deinit(ctr->bundle);
    }
    else
    {
        ctr->bundle = M_MEMORY_ALLOC(BSL_BundleCtx_t);
    }
    BSL_BundleCtx_Init(ctr->bundle, bsl);

    QCBORDecodeContext decoder;
    QCBORDecode_Init(&decoder, (UsefulBufC) { ctr->encoded.ptr, ctr->encoded.len }, QCBOR_DECODE_MODE_NORMAL);
    if (bsl_mock_decode_bundle(&decoder, ctr->bundle))
    {
        return 2;
    }
    if (QCBORDecode_Finish(&decoder))
    {
        return 3;
    }

    string_t src, dst;
    string_init(src);
    BSL_HostEID_EncodeToText(src, &(ctr->bundle->prim_blk.src_node_id));
    string_init(dst);
    BSL_HostEID_EncodeToText(dst, &(ctr->bundle->prim_blk.dest_eid));
    BSL_LOG_INFO("Decoded bundle from %s to %s", string_get_cstr(src), string_get_cstr(dst));
    string_clear(src);
    string_clear(dst);

    return 0;
}

int mock_bpa_encode(mock_bpa_ctr_t *ctr)
{
    CHKERR1(ctr);
    CHKERR1(ctr->bundle);

    QCBOREncodeContext encoder;

    // assume some small size and expand if necessary
    uint8_t smallbuf[SMALLBUF_SIZE];
    QCBOREncode_Init(&encoder, (UsefulBuf) { smallbuf, sizeof(smallbuf) });
    if (bsl_mock_encode_bundle(&encoder, ctr->bundle))
    {
        return 2;
    }
    size_t needlen;
    if (QCBOR_SUCCESS != QCBOREncode_FinishGetSize(&encoder, &needlen))
    {
        return 3;
    }

    if (needlen < SMALLBUF_SIZE)
    {
        if (BSL_Data_CopyFrom(&(ctr->encoded), needlen, smallbuf))
        {
            return 4;
        }
    }
    else
    {
        if (BSL_Data_Resize(&(ctr->encoded), needlen))
        {
            return 4;
        }
        QCBOREncode_Init(&encoder, (UsefulBuf) { ctr->encoded.ptr, ctr->encoded.len });
        if (bsl_mock_encode_bundle(&encoder, ctr->bundle))
        {
            return 2;
        }
        UsefulBufC final;
        if (QCBOR_SUCCESS != QCBOREncode_Finish(&encoder, &final))
        {
            return 3;
        }
    }

    BSL_LOG_INFO("Encoded bundle");

    return 0;
}
