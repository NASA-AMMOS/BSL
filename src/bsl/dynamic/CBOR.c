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
 * @ingroup backend_dyn
 * @brief Definition of CBOR CODEC wrapper functions.
 */
#include "CBOR.h"
#include "bsl/front/TextUtil.h"
#include "bsl/BPSecLib_Private.h"
#include <m-core.h>

int BSL_CBOR_Encode_GetSize(size_t *needlen, BSL_CBOR_Encode_f func, const void *obj)
{
    ASSERT_ARG_NONNULL(needlen);
    ASSERT_ARG_NONNULL(func);

    QCBOREncodeContext encoder;
    QCBOREncode_Init(&encoder, SizeCalculateUsefulBuf);

    int res = func(&encoder, obj);
    if (BSL_SUCCESS != res)
    {
        return res;
    }

    // get used size
    QCBORError qcbor_err = QCBOREncode_FinishGetSize(&encoder, needlen);
    if (qcbor_err != QCBOR_SUCCESS)
    {
        BSL_LOG_ERR("CBOR pre-encoding failed: %s", qcbor_err_to_str(qcbor_err));
        return BSL_ERR_ENCODING;
    }
    BSL_LOG_DEBUG("CBOR pre-encoded size: %zu", *needlen);
    return BSL_SUCCESS;
}

int BSL_CBOR_Encode_Twopass(BSL_Data_t *buf, BSL_CBOR_Encode_f func, const void *obj)
{
    ASSERT_ARG_NONNULL(buf);
    ASSERT_ARG_NONNULL(func);

    int    res;
    size_t need_size;

    QCBOREncodeContext encoder;
    {
        // Get the needed size first with a special buffer
        QCBOREncode_Init(&encoder, SizeCalculateUsefulBuf);

        res = func(&encoder, obj);
        if (BSL_SUCCESS != res)
        {
            return res;
        }

        // get used size
        QCBORError qcbor_err = QCBOREncode_FinishGetSize(&encoder, &need_size);
        if (qcbor_err != QCBOR_SUCCESS)
        {
            BSL_LOG_ERR("CBOR pre-encoding failed: %s", qcbor_err_to_str(qcbor_err));
            return BSL_ERR_ENCODING;
        }
        BSL_LOG_DEBUG("CBOR pre-encoded size: %zu", need_size);
    }

    // fit the buffer
    res = BSL_Data_Resize(buf, need_size);
    if (BSL_SUCCESS != res)
    {
        BSL_LOG_ERR("buffer allocation failed");
        return res;
    }

    {
        // Now actually encode
        QCBOREncode_Init(&encoder, UsefulBuf_FROM_BSL_Data(*buf));

        res = func(&encoder, obj);
        if (BSL_SUCCESS != res)
        {
            return res;
        }

        size_t     used_size;
        QCBORError qcbor_err = QCBOREncode_FinishGetSize(&encoder, &used_size);
        if (qcbor_err != QCBOR_SUCCESS)
        {
            BSL_LOG_ERR("CBOR encoding failed: %s", qcbor_err_to_str(qcbor_err));
            return BSL_ERR_ENCODING;
        }
        BSL_LOG_DEBUG("CBOR encoded size: %zu", used_size);
    }

    BSL_LOG_PLAINTEXT_PTR("CBOR data", obj, buf->ptr, buf->len);
    return BSL_SUCCESS;
}

int BSL_CBOR_Decode(const BSL_Data_t *buf, BSL_CBOR_Decode_f func, const void *obj)
{
    ASSERT_ARG_NONNULL(buf);
    ASSERT_ARG_NONNULL(func);

    BSL_LOG_PLAINTEXT_PTR("CBOR data", obj, buf->ptr, buf->len);

    QCBORDecodeContext decoder;
    QCBORDecode_Init(&decoder, UsefulBufC_FROM_BSL_Data(*buf), QCBOR_DECODE_MODE_MAP_AS_ARRAY);

    int res = func(&decoder, obj);
    if (BSL_SUCCESS != res)
    {
        return res;
    }

    QCBORError err = QCBORDecode_Finish(&decoder);
    if (QCBOR_SUCCESS != err)
    {
        BSL_LOG_ERR("CBOR decoding error %d (%s)", err, qcbor_err_to_str(err));
        return BSL_ERR_DECODING;
    }

    return BSL_SUCCESS;
}

int BSL_CBOR_Compare_Int64(const int64_t *ltv, const int64_t *rtv)
{
    ASSERT_ARG_NONNULL(ltv);
    ASSERT_ARG_NONNULL(rtv);

    const int lt_major = (*ltv >= 0) ? 0 : 1;
    const int rt_major = (*rtv >= 0) ? 0 : 1;

    int res = M_CMP_BASIC(lt_major, rt_major);
    if (res)
    {
        return res;
    }
    // major types are the same
    if (lt_major == 0)
    {
        // more positive ascending
        return M_CMP_BASIC(*ltv, *rtv);
    }
    else
    {
        // more negative ascending
        return -M_CMP_BASIC(*ltv, *rtv);
    }
}

int BSL_CBOR_EncodeEID(QCBOREncodeContext *enc, const BSL_HostEID_t *eid)
{
    int res;
    if (QCBOREncode_IsBufferNULL(enc))
    {
        size_t needlen;

        res = BSL_HostEID_EncodeToCBOR(eid, NULL, &needlen);
        if (res != BSL_SUCCESS)
        {
            BSL_LOG_ERR("Failed to encode EID");
            return BSL_ERR_ENCODING;
        }

        QCBOREncode_AddEncoded(enc, (UsefulBufC) { .ptr = NULL, .len = needlen });
    }
    else
    {
        BSL_Data_t eid_data;
        BSL_Data_Init(&eid_data);

        res = BSL_HostEID_EncodeToCBOR(eid, &eid_data, NULL);
        if (res != BSL_SUCCESS)
        {
            BSL_LOG_ERR("Failed to encode EID");
            return BSL_ERR_ENCODING;
        }

        QCBOREncode_AddEncoded(enc, UsefulBufC_FROM_BSL_Data(eid_data));
        BSL_Data_Deinit(&eid_data);
    }

    return BSL_SUCCESS;
}
