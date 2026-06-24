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
 * Implementation of COSE structures @cite rfc9052.
 */

#include <BPSecLib_Private.h>
#include <backend/CBOR.h>

#include "CoseMsg.h"

void BSLX_CoseMsg_Mac0_Init(BSLX_CoseMsg_Mac0_t *obj)
{
    ASSERT_ARG_NONNULL(obj);
    memset(obj, 0, sizeof(*obj));
    BSL_Data_Init(&obj->phdr_bstr);
    BSLX_CoseMsg_HdrMapTree_init(obj->phdr);
    BSLX_CoseMsg_HdrMapTree_init(obj->uhdr);
    BSL_Data_Init(&obj->tag);
}

void BSLX_CoseMsg_Mac0_Deinit(BSLX_CoseMsg_Mac0_t *obj)
{
    ASSERT_ARG_NONNULL(obj);
    BSL_Data_Deinit(&obj->tag);
    BSLX_CoseMsg_HdrMapTree_clear(obj->uhdr);
    BSLX_CoseMsg_HdrMapTree_clear(obj->phdr);
    BSL_Data_Deinit(&obj->phdr_bstr);
    memset(obj, 0, sizeof(*obj));
}

/// Match ::BSL_CBOR_Encode_f signature.
static int BSLX_CoseMsg_DerivePhdr(QCBOREncodeContext *enc, const BSLX_CoseMsg_HdrMapTree_t *map)
{
    QCBOREncode_OpenMap(enc);

    BSLX_CoseMsg_HdrMapTree_it_t param_it;
    for (BSLX_CoseMsg_HdrMapTree_it(param_it, *map); !BSLX_CoseMsg_HdrMapTree_end_p(param_it);
         BSLX_CoseMsg_HdrMapTree_next(param_it))
    {
        const BSL_IdValPair_t *param = BSLB_IdValPairPtr_cref(*(BSLX_CoseMsg_HdrMapTree_ref(param_it)->value_ptr));
        BSL_IdValPair_Encode(enc, param);
    }

    QCBOREncode_CloseMap(enc);
    return BSL_SUCCESS;
}

int BSLX_CoseMsg_Mac0_DerivePhdr(BSLX_CoseMsg_Mac0_t *obj)
{
    if (BSLX_CoseMsg_HdrMapTree_empty_p(obj->phdr))
    {
        BSL_Data_Resize(&obj->phdr_bstr, 0);
        return BSL_SUCCESS;
    }
    return BSL_CBOR_Encode_Twopass(&obj->phdr_bstr, (BSL_CBOR_Encode_f)&BSLX_CoseMsg_DerivePhdr, &obj->phdr);
}

int BSLX_CoseMsg_Mac0_Encode(QCBOREncodeContext *enc, const BSLX_CoseMsg_Mac0_t *obj)
{
    QCBOREncode_OpenArray(enc);

    // protected map data
    QCBOREncode_AddBytes(enc, UsefulBufC_FROM_BSL_Data(obj->phdr_bstr));
    // unprotected map
    BSLX_CoseMsg_DerivePhdr(enc, &obj->uhdr);
    // detached payload
    QCBOREncode_AddNULL(enc);
    // MAC tag
    QCBOREncode_AddBytes(enc, UsefulBufC_FROM_BSL_Data(obj->tag));

    QCBOREncode_CloseArray(enc);
    return BSL_SUCCESS;
}

int BSLX_CoseMsg_Mac0_Decode(QCBORDecodeContext *dec, BSLX_CoseMsg_Mac0_t *obj)
{
    QCBORDecode_EnterArray(dec, NULL);

    {
        // protected map bytes
        UsefulBufC phdr_content;
        QCBORDecode_EnterBstrWrapped(dec, QCBOR_TAG_REQUIREMENT_NOT_A_TAG, &phdr_content);
        if (QCBOR_SUCCESS != QCBORDecode_GetError(dec))
        {
            BSL_LOG_ERR("Protected header bstr error");
            return BSL_ERR_DECODING;
        }

        if (phdr_content.len > 0)
        {
            QCBORDecode_EnterArray(dec, NULL); // Using QCBOR_DECODE_MODE_MAP_AS_ARRAY
            if (QCBOR_SUCCESS != QCBORDecode_GetError(dec))
            {
                BSL_LOG_ERR("Protected header map error");
                return BSL_ERR_DECODING;
            }

            QCBORItem item;
            while (QCBOR_SUCCESS == QCBORDecode_PeekNext(dec, &item))
            {
                BSLB_IdValPairPtr_t *param_ptr = BSLB_IdValPairPtr_new();

                BSL_IdValPair_t *param = BSLB_IdValPairPtr_ref(param_ptr);
                if (BSL_SUCCESS != BSL_IdValPair_Decode(dec, param))
                {
                    BSLB_IdValPairPtr_release(param_ptr);
                    return BSL_ERR_DECODING;
                }
                else
                {
                    BSLX_CoseMsg_HdrMapTree_set_at(obj->phdr, param->id, param_ptr);
                    BSLB_IdValPairPtr_release(param_ptr);
                }
            }

            QCBORDecode_ExitArray(dec);
        }
        BSL_LOG_DEBUG("Decoded %zu protected items", BSLX_CoseMsg_HdrMapTree_size(obj->phdr));
        // copy only after map success
        BSL_Data_CopyFrom(&obj->phdr_bstr, phdr_content.len, phdr_content.ptr);

        QCBORDecode_ExitBstrWrapped(dec);
    }
    {
        // unprotected map
        QCBORDecode_EnterArray(dec, NULL); // Using QCBOR_DECODE_MODE_MAP_AS_ARRAY
        if (QCBOR_SUCCESS != QCBORDecode_GetError(dec))
        {
            BSL_LOG_ERR("Unprotected header map error");
            return BSL_ERR_DECODING;
        }

        QCBORItem item;
        while (QCBOR_SUCCESS == QCBORDecode_PeekNext(dec, &item))
        {
            BSLB_IdValPairPtr_t *param_ptr = BSLB_IdValPairPtr_new();

            BSL_IdValPair_t *param = BSLB_IdValPairPtr_ref(param_ptr);
            if (BSL_SUCCESS != BSL_IdValPair_Decode(dec, param))
            {
                BSLB_IdValPairPtr_release(param_ptr);
                return BSL_ERR_DECODING;
            }
            else
            {
                BSLX_CoseMsg_HdrMapTree_set_at(obj->uhdr, param->id, param_ptr);
                BSLB_IdValPairPtr_release(param_ptr);
            }
        }

        QCBORDecode_ExitArray(dec);
        BSL_LOG_DEBUG("Decoded %zu unprotected items", BSLX_CoseMsg_HdrMapTree_size(obj->phdr));
    }
    // detached payload
    QCBORDecode_GetNull(dec);
    if (QCBOR_SUCCESS != QCBORDecode_GetAndResetError(dec))
    {
        BSL_LOG_ERR("COSE payload is not detached");
        return BSL_ERR_DECODING;
    }
    // MAC tag
    UsefulBufC view;
    QCBORDecode_GetByteString(dec, &view);
    if (QCBOR_SUCCESS != QCBORDecode_GetAndResetError(dec))
    {
        BSL_LOG_ERR("COSE Mac0 tag is invalid");
        return BSL_ERR_DECODING;
    }
    else
    {
        BSL_Data_CopyFrom(&obj->tag, view.len, view.ptr);
    }

    QCBORDecode_ExitArray(dec);
    return BSL_SUCCESS;
}

int BSLX_CoseMsg_Mac_Structure_Encode(QCBOREncodeContext *enc, const BSLX_CoseMsg_Mac_Structure_t *obj)
{
    ASSERT_PRECONDITION(obj->phdr_bstr);
    ASSERT_PRECONDITION(obj->external_aad);

    QCBOREncode_OpenArray(enc);
    // context
    QCBOREncode_AddText(enc, UsefulBuf_FromSZ("MAC0"));
    // protected
    QCBOREncode_AddBytes(enc, UsefulBufC_FROM_BSL_Data(*(obj->phdr_bstr)));
    // external_aad
    QCBOREncode_AddBytes(enc, UsefulBufC_FROM_BSL_Data(*(obj->external_aad)));
    // payload (head only)
    QCBOREncode_AddBytesLenOnly(enc, (UsefulBufC) { .ptr = NULL, .len = obj->payload_len });

    QCBOREncode_CloseArray(enc);
    return BSL_SUCCESS;
}
