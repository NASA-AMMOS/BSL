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
    BSLB_IdValPairPtrDict_init(obj->phdr);
    BSLB_IdValPairPtrDict_init(obj->uhdr);
    BSL_Data_Init(&obj->tag);
}

void BSLX_CoseMsg_Mac0_Deinit(BSLX_CoseMsg_Mac0_t *obj)
{
    ASSERT_ARG_NONNULL(obj);
    BSLB_IdValPairPtrDict_clear(obj->uhdr);
    BSLB_IdValPairPtrDict_clear(obj->phdr);
    BSL_Data_Deinit(&obj->tag);
    memset(obj, 0, sizeof(*obj));
}

int BSLX_CoseMsg_Mac0_Encode(QCBOREncodeContext *enc, const BSLX_CoseMsg_Mac0_t *obj)
{
    QCBOREncode_OpenArray(enc);
    {
        // protected map
        QCBOREncode_BstrWrap(enc);
        QCBOREncode_OpenMap(enc);

        BSLB_IdValPairPtrDict_it_t param_it;
        for (BSLB_IdValPairPtrDict_it(param_it, obj->phdr); !BSLB_IdValPairPtrDict_end_p(param_it);
             BSLB_IdValPairPtrDict_next(param_it))
        {
            const BSL_IdValPair_t *param = BSLB_IdValPairPtr_cref(BSLB_IdValPairPtrDict_ref(param_it)->value);
            BSL_IdValPair_Encode(enc, param);
        }

        QCBOREncode_CloseMap(enc);
        QCBOREncode_CloseBstrWrap(enc, NULL);
    }
    {
        // unprotected map
        QCBOREncode_OpenMap(enc);

        BSLB_IdValPairPtrDict_it_t param_it;
        for (BSLB_IdValPairPtrDict_it(param_it, obj->uhdr); !BSLB_IdValPairPtrDict_end_p(param_it);
             BSLB_IdValPairPtrDict_next(param_it))
        {
            const BSL_IdValPair_t *param = BSLB_IdValPairPtr_cref(BSLB_IdValPairPtrDict_ref(param_it)->value);
            BSL_IdValPair_Encode(enc, param);
        }

        QCBOREncode_CloseMap(enc);
    }
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
        // protected map
        QCBORDecode_EnterBstrWrapped(dec, QCBOR_TAG_REQUIREMENT_NOT_A_TAG, NULL);
        QCBORDecode_EnterMap(dec, NULL);

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
                BSLB_IdValPairPtrDict_set_at(obj->phdr, param->id, param_ptr);
                BSLB_IdValPairPtr_release(param_ptr);
            }
        }

        QCBORDecode_ExitMap(dec);
        QCBORDecode_ExitBstrWrapped(dec);
    }
    {
        // unprotected map
        QCBORDecode_EnterMap(dec, NULL);

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
                BSLB_IdValPairPtrDict_set_at(obj->uhdr, param->id, param_ptr);
                BSLB_IdValPairPtr_release(param_ptr);
            }
        }

        QCBORDecode_ExitMap(dec);
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
