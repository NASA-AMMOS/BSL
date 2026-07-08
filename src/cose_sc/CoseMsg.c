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

void BSLX_CoseMsg_HdrMapTree_update(BSLX_CoseMsg_HdrMapTree_t base, const BSLX_CoseMsg_HdrMapTree_t addl)
{
    BSLX_CoseMsg_HdrMapTree_it_t map_it;
    for (BSLX_CoseMsg_HdrMapTree_it(map_it, addl); !BSLX_CoseMsg_HdrMapTree_end_p(map_it);
         BSLX_CoseMsg_HdrMapTree_next(map_it))
    {
        const BSLX_CoseMsg_HdrMapTree_subtype_ct *item = BSLX_CoseMsg_HdrMapTree_cref(map_it);

        if (!BSLX_CoseMsg_HdrMapTree_cget(base, *(item->key_ptr)))
        {
            BSLX_CoseMsg_HdrMapTree_set_at(base, *(item->key_ptr), *(item->value_ptr));
        }
    }
}

int BSLX_CoseMsg_Headers_Encode_Map(QCBOREncodeContext *enc, const BSLX_CoseMsg_HdrMapTree_t *map)
{
    QCBOREncode_OpenMap(enc);

    BSLX_CoseMsg_HdrMapTree_it_t map_it;
    for (BSLX_CoseMsg_HdrMapTree_it(map_it, *map); !BSLX_CoseMsg_HdrMapTree_end_p(map_it);
         BSLX_CoseMsg_HdrMapTree_next(map_it))
    {
        const BSL_IdValPair_t *value = BSLB_IdValPairPtr_cref(*(BSLX_CoseMsg_HdrMapTree_ref(map_it)->value_ptr));
        BSL_IdValPair_Encode(enc, value);
    }

    QCBOREncode_CloseMap(enc);
    return BSL_SUCCESS;
}

int BSLX_CoseMsg_Headers_Decode_Map(QCBORDecodeContext *dec, BSLX_CoseMsg_HdrMapTree_t *map)
{
    QCBORDecode_EnterArray(dec, NULL); // Using QCBOR_DECODE_MODE_MAP_AS_ARRAY
    if (QCBOR_SUCCESS != QCBORDecode_GetError(dec))
    {
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
            BSLX_CoseMsg_HdrMapTree_set_at(*map, param->id, param_ptr);
            BSLB_IdValPairPtr_release(param_ptr);
        }
    }

    QCBORDecode_ExitArray(dec);
    return BSL_SUCCESS;
}

void BSLX_CoseMsg_Headers_Init(BSLX_CoseMsg_Headers_t *obj)
{
    ASSERT_ARG_NONNULL(obj);
    BSL_Data_Init(&obj->phdr_bstr);
    BSLX_CoseMsg_HdrMapTree_init(obj->phdr);
    BSLX_CoseMsg_HdrMapTree_init(obj->uhdr);
}

void BSLX_CoseMsg_Headers_Deinit(BSLX_CoseMsg_Headers_t *obj)
{
    ASSERT_ARG_NONNULL(obj);
    BSLX_CoseMsg_HdrMapTree_clear(obj->uhdr);
    BSLX_CoseMsg_HdrMapTree_clear(obj->phdr);
    BSL_Data_Deinit(&obj->phdr_bstr);
}

int BSLX_CoseMsg_Headers_Encode(QCBOREncodeContext *enc, const BSLX_CoseMsg_Headers_t *obj)
{
    // protected map data
    QCBOREncode_AddBytes(enc, UsefulBufC_FROM_BSL_Data(obj->phdr_bstr));
    // unprotected map
    BSLX_CoseMsg_Headers_Encode_Map(enc, &obj->uhdr);

    return BSL_SUCCESS;
}

int BSLX_CoseMsg_Headers_Decode(QCBORDecodeContext *dec, BSLX_CoseMsg_Headers_t *obj)
{
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
            if (BSL_SUCCESS != BSLX_CoseMsg_Headers_Decode_Map(dec, &obj->phdr))
            {
                BSL_LOG_ERR("Protected header map error");
                return BSL_ERR_DECODING;
            }
        }
        BSL_LOG_DEBUG("Decoded %zu protected items", BSLX_CoseMsg_HdrMapTree_size(obj->phdr));
        // copy only after map success
        BSL_Data_CopyFrom(&obj->phdr_bstr, phdr_content.len, phdr_content.ptr);

        QCBORDecode_ExitBstrWrapped(dec);
    }
    {
        // unprotected map
        if (BSL_SUCCESS != BSLX_CoseMsg_Headers_Decode_Map(dec, &obj->uhdr))
        {
            BSL_LOG_ERR("Unprotected header map error");
            return BSL_ERR_DECODING;
        }
        BSL_LOG_DEBUG("Decoded %zu unprotected items", BSLX_CoseMsg_HdrMapTree_size(obj->phdr));
    }

    return BSL_SUCCESS;
}

int BSLX_CoseMsg_Headers_DerivePhdr(BSLX_CoseMsg_Headers_t *obj)
{
    if (BSLX_CoseMsg_HdrMapTree_empty_p(obj->phdr))
    {
        BSL_Data_Resize(&obj->phdr_bstr, 0);
        return BSL_SUCCESS;
    }
    return BSL_CBOR_Encode_Twopass(&obj->phdr_bstr, (BSL_CBOR_Encode_f)&BSLX_CoseMsg_Headers_Encode_Map, &obj->phdr);
}

/** Decode a @c crit array and fail directly.
 * Matches ::BSL_CBOR_Decode_f signature.
 */
static int BSLX_CoseMsg_Headers_CheckCrit_Decode(QCBORDecodeContext *dec, const void *obj _U_)
{
    QCBORDecode_EnterArray(dec, NULL);
    if (QCBOR_SUCCESS != QCBORDecode_GetError(dec))
    {
        return BSL_ERR_DECODING;
    }

    QCBORItem item;
    while (QCBOR_SUCCESS == QCBORDecode_PeekNext(dec, &item))
    {
        int64_t key;
        QCBORDecode_GetInt64(dec, &key);
        if (QCBOR_SUCCESS != QCBORDecode_GetError(dec))
        {
            BSL_LOG_ERR("BPSec profile requires header parameter labels to be int type");
            return BSL_ERR_DECODING;
        }
        // check for unhandled labels
        switch (key)
        {
            case BSLX_COSEMSG_HDR_ALG:
            case BSLX_COSEMSG_HDR_CRIT:
            case BSLX_COSEMSG_HDR_CONTENTTYPE:
            case BSLX_COSEMSG_HDR_KID:
            case BSLX_COSEMSG_HDR_IV:
            case BSLX_COSEMSG_HDR_PARTIALIV:
                // above should not be present but still handle as valid
            case BSLX_COSEMSG_HDR_KIDCONTEXT:
            case BSLX_COSEMSG_HDR_SALT:
                break;
            default:
                BSL_LOG_ERR("BPSec profile does not use header parameter label %" PRId64, key);
                return BSL_ERR_DECODING;
        }
    }

    QCBORDecode_ExitArray(dec);
    return BSL_SUCCESS;
}

int BSLX_CoseMsg_Headers_CheckCrit(const BSLX_CoseMsg_Headers_t *obj)
{
    const BSL_IdValPair_t *hdr = BSLX_CoseMsg_Headers_Get(obj, BSLX_COSEMSG_HDR_CRIT, true);
    if (hdr)
    {
        BSL_Data_t view;
        if (BSL_SUCCESS != BSL_IdValPair_GetAsRaw(hdr, &view))
        {
            BSL_LOG_ERR("Header crit is present but invalid");
            return BSL_ERR_DECODING;
        }
        int res = BSL_CBOR_Decode(&view, (BSL_CBOR_Decode_f)&BSLX_CoseMsg_Headers_CheckCrit_Decode, NULL);
        return res;
    }
    return BSL_SUCCESS;
}

const BSL_IdValPair_t *BSLX_CoseMsg_Headers_Get(const BSLX_CoseMsg_Headers_t *obj, int64_t label, bool need_phdr)
{
    BSLB_IdValPairPtr_t *const *found = BSLX_CoseMsg_HdrMapTree_cget(obj->phdr, label);
    if (!found)
    {
        found = BSLX_CoseMsg_HdrMapTree_cget(obj->uhdr, label);
        if (found && need_phdr)
        {
            BSL_LOG_ERR("Header parameter %" PRId64 " needs to be protected but is not, ignoring it", label);
            found = NULL;
        }
    }
    return found ? BSLB_IdValPairPtr_cref(*found) : NULL;
}

void BSLX_CoseMsg_Mac0_Init(BSLX_CoseMsg_Mac0_t *obj)
{
    ASSERT_ARG_NONNULL(obj);
    memset(obj, 0, sizeof(*obj));
    BSLX_CoseMsg_Headers_Init(&obj->headers);
    BSL_Data_Init(&obj->tag);
}

void BSLX_CoseMsg_Mac0_Deinit(BSLX_CoseMsg_Mac0_t *obj)
{
    ASSERT_ARG_NONNULL(obj);
    BSL_Data_Deinit(&obj->tag);
    BSLX_CoseMsg_Headers_Deinit(&obj->headers);
    memset(obj, 0, sizeof(*obj));
}

int BSLX_CoseMsg_Mac0_Encode(QCBOREncodeContext *enc, const BSLX_CoseMsg_Mac0_t *obj)
{
    QCBOREncode_OpenArray(enc);

    BSLX_CoseMsg_Headers_Encode(enc, &obj->headers);
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

    int res = BSLX_CoseMsg_Headers_Decode(dec, &obj->headers);
    if (BSL_SUCCESS != res)
    {
        return res;
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

void BSLX_CoseMsg_Encrypt0_Init(BSLX_CoseMsg_Encrypt0_t *obj)
{
    ASSERT_ARG_NONNULL(obj);
    memset(obj, 0, sizeof(*obj));
    BSLX_CoseMsg_Headers_Init(&obj->headers);
}

void BSLX_CoseMsg_Encrypt0_Deinit(BSLX_CoseMsg_Encrypt0_t *obj)
{
    ASSERT_ARG_NONNULL(obj);
    BSLX_CoseMsg_Headers_Deinit(&obj->headers);
    memset(obj, 0, sizeof(*obj));
}

int BSLX_CoseMsg_Encrypt0_Encode(QCBOREncodeContext *enc, const BSLX_CoseMsg_Encrypt0_t *obj)
{
    QCBOREncode_OpenArray(enc);

    BSLX_CoseMsg_Headers_Encode(enc, &obj->headers);
    // detached payload
    QCBOREncode_AddNULL(enc);

    QCBOREncode_CloseArray(enc);
    return BSL_SUCCESS;
}

int BSLX_CoseMsg_Encrypt0_Decode(QCBORDecodeContext *dec, BSLX_CoseMsg_Encrypt0_t *obj)
{

    QCBORDecode_EnterArray(dec, NULL);

    int res = BSLX_CoseMsg_Headers_Decode(dec, &obj->headers);
    if (BSL_SUCCESS != res)
    {
        return res;
    }
    // detached payload
    QCBORDecode_GetNull(dec);
    if (QCBOR_SUCCESS != QCBORDecode_GetAndResetError(dec))
    {
        BSL_LOG_ERR("COSE payload is not detached");
        return BSL_ERR_DECODING;
    }

    QCBORDecode_ExitArray(dec);
    return BSL_SUCCESS;
}
