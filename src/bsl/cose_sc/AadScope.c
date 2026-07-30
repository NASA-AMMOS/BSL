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
#include "AadScope.h"

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
