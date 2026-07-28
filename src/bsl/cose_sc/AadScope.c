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
