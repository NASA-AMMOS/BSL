#include "CBOR.h"
#include <BPSecLib_Private.h>

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
        QCBOREncode_Init(&encoder, (UsefulBuf) { .ptr = buf->ptr, .len = buf->len });

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
    QCBORDecode_Init(&decoder, (UsefulBufC) { .ptr = buf->ptr, .len = buf->len }, QCBOR_DECODE_MODE_NORMAL);

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
