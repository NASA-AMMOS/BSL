#ifndef BSLB_CBOR_H_
#define BSLB_CBOR_H_

#include <BPSecLib_Public.h>

#include <qcbor/qcbor_encode.h>
#include <qcbor/qcbor_spiffy_decode.h>

/** Callback to actually perform the encoding.
 *
 * @param enc Non-null pointer to the encoder to use.
 * @param obj Pointer to the user data to encode.
 */
typedef int (*BSL_CBOR_Encode_f)(QCBOREncodeContext *enc, const void *obj);

/** Perform two-pass size-fitted encoding.
 *
 * @param[out] buf The already-initialized buffer to resize and write into.
 * @param func The encoding function which takes the user data.
 * @param obj Pointer to the user data to encode.
 * @return BSL_SUCCESS if successful
 */
int BSL_CBOR_Encode_Twopass(BSL_Data_t *buf, BSL_CBOR_Encode_f func, const void *obj);

/** Callback to actually perform the decoding.
 *
 * @param enc Non-null pointer to the decoder to use.
 * @param obj Pointer to the user data to decode into.
 */
typedef int (*BSL_CBOR_Decode_f)(QCBORDecodeContext *dec, const void *obj);

/** Perform size- and error-checked encoding.
 *
 * @param[in] buf The populated buffer to read from.
 * @param func The decoding function which takes the user data.
 * @param obj Pointer to the user data to encode.
 * @return BSL_SUCCESS if successful
 */
int BSL_CBOR_Decode(const BSL_Data_t *buf, BSL_CBOR_Decode_f func, const void *obj);

#endif /* BSLB_CBOR_H_ */
