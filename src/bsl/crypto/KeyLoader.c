#include "KeyLoader.h"
#include <bsl/front/TextUtil.h>
#include <bsl/dynamic/CBOR.h>
#include <bsl/dynamic/IdValPair.h>
#include <bsl/cose_sc/CoseMsg.h>

#include <jansson.h>
#include <m-string.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

extern BSL_KeyStore_Descriptors_t BSL_KeyStore_State;

int BSL_Crypto_KeyLoader_LoadFile(const char *file_path)
{
    int retval = BSL_SUCCESS;

    int infd = open(file_path, O_RDONLY);
    if (infd < 0)
    {
        BSL_LOG_ERR("Failed to open input file %s", file_path);
        return BSL_ERR_DECODING;
    }

    BSL_LOG_INFO("Reading keys from %s", file_path);
    m_string_t path;
    m_string_init_set_cstr(path, file_path);
    bool is_json = m_string_end_with_str_p(path, ".json");
    bool is_cbor = m_string_end_with_str_p(path, ".cbor");
    m_string_clear(path);

    if (is_json)
    {
        retval = BSL_Crypto_KeyLoader_LoadJwkSet(infd);
    }
    else if (is_cbor)
    {
        retval = BSL_Crypto_KeyLoader_LoadCoseKeySet(infd);
    }
    else
    {
        BSL_LOG_ERR("Unhandled key file extension for %s", file_path);
        retval = BSL_ERR_ARG_INVALID;
    }

    return retval;
}

int BSL_Crypto_KeyLoader_LoadJwkSet(int fd)
{
    int retval = BSL_SUCCESS;

    json_error_t err;

    json_t *root = json_loadfd(fd, 0, &err);
    if (!root)
    {
        BSL_LOG_ERR("JSON error: line %d: %s", err.line, err.text);
        json_decref(root);
        return 1;
    }

    const json_t *keys = json_object_get(root, "keys");
    if (!keys || !json_is_array(keys))
    {
        BSL_LOG_ERR("Missing \"keys\" ");
        json_decref(root);
        return 1;
    }

    const size_t n = json_array_size(keys);
    BSL_LOG_INFO("Found %zu key objects", n);

    for (size_t i = 0; i < n; ++i)
    {
        const json_t *key_obj = json_array_get(keys, i);
        if (!json_is_object(key_obj))
        {
            continue;
        }

        const json_t *kty = json_object_get(key_obj, "kty");
        if (!kty)
        {
            BSL_LOG_ERR("Missing \"kty\" ");
            continue;
        }

        if (0 != strcmp("oct", json_string_value(kty)))
        {
            BSL_LOG_ERR("Not a symmetric key set");
            continue;
        }

        const json_t *kid = json_object_get(key_obj, "kid");
        if (!kid || !json_is_string(kid))
        {
            BSL_LOG_ERR("Missing \"kid\" ");
            continue;
        }
        const char *kid_str = json_string_value(kid);
        BSL_LOG_DEBUG("kid: %s", kid_str);

        const json_t *k = json_object_get(key_obj, "k");
        if (!k || !json_is_string(k))
        {
            BSL_LOG_ERR("Missing \"k\" ");
            continue;
        }

        BSL_Data_t k_data;
        BSL_Data_Init(&k_data);
        retval = BSL_TextUtil_Base64_Decode(&k_data, json_string_value(k), json_string_length(k));

        if (!retval)
        {
            BSL_Data_t kid_view = BSL_DATA_INIT_VIEW_CSTR(kid_str);

            BSL_Crypto_KeyHandle_t keyhandle;
            BSL_Crypto_LoadKey(k_data.ptr, k_data.len, &keyhandle);
            retval = BSL_KeyStore_State.add_key(&kid_view, keyhandle);
            BSL_Crypto_ReleaseKeyHandle(keyhandle);
        }
        BSL_Data_Deinit(&k_data);

        if (retval)
        {
            BSL_LOG_ERR("JKW register failure");
            break;
        }
    }

    json_decref(root);
    return retval;
}

/** Decode a @c COSE_KeySet array.
 *  Matches ::BSL_CBOR_Decode_f signature.
 */
static int mock_bpa_key_registry_cosekey_decode(QCBORDecodeContext *dec, const void *obj _U_)
{
    int retval = BSL_SUCCESS;

    QCBORItem item;
    QCBORDecode_EnterArray(dec, NULL);

    // array-of-key-maps
    while (QCBOR_SUCCESS == QCBORDecode_PeekNext(dec, &item))
    {
        bool       has_kty = false;
        int64_t    kty     = 0;
        bool       has_alg = false;
        int64_t    alg     = 0;
        UsefulBufC kid     = NULLUsefulBufC;
        UsefulBufC baseiv  = NULLUsefulBufC;
        UsefulBufC k_data  = NULLUsefulBufC;

        QCBORDecode_EnterArray(dec, NULL); // using QCBOR_DECODE_MODE_MAP_AS_ARRAY

        while (QCBOR_SUCCESS == QCBORDecode_PeekNext(dec, &item))
        {
            int64_t label;
            QCBORDecode_GetInt64(dec, &label);
            if (QCBOR_SUCCESS != QCBORDecode_GetError(dec))
            {
                BSL_LOG_ERR("Unable to get key label");
                break;
            }
            BSL_LOG_DEBUG("got label %" PRId64, label);

            switch (label)
            {
                case BSLX_COSEMSG_KEY_PARAM_KTY:
                    QCBORDecode_GetInt64(dec, &kty);
                    has_kty = true;
                    break;
                case BSLX_COSEMSG_KEY_PARAM_KID:
                    QCBORDecode_GetByteString(dec, &kid);
                    break;
                case BSLX_COSEMSG_KEY_PARAM_ALG:
                    QCBORDecode_GetInt64(dec, &alg);
                    has_alg = true;
                    break;
                case BSLX_COSEMSG_KEY_PARAM_BASEIV:
                    QCBORDecode_GetByteString(dec, &baseiv);
                    break;
                case -1:
                    if (has_kty && (kty == 4))
                    {
                        QCBORDecode_GetByteString(dec, &k_data);
                    }
                    break;
                default:
                    // consume but ignore
                    QCBORDecode_VGetNextConsume(dec, &item);
                    break;
            }
            if (QCBOR_SUCCESS != QCBORDecode_GetError(dec))
            {
                BSL_LOG_ERR("Unable to get key value");
                break;
            }

            if (has_kty && (kty != 4))
            {
                BSL_LOG_WARNING("Ignoring non-symmetric key type %" PRId64, kty);
                break;
            }
        }
        QCBORDecode_ExitArray(dec);

        // If valid enough to store
        if (has_kty && kid.ptr && k_data.ptr)
        {
            BSL_Data_t kid_view;
            BSL_Data_InitView(&kid_view, kid.len, (BSL_DataPtr_t)kid.ptr);

            BSL_Crypto_KeyHandle_t keyhandle;
            BSL_Crypto_LoadKey(k_data.ptr, k_data.len, &keyhandle);

            if (has_alg)
            {
                BSL_IdValPair_SetInt64(BSL_KeyStore_State.set_parameter(keyhandle, BSLX_COSEMSG_KEY_PARAM_ALG),
                                       BSLX_COSEMSG_KEY_PARAM_ALG, alg);
            }
            else
            {
                BSL_LOG_WARNING("COSE Key without an alg parameter");
            }

            if (baseiv.len > 0)
            {
                BSL_Data_t view;
                BSL_Data_InitView(&view, baseiv.len, (BSL_DataPtr_t)baseiv.ptr);
                BSL_IdValPair_SetBytestr(BSL_KeyStore_State.set_parameter(keyhandle, BSLX_COSEMSG_KEY_PARAM_BASEIV),
                                         BSLX_COSEMSG_KEY_PARAM_BASEIV, view);
            }

            retval = BSL_KeyStore_State.add_key(&kid_view, keyhandle);
            BSL_Crypto_ReleaseKeyHandle(keyhandle);
            BSL_LOG_DEBUG("Adding key result %d", retval);
            if (BSL_SUCCESS != retval)
            {
                BSL_LOG_ERR("Unable to store key");
                break;
            }
        }
    }
    QCBORDecode_ExitArray(dec);
    return retval;
}

int BSL_Crypto_KeyLoader_LoadCoseKeySet(int infd)
{
    struct stat sb;
    if ((fstat(infd, &sb) < 0) || (sb.st_size == 0))
    {
        BSL_LOG_ERR("Error getting file size");
        close(infd);
        return BSL_ERR_DECODING;
    }

    void *data = mmap(NULL, sb.st_size, PROT_READ, MAP_PRIVATE, infd, 0);
    if (!data)
    {
        BSL_LOG_ERR("Error in mmap");
        close(infd);
        return BSL_ERR_DECODING;
    }

    BSL_Data_t view;
    BSL_Data_InitView(&view, sb.st_size, (BSL_DataPtr_t)data);

    int retval = BSL_CBOR_Decode(&view, &mock_bpa_key_registry_cosekey_decode, NULL);

    if (munmap(data, sb.st_size) < 0)
    {
        BSL_LOG_ERR("Error in munmap");
    }
    close(infd);
    return retval;
}
