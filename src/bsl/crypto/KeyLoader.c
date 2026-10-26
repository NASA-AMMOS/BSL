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
 * @ingroup crypto
 * Implementation of the key loader logic for JWK Set and COSE Key Set.
 */
#include "KeyLoader.h"

#include <bsl/front/TextUtil.h>
#include "bsl/dynamic/MLibConfig.h"
#include <bsl/dynamic/CBOR.h>
#include <bsl/dynamic/Variant.h>
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
    close(infd);

    return retval;
}

int BSL_Crypto_KeyLoader_LoadJwkSet(int infd)
{
    CHK_ARG_EXPR(infd >= 0);
    int retval = BSL_SUCCESS;

    json_error_t err;

    json_t *root = json_loadfd(infd, 0, &err);
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
            BSL_LOG_DEBUG("Adding key result %d", retval);
            if (BSL_SUCCESS != retval)
            {
                BSL_LOG_ERR("Unable to store key");
            }
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

static void BSL_Crypto_KeyLoader_LoadCoseKeyMap_decode(QCBORDecodeContext *dec)
{
    bool       has_kty = false;
    int64_t    kty     = 0;
    bool       has_alg = false;
    int64_t    alg     = 0;
    UsefulBufC kid     = NULLUsefulBufC;
    UsefulBufC baseiv  = NULLUsefulBufC;
    // type-specific options
    UsefulBufC k_data  = NULLUsefulBufC;
    bool       has_crv = false;
    int64_t    ec_crv  = 0;
    UsefulBufC x_data  = NULLUsefulBufC;
    UsefulBufC y_data  = NULLUsefulBufC;
    UsefulBufC d_data  = NULLUsefulBufC;

    QCBORItem item;
    while (QCBOR_SUCCESS == QCBORDecode_PeekNext(dec, &item))
    {
        int64_t label;
        QCBORDecode_GetInt64(dec, &label);
        if (QCBOR_SUCCESS != QCBORDecode_GetError(dec))
        {
            BSL_LOG_ERR("Unable to get key label");
            return;
        }
        BSL_LOG_DEBUG("got label %" PRId64, label);

        if (label >= 0)
        {
            switch (label)
            {
                case BSLX_COSEMSG_KEY_PARAM_KTY:
                    QCBORDecode_GetInt64(dec, &kty);
                    if (QCBOR_SUCCESS != QCBORDecode_GetError(dec))
                    {
                        BSL_LOG_ERR("Invalid kty value");
                        return;
                    }
                    has_kty = true;
                    BSL_LOG_DEBUG("got kty %" PRId64, kty);
                    break;
                case BSLX_COSEMSG_KEY_PARAM_KID:
                    QCBORDecode_GetByteString(dec, &kid);
                    if (QCBOR_SUCCESS != QCBORDecode_GetError(dec))
                    {
                        BSL_LOG_ERR("Invalid kid value");
                        return;
                    }
                    break;
                case BSLX_COSEMSG_KEY_PARAM_ALG:
                    QCBORDecode_GetInt64(dec, &alg);
                    if (QCBOR_SUCCESS != QCBORDecode_GetError(dec))
                    {
                        BSL_LOG_ERR("Invalid alg value");
                        return;
                    }
                    has_alg = true;
                    break;
                case BSLX_COSEMSG_KEY_PARAM_BASEIV:
                    QCBORDecode_GetByteString(dec, &baseiv);
                    break;
                default:
                    // consume but ignore
                    QCBORDecode_VGetNextConsume(dec, &item);
                    break;
            }
        }
        else if (has_kty)
        {
            if (kty == BSLX_COSEMSG_KEY_TYPE_SYMMETRIC)
            {
                switch (label)
                {
                    case -1:
                        QCBORDecode_GetByteString(dec, &k_data);
                        if (QCBOR_SUCCESS != QCBORDecode_GetError(dec))
                        {
                            BSL_LOG_ERR("Invalid k value");
                            return;
                        }
                        break;
                    default:
                        // key is invalid
                        BSL_LOG_WARNING("Invalid key label %" PRId64, label);
                        return;
                }
            }
            else if (kty == BSLX_COSEMSG_KEY_TYPE_EC2)
            {
                switch (label)
                {
                    case BSLX_COSEMSG_KEY_PARAM_EC2_CRV:
                        QCBORDecode_GetInt64(dec, &ec_crv);
                        if (QCBOR_SUCCESS != QCBORDecode_GetError(dec))
                        {
                            BSL_LOG_ERR("Invalid crv value");
                            return;
                        }
                        has_crv = true;
                        break;
                    case BSLX_COSEMSG_KEY_PARAM_EC2_X:
                        QCBORDecode_GetByteString(dec, &x_data);
                        if (QCBOR_SUCCESS != QCBORDecode_GetError(dec))
                        {
                            BSL_LOG_ERR("Invalid x value");
                            return;
                        }
                        break;
                    case BSLX_COSEMSG_KEY_PARAM_EC2_Y:
                        QCBORDecode_GetByteString(dec, &y_data);
                        if (QCBOR_SUCCESS != QCBORDecode_GetError(dec))
                        {
                            BSL_LOG_ERR("Invalid y value");
                            return;
                        }
                        break;
                    case BSLX_COSEMSG_KEY_PARAM_EC2_D:
                        QCBORDecode_GetByteString(dec, &d_data);
                        if (QCBOR_SUCCESS != QCBORDecode_GetError(dec))
                        {
                            BSL_LOG_ERR("Invalid d value");
                            return;
                        }
                        break;
                    default:
                        // key is invalid
                        BSL_LOG_WARNING("Invalid key label %" PRId64, label);
                        return;
                }
            }
        }
    }

    // If valid enough to store
    if (!has_kty || !kid.ptr)
    {
        return;
    }
    if (kty == BSLX_COSEMSG_KEY_TYPE_SYMMETRIC)
    {
        if (k_data.len == 0)
        {
            BSL_LOG_WARNING("Ignoring symmetric key without k");
            return;
        }
    }
    else if (kty == BSLX_COSEMSG_KEY_TYPE_EC2)
    {
        if (!has_crv || (x_data.len == 0) || (y_data.len == 0))
        {
            BSL_LOG_WARNING("Ignoring EC2 key without x or y");
            return;
        }
    }
    else
    {
        BSL_LOG_WARNING("Ignoring unhandled key type %" PRId64, kty);
        return;
    }

    BSL_Crypto_KeyHandle_t keyhandle;
    // empty key object
    int res = BSL_KeyStore_State.new_key(&keyhandle);
    if (BSL_SUCCESS != res)
    {
        BSL_LOG_ERR("Unable to create key");
        return;
    }
    BSL_Variant_SetInt64(BSL_KeyStore_State.set_parameter(keyhandle, BSLX_COSEMSG_KEY_PARAM_KTY), kty);

    if (has_alg)
    {
        BSL_Variant_SetInt64(BSL_KeyStore_State.set_parameter(keyhandle, BSLX_COSEMSG_KEY_PARAM_ALG), alg);
    }
    else
    {
        BSL_LOG_WARNING("COSE Key without an alg parameter");
    }
    if (baseiv.len > 0)
    {
        BSL_Data_t view = BSL_DATA_INIT_VIEW(baseiv.ptr, baseiv.len);
        BSL_Variant_SetBytestr(BSL_KeyStore_State.set_parameter(keyhandle, BSLX_COSEMSG_KEY_PARAM_BASEIV), view);
    }

    if (k_data.len > 0)
    {
        BSL_Data_t view = BSL_DATA_INIT_VIEW(k_data.ptr, k_data.len);

        res = BSL_KeyStore_State.set_keymat(keyhandle, &view);
        if (BSL_SUCCESS != res)
        {
            BSL_LOG_ERR("Failed to set new key material");
            return;
        }
    }
    if (has_crv)
    {
        BSL_Variant_SetInt64(BSL_KeyStore_State.set_parameter(keyhandle, BSLX_COSEMSG_KEY_PARAM_EC2_CRV), ec_crv);
    }
    if (x_data.len > 0)
    {
        BSL_Data_t view = BSL_DATA_INIT_VIEW(x_data.ptr, x_data.len);
        BSL_Variant_SetBytestr(BSL_KeyStore_State.set_parameter(keyhandle, BSLX_COSEMSG_KEY_PARAM_EC2_X), view);
    }
    if (y_data.len > 0)
    {
        BSL_Data_t view = BSL_DATA_INIT_VIEW(y_data.ptr, y_data.len);
        BSL_Variant_SetBytestr(BSL_KeyStore_State.set_parameter(keyhandle, BSLX_COSEMSG_KEY_PARAM_EC2_Y), view);
    }
    if (d_data.len > 0)
    {
        BSL_Data_t view = BSL_DATA_INIT_VIEW(d_data.ptr, d_data.len);
        BSL_Variant_SetBytestr(BSL_KeyStore_State.set_parameter(keyhandle, BSLX_COSEMSG_KEY_PARAM_EC2_D), view);
    }

    {
        BSL_Data_t view = BSL_DATA_INIT_VIEW(kid.ptr, kid.len);
        // key is immutable after this
        res = BSL_KeyStore_State.add_key(&view, keyhandle);
    }
    BSL_Crypto_ReleaseKeyHandle(keyhandle);
    BSL_LOG_DEBUG("Store key result %d", res);
    if (BSL_SUCCESS != res)
    {
        BSL_LOG_ERR("Unable to store key");
    }
}

/** Decode a @c COSE_KeySet array.
 *  Matches ::BSL_CBOR_Decode_f signature.
 */
static int BSL_Crypto_KeyLoader_LoadCoseKeySet_decode(QCBORDecodeContext *dec, const void *obj _U_)
{
    int retval = BSL_SUCCESS;

    QCBORItem item;
    QCBORDecode_EnterArray(dec, NULL);

    // array-of-key-maps
    while (QCBOR_SUCCESS == QCBORDecode_PeekNext(dec, &item))
    {
        QCBORDecode_EnterArray(dec, NULL); // using QCBOR_DECODE_MODE_MAP_AS_ARRAY

        BSL_Crypto_KeyLoader_LoadCoseKeyMap_decode(dec);
        if (QCBOR_SUCCESS != QCBORDecode_GetAndResetError(dec))
        {
            BSL_LOG_WARNING("Unable to handle key object");
        }

        QCBORDecode_ExitArray(dec);
    }
    QCBORDecode_ExitArray(dec);
    return retval;
}

int BSL_Crypto_KeyLoader_LoadCoseKeySet(int infd)
{
    CHK_ARG_EXPR(infd >= 0);
    struct stat sb;
    if ((fstat(infd, &sb) < 0) || (sb.st_size <= 0))
    {
        BSL_LOG_ERR("Error getting file size");
        return BSL_ERR_DECODING;
    }

    void *data = mmap(NULL, (size_t)sb.st_size, PROT_READ, MAP_PRIVATE, infd, 0);
    if (!data)
    {
        BSL_LOG_ERR("Error in mmap");
        return BSL_ERR_DECODING;
    }

    BSL_Data_t view;
    BSL_Data_InitView(&view, (size_t)sb.st_size, (BSL_DataPtr_t)data);

    int retval = BSL_CBOR_Decode(&view, &BSL_Crypto_KeyLoader_LoadCoseKeySet_decode, NULL);

    if (munmap(data, (size_t)sb.st_size) < 0)
    {
        BSL_LOG_ERR("Error in munmap");
    }
    return retval;
}
