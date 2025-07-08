/*
 * Copyright (c) 2024 The Johns Hopkins University Applied Physics
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
 * Contains functionality and data structures to implement BCB using security context in RFC9173.
 * @ingroup example_security_context
 */

#include "DefaultSecContext_Private.h"
#include "rfc9173.h"
#include "backend/DynSeqReadWrite.h"
#include <BPSecLib.h>
#include <qcbor/qcbor_encode.h>
#include <qcbor/qcbor_spiffy_decode.h>

BSLX_BlockHeader_t BSLX_BlockHeader_Init(uint64_t block_type, uint64_t block_num, uint64_t flags)
{
    BSLX_BlockHeader_t header;
    header.block_type    = block_type;
    header.block_num     = block_num;
    header.control_flags = flags;
    return header;
}

void BSLX_BlockHeader_Encode(BSLX_BlockHeader_t header, QCBOREncodeContext *encoder)
{
    assert(encoder != NULL);
    QCBOREncode_AddUInt64(encoder, header.block_type);
    QCBOREncode_AddUInt64(encoder, header.block_num);
    QCBOREncode_AddUInt64(encoder, header.control_flags);
}

BSLX_BCBEncryptCtx_t BSLX_BCBContext_Initialize(BSLX_BCBParams_t params, BSL_Data_t content,
                                                BSLX_ScratchSpace_t *scratch_space)
{
    assert(scratch_space != NULL);

    BSLX_BCBEncryptCtx_t bcb_context;
    memset(&bcb_context, 0, sizeof(bcb_context));

    if (params.err_count > 0)
    {
        BSL_LOG_ERR("BCB parameters contain %lu integrity error(s)", params);
        bcb_context.success = false;
        return bcb_context;
    }

    bcb_context.params = params;
    BSL_Data_InitView(&bcb_context.debugstr, 500, BSLX_ScratchSpace_take(scratch_space, 500));
    BSL_Data_InitView(&bcb_context.aad, 500, BSLX_ScratchSpace_take(scratch_space, 500));
    BSL_Data_InitView(&bcb_context.authtag, 500, BSLX_ScratchSpace_take(scratch_space, 500));

    if (params.crypto_mode == BSL_CRYPTO_ENCRYPT)
    {
        BSL_LOG_INFO("Setting to ENCRYPT");
        bcb_context.plaintext = content;
        BSL_Data_InitView(&bcb_context.ciphertext, content.len + 256,
                          BSLX_ScratchSpace_take(scratch_space, content.len + 256));
    }
    else if (params.crypto_mode == BSL_CRYPTO_DECRYPT)
    {
        BSL_LOG_INFO("Setting to DECRYPT");
        bcb_context.ciphertext = content;
        BSL_Data_InitView(&bcb_context.plaintext, content.len + 256,
                          BSLX_ScratchSpace_take(scratch_space, content.len + 256));
    }
    else
    {
        BSL_LOG_ERR("Unknown crypto mode: %lu", params.crypto_mode);
        bcb_context.success = 0;
        return bcb_context;
    }

    bcb_context.success = 1;
    return bcb_context;
}

static uint64_t _bcb_encode_aad_flags(const BSLX_BCBParams_t *params)
{
    uint64_t flags = 0;
    flags |= 0; // Ignore primary block for now
    flags |= ((!params->skip_aad_target_block & 0x01) << 1);
    flags |= ((!params->skip_aad_sec_block & 0x01) << 2);
    BSL_LOG_ERR("flags = %lu", flags);
    return flags;
}

static inline UsefulBuf _to_useful_buf(BSL_Data_t dat)
{
    UsefulBuf ub = { .ptr = dat.ptr, .len = dat.len };
    return ub;
}
BSLX_BCBEncryptCtx_t BSLX_BCBContext_ComputeAAD(const BSLX_BCBEncryptCtx_t bcb_input_context)
{
    BSLX_BCBEncryptCtx_t bcb_context = bcb_input_context;
    if (!bcb_context.success)
    {
        bcb_context.success = 0;
        return bcb_context;
    }

    uint64_t flags = _bcb_encode_aad_flags(&bcb_context.params);
    // assert( (flags & 0x04) == 0); // Prim block not implemented

    QCBOREncodeContext aad_enc;
    QCBOREncode_Init(&aad_enc, _to_useful_buf(bcb_context.aad));
    BSL_LOG_DEBUG("Adding AAD to start with value: %lu", flags);
    QCBOREncode_AddUInt64(&aad_enc, flags);

    if (flags & 0x02)
    {
        BSL_LOG_DEBUG("Adding target block header to AAD");
        BSLX_BlockHeader_Encode(bcb_context.params.target_block, &aad_enc);
    }
    if (flags & 0x04)
    {
        BSL_LOG_DEBUG("Adding security block header to AAD");
        BSLX_BlockHeader_Encode(bcb_context.params.sec_block, &aad_enc);
    }

    UsefulBufC enc_buf;
    QCBORError err      = QCBOREncode_Finish(&aad_enc, &enc_buf);
    bcb_context.aad.len = enc_buf.len;
    bcb_context.success = (err == QCBOR_SUCCESS) ? true : false;
    if (!bcb_context.success)
    {
        BSL_LOG_ERR("BCB CBOR encoding of AAD failed");
    }
    return bcb_context;
}

BSLX_BCBEncryptCtx_t BSLX_BCBContext_Decrypt(const BSLX_BCBEncryptCtx_t bcb_input_context)
{
    BSLX_BCBEncryptCtx_t bcb_context = bcb_input_context;
    bcb_context.success              = false;
    if (!bcb_input_context.success)
    {
        return bcb_context;
    }

    BSL_CryptoCipherAESVariant_e aes_mode =
        ((bcb_input_context.params.aes_variant == RFC9173_BCB_AES_VARIANT_A128GCM) ? BSL_CRYPTO_AES_128
                                                                                   : BSL_CRYPTO_AES_256);

    BSL_LOG_INFO("AES Mode     : %s", aes_mode == BSL_CRYPTO_AES_128 ? "AES128" : "AES256");
    BSL_LOG_INFO("Ciphertext   : %s",
                 BSL_Log_DumpAsHexString(bcb_context.debugstr.ptr, bcb_context.debugstr.len,
                                         bcb_input_context.ciphertext.ptr, bcb_input_context.ciphertext.len));

    // Zero-pad the key on both sides
    uint8_t key_buffer[100];
    memset(key_buffer, 0, sizeof(key_buffer));
    uint8_t   *cek_ptr = &key_buffer[8];
    BSL_Data_t cek_space;
    BSL_Data_InitView(&cek_space, 64, cek_ptr);

    assert(bcb_context.params.wrapped_key.len > 0);
    assert(bcb_context.params.key_id > 0);
    assert(cek_space.len > 0);
    assert(cek_space.ptr != NULL);
    BSL_LOG_INFO("Wrapped Key  : %s",
                 BSL_Log_DumpAsHexString(bcb_context.debugstr.ptr, bcb_context.debugstr.len,
                                         bcb_context.params.wrapped_key.ptr, bcb_context.params.wrapped_key.len));
    int r =
        BSL_CryptoTools_UnwrapAESKey(&cek_space, bcb_context.params.wrapped_key, bcb_context.params.key_id, aes_mode);
    BSL_LOG_INFO("UNWRAPPED Key: %s", BSL_Log_DumpAsHexString(bcb_context.debugstr.ptr, bcb_context.debugstr.len,
                                                              cek_space.ptr, cek_space.len));
    if (r != 0)
    {
        return bcb_context;
    }
    assert(r == 0);

    assert(bcb_context.params.iv.len > 0);
    BSL_LOG_INFO("IV          : %s", BSL_Log_DumpAsHexString(bcb_context.debugstr.ptr, bcb_context.debugstr.len,
                                                             bcb_context.params.iv.ptr, bcb_context.params.iv.len));
    BSL_CryptoCipherCtx_t cipher;

    r = BSL_CryptoCipherCtx_Init(&cipher, BSL_CRYPTO_DECRYPT, aes_mode, bcb_context.params.iv.ptr, bcb_context.params.iv.len, cek_space);
    if (r != 0)
    {
        BSL_LOG_ERR("Decrypt: init failed.");
        r = BSL_CryptoCipherCtx_Deinit(&cipher);
        assert(r == 0);
        return bcb_context;
    }

    r = BSL_CryptoCipherCtx_AddAAD(&cipher, bcb_context.aad.ptr, bcb_context.aad.len);
    if (r != 0)
    {
        BSL_LOG_ERR("Decrypt: add AAD failed.");
        r = BSL_CryptoCipherCtx_Deinit(&cipher);
        assert(r == 0);
        return bcb_context;
    }

    r = BSL_CryptoCipherCtx_SetTag(&cipher, bcb_context.authtag.ptr);
    if (r != 0)
    {
        BSL_LOG_ERR("Decrypt: set authtag failed.");
        r = BSL_CryptoCipherCtx_Deinit(&cipher);
        assert(r == 0);
        return bcb_context;
    }

    BSL_SeqReader_t reader;
    BSL_SeqWriter_t writer;

    r = BSL_SeqReader_InitFlat(&reader, bcb_context.ciphertext.ptr, bcb_context.ciphertext.len);
    assert(r == 0);
    r = BSL_SeqWriter_InitFlat(&writer, &bcb_context.plaintext.ptr, &bcb_context.plaintext.len);
    assert(r == 0);

    if (BSL_CryptoCipherCtx_AddSeq(&cipher, &reader, &writer) == 0)
    {
        if (BSL_CryptoCipherContext_FinalizeSeq(&cipher, &writer) == 0)
        {
            bcb_context.success = true;
        }
        else
        {
            BSL_LOG_ERR("Cannot finalize Decryption");
        }
    }
    else
    {
        BSL_LOG_ERR("Error adding data to decrypt ctx");
    }
    

    r = BSL_CryptoCipherCtx_Deinit(&cipher);
    assert(r == 0);
    r = BSL_SeqWriter_Deinit(&writer);
    assert(r == 0);

    return bcb_context;
}

BSLX_BCBEncryptCtx_t BSLX_BCBContext_Encrypt(const BSLX_BCBEncryptCtx_t bcb_input_context)
{
    BSLX_BCBEncryptCtx_t bcb_context = bcb_input_context;
    bcb_context.success              = false;
    if (!bcb_input_context.success)
    {
        return bcb_context;
    }

    BSL_CryptoCipherAESVariant_e aes_mode =
        ((bcb_context.params.aes_variant == RFC9173_BCB_AES_VARIANT_A128GCM) ? BSL_CRYPTO_AES_128 : BSL_CRYPTO_AES_256);

    uint8_t cek_buf[] = {
        0x71, 0x77, 0x65, 0x72, 0x74, 0x79, 0x75, 0x69, 0x6f, 0x70, 0x61, 0x73, 0x64, 0x66, 0x67, 0x68
    };
    BSL_LOG_INFO("CEK 0       : %s",
                 BSL_Log_DumpAsHexString(bcb_context.debugstr.ptr, bcb_context.debugstr.len, cek_buf, sizeof(cek_buf)));
    uint8_t wrapped_key_buf[32];
    memset(wrapped_key_buf, 0, sizeof(wrapped_key_buf));
    BSL_Data_t cek, wrapped_key;
    BSL_Data_InitView(&cek, sizeof(cek_buf), cek_buf);
    BSL_Data_InitView(&wrapped_key, 32, wrapped_key_buf);

    int r2 = BSL_CryptoTools_WrapAESKey(&wrapped_key, cek, bcb_context.params.key_id, aes_mode);
    assert(r2 == 0);
    BSL_Log_DumpAsHexString(bcb_context.debugstr.ptr, bcb_context.debugstr.len, cek.ptr, cek.len);
    BSL_LOG_INFO("CEK         : %s", bcb_context.debugstr.ptr);
    BSL_LOG_INFO("Wrapped Key : %s", BSL_Log_DumpAsHexString(bcb_context.debugstr.ptr, bcb_context.debugstr.len,
                                                             wrapped_key.ptr, wrapped_key.len));

    int                   r;
    BSL_CryptoCipherCtx_t cipher;
    r = BSL_CryptoCipherCtx_Init(&cipher, BSL_CRYPTO_ENCRYPT, aes_mode, bcb_context.params.iv.ptr,
                                 bcb_context.params.iv.len, cek);
    if (r == 0)
    {
        r = BSL_CryptoCipherCtx_AddAAD(&cipher, bcb_context.aad.ptr, bcb_context.aad.len);
        if (r != 0)
        {
            BSL_LOG_ERR("Encrypt: add AAD failed.");
            r = BSL_CryptoCipherCtx_Deinit(&cipher);
            assert(r == 0);
            return bcb_context;
        }

        BSL_SeqReader_t reader;
        BSL_SeqWriter_t writer;

        r = BSL_SeqReader_InitFlat(&reader, bcb_context.plaintext.ptr, bcb_context.plaintext.len);
        assert(r == 0);

        r = BSL_SeqWriter_InitFlat(&writer,  &bcb_context.ciphertext.ptr, &bcb_context.ciphertext.len);
        assert(r == 0);

        r = BSL_CryptoCipherCtx_AddSeq(&cipher, &reader, &writer);

        if (r == 0)
        {
            r = BSL_CryptoCipherContext_FinalizeSeq(&cipher, &writer);
            
            if (r == 0)
            {
                r                       = BSL_CryptoCipherCtx_GetTag(&cipher, (void **)&bcb_context.authtag.ptr);
                bcb_context.authtag.len = BSL_CRYPTO_AESGCM_AUTH_TAG_LEN;
                bcb_context.success     = (r == 0);
                if (r != 0)
                {
                    BSL_LOG_ERR("BCB cannot get auth tag");
                }
            }
            else
            {
                BSL_LOG_ERR("Cannot finalize encryption");
            }

            r = BSL_SeqWriter_Deinit(&writer);
            assert(r == 0);
        }
        else
        {
            BSL_LOG_ERR("Cannot encrypt");
        }
    }

    if (BSL_CryptoCipherCtx_Deinit(&cipher) != 0)
    {
        BSL_LOG_ERR("BCB failed to deinitialize cipher");
    }
    return bcb_context;
}

BSLX_BCBParams_t BSLX_GetBCBParams(const BSL_BundleCtx_t *bundle, const BSL_SecOper_t *sec_oper)
{
    assert(sec_oper != NULL);
    assert(bundle != NULL);

    BSLX_BCBParams_t params;
    memset(&params, 0, sizeof(params));
    params.crypto_mode = BSL_SecOper_IsRoleSource(sec_oper) == true ? BSL_CRYPTO_ENCRYPT : BSL_CRYPTO_DECRYPT;
    params.target_block.block_num = sec_oper->target_block_num;
    BSL_BundleContext_GetBlockMetadata(bundle, params.target_block.block_num, &params.target_block.block_type,
                                       &params.target_block.control_flags, NULL, NULL);
    params.sec_block.block_num = sec_oper->sec_block_num;
    BSL_BundleContext_GetBlockMetadata(bundle, params.sec_block.block_num, &params.sec_block.block_type, NULL, NULL,
                                       NULL);

    for (size_t param_index = 0; param_index < BSL_SecParamList_size(sec_oper->_param_list); param_index++)
    {
        const BSL_SecParam_t *param  = BSL_SecParamList_cget(sec_oper->_param_list, param_index);
        bool                  is_int = BSL_SecParam_IsInt64(param);
        switch (param->param_id)
        {
            case RFC9173_BCB_SECPARAM_IV:
            {
                assert(!is_int);
                BSL_Data_t as_data;
                if (BSL_SecParam_GetAsBytestr(param, &as_data) < 0)
                    params.err_count++;
                if (BSL_Data_InitView(&params.iv, as_data.len, as_data.ptr) < 0)
                    params.err_count++;
                break;
            }
            case RFC9173_BCB_SECPARAM_AESVARIANT:
            {
                BSL_LOG_DEBUG("BCB parsing AES variant (optid=%lu)", param->param_id);
                assert(is_int);
                params.aes_variant = BSL_SecParam_GetAsUInt64(param);
                if (params.aes_variant < RFC9173_BCB_AES_VARIANT_A128GCM
                    || params.aes_variant > RFC9173_BCB_AES_VARIANT_A256GCM)
                {
                    BSL_LOG_ERR("Unknown AES variant %lu", params.aes_variant);
                    params.err_count++;
                }
                break;
            }
            case RFC9173_BCB_SECPARAM_WRAPPEDKEY:
            {
                BSL_LOG_DEBUG("BCB parsing Wrapped key parameter (optid=%lu)", param->param_id);
                assert(!is_int);
                BSL_Data_t as_data;
                if (BSL_SecParam_GetAsBytestr(param, &as_data) < 0)
                {
                    params.err_count++;
                    break;
                }
                if (BSL_Data_InitView(&params.wrapped_key, as_data.len, as_data.ptr) < 0)
                {
                    BSL_LOG_ERR("Could not get view of wrapped key");
                    params.err_count++;
                    break;
                }
                break;
            }
            case RFC9173_BCB_SECPARAM_AADSCOPE:
            {
                assert(is_int);
                uint64_t aad_scope = BSL_SecParam_GetAsUInt64(param);
                if ((aad_scope & RFC9173_BCB_AADSCOPEFLAGID_INC_PRIM_BLOCK) == 0)
                {
                    BSL_LOG_DEBUG("BCB AAD does not contain primary block flag");
                    params.skip_aad_prim_block = true;
                }
                if ((aad_scope & RFC9173_BCB_AADSCOPEFLAGID_INC_TARGET_HEADER) == 0)
                {
                    BSL_LOG_DEBUG("BCB AAD does not contain target block flag");
                    params.skip_aad_target_block = true;
                }
                if ((aad_scope & RFC9173_BCB_AADSCOPEFLAGID_INC_SECURITY_HEADER) == 0)
                {
                    BSL_LOG_DEBUG("BCB AAD does not contain security header");
                    params.skip_aad_sec_block = true;
                }
                break;
            }
            case BSL_SECPARAM_TYPE_INT_KEY_ID:
            {
                BSL_LOG_DEBUG("BCB parsing Key ID (optid=%lu)", param->param_id);
                assert(is_int);
                params.key_id = BSL_SecParam_GetAsUInt64(param);
                break;
            }
            default:
            {
                BSL_LOG_ERR("Unexpected param ID: %lu", param->param_id);
                params.err_count++;
            }
        }
    }
    return params;
}

BSL_Data_t BSLX_ValidateBCBInput(const BSL_BundleCtx_t *bundle, BSL_SecOper_t *sec_oper)
{
    BSL_Data_t target_btsd;
    BSL_BundleContext_GetBlockMetadata(bundle, sec_oper->target_block_num, NULL, NULL, NULL, &target_btsd);
    if (target_btsd.len == 0)
    {
        BSL_LOG_ERR("BTSD input to BCB is empty!");
    }
    return target_btsd;
}

int BSLX_ExecuteBCB(BSL_LibCtx_t *lib, const BSL_BundleCtx_t *bundle, const BSL_SecOper_t *sec_oper,
                    BSL_SecOutcome_t *sec_outcome)
{
    (void)lib;
    CHKERR1(bundle != NULL);
    CHKERR1(sec_oper != NULL);
    CHKERR1(sec_outcome != NULL);

    BSL_Data_t target_block_btsd;
    if (BSL_BundleContext_GetBlockMetadata(bundle, sec_oper->target_block_num, NULL, NULL, NULL, &target_block_btsd) < 0)
    {
        BSL_LOG_ERR("Could not get block metadata");
        return -2;
    }

    BSLX_ScratchSpace_t        scratch      = { .buffer   = sec_outcome->allocation.ptr,
                                                .position = 0,
                                                .size     = sec_outcome->allocation.len };
    
    BSLX_BCBParams_t params = BSLX_GetBCBParams(bundle, sec_oper);
    BSLX_BCBEncryptCtx_t bcb_ctx = BSLX_BCBContext_Initialize(params, target_block_btsd, &scratch);
    BSLX_BCBEncryptCtx_t final_result;
    if (params.crypto_mode == BSL_CRYPTO_ENCRYPT)
    {
        final_result = BSLX_BCBContext_Encrypt(BSLX_BCBContext_ComputeAAD(bcb_ctx));

        // Append the security result to the sop outcome list.
        if (final_result.authtag.len > 0)
        {
            BSL_Log_DumpAsHexString(final_result.debugstr.ptr, final_result.debugstr.len, final_result.authtag.ptr,
                                    final_result.authtag.len);
            BSL_SecResult_t *auth_tag_result = BSLX_ScratchSpace_take(&scratch, sizeof(*auth_tag_result));
            BSL_SecResult_Init(auth_tag_result, RFC9173_BCB_RESULTID_AUTHTAG, RFC9173_CONTEXTID_BCB_AES_GCM,
                            sec_oper->target_block_num, final_result.authtag);
            BSL_SecOutcome_AppendResult(sec_outcome, auth_tag_result);

            BSL_SeqWriter_t writer;
            BSL_SeqWriter_t *writer_ptr = &writer;
            int r = BSL_BundleCtx_WriteBTSD((BSL_BundleCtx_t *)bundle, sec_oper->target_block_num, &writer_ptr);
            CHKERR1(r == 0);
            size_t len = final_result.ciphertext.len;
            r = BSL_SeqWriter_Put(writer_ptr, final_result.ciphertext.ptr, &len);
            CHKERR1(r == 0);
            BSL_SeqWriter_Deinit(writer_ptr);
        }

        BSL_FREE(final_result.ciphertext.ptr);  // Since this pointer is used with writer, needs this FREE, else memleak
                                                // Is there a way around this as the standard workflow?
    }
    else
    {
        BSL_Data_t asb_btsd;
        if (BSL_BundleContext_GetBlockMetadata(bundle, sec_oper->sec_block_num, NULL, NULL, NULL, &asb_btsd) < 0)
        {
            BSL_LOG_ERR("Could not get block metadata");
            return -2;
        }

        BSL_AbsSecBlock_t bcb_asb;
        BSL_AbsSecBlock_DecodeFromCBOR(&bcb_asb, asb_btsd);
        
        BSL_LOG_INFO("Decrypt/acceptor: %d sec results in asb", BSL_SecResultList_size(bcb_asb.results));
        BSL_SecResult_t *authtag_result;
        for (size_t i = 0 ; i < BSL_SecResultList_size(bcb_asb.results); i++)
        {
            authtag_result = BSL_SecResultList_get(bcb_asb.results, i);

            // find the authtag in the sec result list by matching target block id
            if (authtag_result->target_block_num == sec_oper->target_block_num && authtag_result->result_id == 1)
            {
                memcpy(bcb_ctx.authtag.ptr, authtag_result->_bytes, authtag_result->_bytelen);
                bcb_ctx.authtag.len = authtag_result->_bytelen;
                bcb_ctx.authtag.owned = 0;
            }
        }

        final_result = BSLX_BCBContext_Decrypt(BSLX_BCBContext_ComputeAAD(bcb_ctx));

        if (final_result.success)
        {
            BSL_SeqWriter_t writer;
            BSL_SeqWriter_t *writer_ptr = &writer;

            // modify the target block BTSD in-place
            int r = BSL_BundleCtx_WriteBTSD((BSL_BundleCtx_t *)bundle, sec_oper->target_block_num, &writer_ptr);
            CHKERR1(r == 0);
            size_t len = final_result.plaintext.len;
            r = BSL_SeqWriter_Put(writer_ptr, final_result.plaintext.ptr, &len);
            CHKERR1(r == 0);
            r = BSL_SeqWriter_Deinit(writer_ptr);
            CHKERR1(r == 0);
        }

        BSL_AbsSecBlock_Deinit(&bcb_asb);
        BSL_FREE(final_result.plaintext.ptr);
    }

    return final_result.success == true ? 0 : -1;
}
