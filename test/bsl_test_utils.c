/*
 * Copyright (c) 2025 The Johns Hopkins University Applied Physics
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
#include <assert.h>

#include <m-string.h>

#include <BPSecLib_Private.h>
#include <CryptoInterface.h>
#include <mock_bpa/MockBPA.h>

#include <backend/SecParam.h>
#include <backend/SecurityActionSet.h>
#include <backend/UtilDefs_SeqReadWrite.h>
#include <policy_provider/SamplePolicyProvider.h>
#include <security_context/DefaultSecContext.h>

#include "bsl_test_utils.h"
#include <security_context/rfc9173.h>

#define quick_data(field, tgt) \
    field.len = sizeof(tgt);   \
    field.ptr = (uint8_t *)tgt

void BIBTestContext_Deinit(BIBTestContext *obj)
{
    BSL_SecOper_Deinit(&obj->sec_oper);
}

void BSL_TestUtils_InitBIB_AppendixA1(BIBTestContext *context, BSL_SecRole_e role, const char *key_id)
{
    quick_data(context->hmac, ApxA1_HMAC);

    BSL_SecParam_InitStr(&context->param_test_key, BSL_SECPARAM_TYPE_KEY_ID, key_id);
    BSL_SecParam_InitInt64(&context->param_scope_flags, RFC9173_BIB_PARAMID_INTEG_SCOPE_FLAG, 0);
    BSL_SecParam_InitInt64(&context->param_sha_variant, RFC9173_BIB_PARAMID_SHA_VARIANT, RFC9173_BIB_SHA_HMAC512);
    BSL_SecParam_InitBytestr(&context->param_hmac, BSL_SECPARAM_TYPE_AUTH_TAG, context->hmac);
    BSL_SecParam_InitInt64(&context->use_key_wrap, BSL_SECPARAM_USE_KEY_WRAP, 0);

    BSL_SecOper_Init(&context->sec_oper);
    BSL_SecOper_Populate(&context->sec_oper, 1, 1, 2, BSL_SECBLOCKTYPE_BIB, role, BSL_POLICYACTION_DROP_BLOCK);

    BSL_SecOper_AppendParam(&context->sec_oper, &context->param_sha_variant);
    BSL_SecOper_AppendParam(&context->sec_oper, &context->param_scope_flags);
    BSL_SecOper_AppendParam(&context->sec_oper, &context->param_test_key);
    BSL_SecOper_AppendParam(&context->sec_oper, &context->use_key_wrap);
}

void BSL_TestUtils_InitBCB_Appendix2(BCBTestContext *context, BSL_SecRole_e role)
{
    quick_data(context->init_vector, ApxA2_InitVec);
    quick_data(context->auth_tag, ApxA2_AuthTag);
    quick_data(context->wrapped_key, ApxA2_WrappedKey);
    quick_data(context->key_enc_key, ApxA2_KeyEncKey);

    BSL_SecParam_InitInt64(&context->param_scope_flags, RFC9173_BCB_SECPARAM_AADSCOPE, 0);
    BSL_SecParam_InitStr(&context->param_test_key_id, BSL_SECPARAM_TYPE_KEY_ID, RFC9173_EXAMPLE_A2_KEY);
    BSL_SecParam_InitInt64(&context->param_aes_variant, RFC9173_BCB_SECPARAM_AESVARIANT,
                           RFC9173_BCB_AES_VARIANT_A128GCM);
    BSL_SecParam_InitBytestr(&context->param_init_vec, RFC9173_BCB_SECPARAM_IV, context->init_vector);
    BSL_SecParam_InitBytestr(&context->param_auth_tag, BSL_SECPARAM_TYPE_AUTH_TAG, context->auth_tag);
    BSL_SecParam_InitBytestr(&context->param_wrapped_key, RFC9173_BCB_SECPARAM_WRAPPEDKEY, context->wrapped_key);
    BSL_SecParam_InitInt64(&context->use_wrap_key, BSL_SECPARAM_USE_KEY_WRAP, 1);

    BSL_SecOper_Init(&context->sec_oper);
    BSL_SecOper_Populate(&context->sec_oper, 2, 1, 2, BSL_SECBLOCKTYPE_BCB, role, BSL_POLICYACTION_NOTHING);

    BSL_SecOper_AppendParam(&context->sec_oper, &context->param_init_vec);
    BSL_SecOper_AppendParam(&context->sec_oper, &context->param_aes_variant);
    BSL_SecOper_AppendParam(&context->sec_oper, &context->param_wrapped_key);
    BSL_SecOper_AppendParam(&context->sec_oper, &context->use_wrap_key);
    BSL_SecOper_AppendParam(&context->sec_oper, &context->param_scope_flags);
    if (role != BSL_SECROLE_SOURCE)
        BSL_SecOper_AppendParam(&context->sec_oper, &context->param_auth_tag);
    BSL_SecOper_AppendParam(&context->sec_oper, &context->param_test_key_id);
}

BSL_SecurityActionSet_t *BSL_TestUtils_InitMallocBIBActionSet(BIBTestContext *bib_context)
{
    BSL_SecurityActionSet_t *action_set = BSL_CALLOC(1, sizeof(BSL_SecurityActionSet_t));
    BSL_SecurityActionSet_Init(action_set);
    BSL_SecurityAction_t *act = BSL_CALLOC(1, sizeof(BSL_SecurityAction_t));
    BSL_SecurityAction_Init(act);
    BSL_SecurityAction_AppendSecOper(act, &bib_context->sec_oper);
    // ensure consistent context state
    BSL_SecOper_Init(&bib_context->sec_oper);
    BSL_SecurityActionSet_AppendAction(action_set, act);
    BSL_SecurityAction_Deinit(act);
    BSL_FREE(act);
    return action_set;
}

BSL_SecurityResponseSet_t *BSL_TestUtils_MallocEmptyPolicyResponse(void)
{
    return BSL_CALLOC(1, BSL_SecurityResponseSet_Sizeof());
}

int rfc9173_byte_gen_fn_a1(unsigned char *buf, int len)
{
    if (len == 12) // IV
    {
        uint8_t iv[] = { 0x54, 0x77, 0x65, 0x6c, 0x76, 0x65, 0x31, 0x32, 0x31, 0x32, 0x31, 0x32 };
        memcpy(buf, iv, 12);
    }
    else // A1 KEY
    {
        uint8_t rfc9173A1_key[] = { 0x1a, 0x2b, 0x1a, 0x2b, 0x1a, 0x2b, 0x1a, 0x2b,
                                    0x1a, 0x2b, 0x1a, 0x2b, 0x1a, 0x2b, 0x1a, 0x2b };
        memcpy(buf, rfc9173A1_key, len);
    }
    return 1;
}

int rfc9173_byte_gen_fn_a2_kek(unsigned char *buf, int len)
{
    if (len == 12) // IV
    {
        uint8_t iv[] = { 0x54, 0x77, 0x65, 0x6c, 0x76, 0x65, 0x31, 0x32, 0x31, 0x32, 0x31, 0x32 };
        memcpy(buf, iv, 12);
    }
    else // A2 KEY
    {
        uint8_t rfc9173A2_key[] = { 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68,
                                    0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70 };
        memcpy(buf, rfc9173A2_key, len);
    }
    return 1;
}

int rfc9173_byte_gen_fn_a2_cek(unsigned char *buf, int len)
{
    if (len == 12) // IV
    {
        uint8_t iv[] = { 0x54, 0x77, 0x65, 0x6c, 0x76, 0x65, 0x31, 0x32, 0x31, 0x32, 0x31, 0x32 };
        memcpy(buf, iv, 12);
    }
    else // A3 KEY
    {
        uint8_t rfc9173A3_key[] = { 0x71, 0x77, 0x65, 0x72, 0x74, 0x79, 0x75, 0x69,
                                    0x6f, 0x70, 0x61, 0x73, 0x64, 0x66, 0x67, 0x68 };
        memcpy(buf, rfc9173A3_key, len);
    }
    return 1;
}

int rfc9173_byte_gen_fn_a4(unsigned char *buf, int len)
{
    if (len == 12) // IV
    {
        uint8_t iv[] = { 0x54, 0x77, 0x65, 0x6c, 0x76, 0x65, 0x31, 0x32, 0x31, 0x32, 0x31, 0x32 };
        memcpy(buf, iv, 12);
    }
    else // A4 KEY
    {
        uint8_t rfc9173A4_key[] = { 0x71, 0x77, 0x65, 0x72, 0x74, 0x79, 0x75, 0x69, 0x6f, 0x70, 0x61,
                                    0x73, 0x64, 0x66, 0x67, 0x68, 0x71, 0x77, 0x65, 0x72, 0x74, 0x79,
                                    0x75, 0x69, 0x6f, 0x70, 0x61, 0x73, 0x64, 0x66, 0x67, 0x68 };
        memcpy(buf, rfc9173A4_key, len);
    }
    return 1;
}

void BSL_TestUtils_SetupDefaultSecurityContext(BSL_LibCtx_t *bsl_lib)
{
    assert(bsl_lib != NULL);

    BSL_CryptoInit();
    uint8_t rfc9173A1_key[]     = { 0x1a, 0x2b, 0x1a, 0x2b, 0x1a, 0x2b, 0x1a, 0x2b,
                                    0x1a, 0x2b, 0x1a, 0x2b, 0x1a, 0x2b, 0x1a, 0x2b };
    uint8_t rfc9173A2_key[]     = { 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68,
                                    0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70 };
    uint8_t rfc9173A3_key[]     = { 0x71, 0x77, 0x65, 0x72, 0x74, 0x79, 0x75, 0x69,
                                    0x6f, 0x70, 0x61, 0x73, 0x64, 0x66, 0x67, 0x68 };
    uint8_t rfc9173A4_BCB_key[] = { 0x71, 0x77, 0x65, 0x72, 0x74, 0x79, 0x75, 0x69, 0x6f, 0x70, 0x61,
                                    0x73, 0x64, 0x66, 0x67, 0x68, 0x71, 0x77, 0x65, 0x72, 0x74, 0x79,
                                    0x75, 0x69, 0x6f, 0x70, 0x61, 0x73, 0x64, 0x66, 0x67, 0x68 };
    BSL_Crypto_AddRegistryKey(RFC9173_EXAMPLE_A1_KEY, rfc9173A1_key, 16);
    BSL_Crypto_AddRegistryKey(RFC9173_EXAMPLE_A2_KEY, rfc9173A2_key, 16);
    BSL_Crypto_AddRegistryKey(RFC9173_EXAMPLE_A3_KEY, rfc9173A3_key, sizeof(rfc9173A3_key));
    BSL_Crypto_AddRegistryKey(RFC9173_EXAMPLE_A4_BCB_KEY, rfc9173A4_BCB_key, sizeof(rfc9173A4_BCB_key));

    BSL_SecCtxDesc_t bib_sec_desc;
    bib_sec_desc.execute  = BSLX_BIB_Execute;
    bib_sec_desc.validate = BSLX_BIB_Validate;
    assert(0 == BSL_API_RegisterSecurityContext(bsl_lib, 1, bib_sec_desc));

    BSL_SecCtxDesc_t bcb_sec_desc;
    bcb_sec_desc.execute  = BSLX_BCB_Execute;
    bcb_sec_desc.validate = BSLX_BCB_Validate;
    assert(0 == BSL_API_RegisterSecurityContext(bsl_lib, 2, bcb_sec_desc));
}

bool BSL_TestUtils_IsB16StrEqualTo(const char *b16_string, BSL_Data_t encoded_val)
{
    string_t in_text;
    string_init_set_str(in_text, b16_string);
    BSL_Data_t in_data;
    BSL_Data_Init(&in_data);
    in_data.owned = 1;
    if (BSL_TestUtils_DecodeBase16(&in_data, in_text) != 0)
    {
        BSL_Data_Deinit(&in_data);
        string_clear(in_text);
        assert(0);
        // TEST_ASSERT_MESSAGE(0, "Could not base16-decode sequence");
    }
    string_clear(in_text);

    BSL_TestUtils_PrintHexToBuffer("actual str  : ", encoded_val.ptr, encoded_val.len);
    BSL_TestUtils_PrintHexToBuffer("expected str: ", in_data.ptr, in_data.len);
    if (encoded_val.len != in_data.len)
    {
        BSL_LOG_ERR("Mismatch, got %zu bytes, expected %zu bytes", encoded_val.len, in_data.len);
        BSL_Data_Deinit(&in_data);
        return false;
    }

    int r = memcmp(encoded_val.ptr, in_data.ptr, in_data.len);
    BSL_Data_Deinit(&in_data);
    return r == 0 ? true : false;
}

void BSL_TestUtils_PrintHexToBuffer(const char *message, uint8_t *buff, size_t bufflen)
{
    uint8_t ascii_buf[2 * bufflen + 1];
    BSL_Log_DumpAsHexString(ascii_buf, sizeof(ascii_buf), buff, bufflen);
    BSL_LOG_INFO("%s :: %s", message, ascii_buf);
}

int BSL_TestUtils_LoadBundleFromCBOR(BSL_TestContext_t *test_ctx, const char *cbor_seq)
{
    assert(test_ctx != NULL);
    assert(cbor_seq != NULL);

    string_t in_text;
    string_init_set_str(in_text, cbor_seq);
    BSL_Data_t in_data;
    BSL_Data_Init(&in_data);
    in_data.owned = 1;
    if (BSL_TestUtils_DecodeBase16(&in_data, in_text) != 0)
    {
        BSL_Data_Deinit(&in_data);
        string_clear(in_text);
        return -1;
    }
    string_clear(in_text);

    test_ctx->mock_bpa_ctr.encoded       = in_data;
    test_ctx->mock_bpa_ctr.encoded.owned = 1;

    MockBPA_Bundle_t *bundle = test_ctx->mock_bpa_ctr.bundle_ref.data;
    assert(bundle != NULL);

    int decode_status = mock_bpa_decode(&(test_ctx->mock_bpa_ctr));
    assert(bundle->primary_block.version == 7);
    assert(bundle->primary_block.timestamp.seq_num > 0);
    assert(bundle->primary_block.lifetime > 0);
    assert(bundle->primary_block.flags <= 64);
    assert(bundle->primary_block.crc_type <= 4);
    assert(MockBPA_BlockList_size(bundle->blocks) > 0);
    assert(MockBPA_BlockByNum_size(bundle->blocks_num) > 0);
    return decode_status;
}

BSL_HostEIDPattern_t BSL_TestUtils_GetEidPatternFromText(const char *text)
{
    BSL_HostEIDPattern_t pat;
    BSL_HostEIDPattern_Init(&pat);
    assert(0 == BSL_HostEIDPattern_DecodeFromText(&pat, text));
    return pat;
}

RFC9173_A1_Params BSL_TestUtils_GetRFC9173_A1Params(const char *key_id)
{
    RFC9173_A1_Params params = { 0 };
    BSL_SecParam_InitInt64(&params.sha_variant, RFC9173_TestVectors_AppendixA1.bib_asb_sha_variant_key,
                           RFC9173_TestVectors_AppendixA1.bib_asb_sha_variant_value);
    BSL_SecParam_InitInt64(&params.scope_flags, RFC9173_TestVectors_AppendixA1.bib_asb_scope_flags_key,
                           RFC9173_TestVectors_AppendixA1.bib_asb_scope_flags_value);
    BSL_SecParam_InitStr(&params.test_key_id, BSL_SECPARAM_TYPE_KEY_ID, key_id);
    BSL_SecParam_InitInt64(&params.use_wrap_key, BSL_SECPARAM_USE_KEY_WRAP, 0);
    return params;
}

int BSL_TestUtils_EncodeBase16(string_t out, const BSL_Data_t *in, bool uppercase)
{
    const char *fmt = uppercase ? "%02X" : "%02x";

    const uint8_t *curs = in->ptr;
    const uint8_t *end  = curs + in->len;
    for (; curs < end; ++curs)
    {
        string_cat_printf(out, fmt, *curs);
    }
    return 0;
}

/// Size of the @c BSL_TestUtils_DecodeBase16_table
static const size_t BSL_TestUtils_DecodeBase16_lim = 0x80;
// clang-format off
/// Decode table for base16
static const int BSL_TestUtils_DecodeBase16_table[0x80] =
{
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -2, -2, -1, -1, -2, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -2, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
     0,  1,  2,  3,  4,  5,  6,  7,  8,  9, -1, -1, -1, -1, -1, -1,
    -1, 10, 11, 12, 13, 14, 15, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, 10, 11, 12, 13, 14, 15, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
};
// clang-format on

/** Decode a single character.
 *
 * @param chr The character to decode.
 * @return If positive, the decoded value.
 * -1 to indicate error.
 * -2 to indicate whitespace.
 */
static int BSL_TestUtils_DecodeBase16_char(uint8_t chr)
{
    if (chr >= BSL_TestUtils_DecodeBase16_lim)
    {
        return -1;
    }
    return BSL_TestUtils_DecodeBase16_table[chr];
}

int BSL_TestUtils_DecodeBase16(BSL_Data_t *out, const string_t in)
{
    CHKERR1(out);
    CHKERR1(in);

    const size_t in_len = string_size(in);
    if (in_len % 2 != 0)
    {
        return 1;
    }
    const char *curs = string_get_cstr(in);
    const char *end  = curs + in_len;

    if (BSL_Data_Resize(out, in_len / 2))
    {
        return 2;
    }
    uint8_t *out_curs = out->ptr;

    while (curs < end)
    {
        const int high = BSL_TestUtils_DecodeBase16_char(*(curs++));
        const int low  = BSL_TestUtils_DecodeBase16_char(*(curs++));
        if ((high < 0) || (low < 0))
        {
            return 3;
        }

        const uint8_t byte = (uint8_t)((high << 4) | low);
        *(out_curs++)      = byte;
    }
    return 0;
}

int BSL_TestUtils_ModifyEIDs(BSL_BundleRef_t *input_bundle, const char *src_eid, const char *dest_eid,
                             const char *report_to_eid)
{
    BSL_PrimaryBlock_t primary_block = { 0 };
    BSL_BundleCtx_GetBundleMetadata(input_bundle, &primary_block);
    int res = 0;
    if (src_eid)
    {
        res |= (!!mock_bpa_eid_from_text(&(primary_block.field_src_node_id), src_eid, NULL));
    }
    if (dest_eid)
    {
        res |= (!!mock_bpa_eid_from_text(&(primary_block.field_dest_eid), dest_eid, NULL) << 1);
    }
    if (report_to_eid)
    {
        res |= (!!mock_bpa_eid_from_text(&(primary_block.field_report_to_eid), report_to_eid, NULL) << 2);
    }
    BSL_PrimaryBlock_deinit(&primary_block);

    return res;
}

/// Internal state for reader and writer
struct BSL_TestUtils_Flat_Data_s
{
    /// Pointer to external buffer pointer
    void **origbuf;
    /// Pointer to external size
    size_t *origsize;

    /// Pointer to the head of the buffer
    char *ptr;
    /// Working size of the buffer
    size_t size;
    /// File opened for the buffer
    FILE *file;
};

static int BSL_TestUtils_ReadBTSD_Read(void *user_data, void *buf, size_t *bufsize)
{
    struct BSL_TestUtils_Flat_Data_s *obj = user_data;
    if (!obj || !obj->file)
    {
        return -1;
    }

    const size_t got = fread(buf, 1, *bufsize, obj->file);
    *bufsize         = got;
    return 0;
}

static void BSL_TestUtils_ReadBTSD_Deinit(void *user_data)
{
    struct BSL_TestUtils_Flat_Data_s *obj = user_data;
    if (!obj || !obj->file)
    {
        return;
    }

    fclose(obj->file);
    // buffer is external data, no cleanup
    BSL_FREE(obj);
}

BSL_SeqReader_t *BSL_TestUtils_FlatReader(const void *buf, size_t bufsize)
{
    struct BSL_TestUtils_Flat_Data_s *obj = BSL_CALLOC(1, sizeof(struct BSL_TestUtils_Flat_Data_s));
    ASSERT_PROPERTY(obj);
    obj->origbuf  = NULL;
    obj->origsize = NULL;
    obj->ptr      = (void *)buf;
    obj->size     = bufsize;
    obj->file     = fmemopen(obj->ptr, obj->size, "rb");

    BSL_SeqReader_t *reader = BSL_MALLOC(sizeof(BSL_SeqReader_t));
    ASSERT_PROPERTY(reader);
    reader->user_data = obj;
    reader->read      = BSL_TestUtils_ReadBTSD_Read;
    reader->deinit    = BSL_TestUtils_ReadBTSD_Deinit;

    return reader;
}

static int BSL_TestUtils_WriteBTSD_Write(void *user_data, const void *buf, size_t size)
{
    struct BSL_TestUtils_Flat_Data_s *obj = user_data;
    if (!obj || !obj->file)
    {
        return -1;
    }

    const size_t got = fwrite(buf, 1, size, obj->file);
    if (got < size)
    {
        return BSL_ERR_FAILURE;
    }
    return BSL_SUCCESS;
}

static void BSL_TestUtils_WriteBTSD_Deinit(void *user_data)
{
    struct BSL_TestUtils_Flat_Data_s *obj = user_data;
    if (!obj || !obj->file)
    {
        return;
    }

    fclose(obj->file);

    // now write-back the result
    if (obj->origbuf)
    {
        *obj->origbuf = obj->ptr;
    }
    if (obj->origsize)
    {
        *obj->origsize = obj->size;
    }

    BSL_FREE(obj);
}

BSL_SeqWriter_t *BSL_TestUtils_FlatWriter(void **buf, size_t *bufsize)
{
    struct BSL_TestUtils_Flat_Data_s *obj = BSL_CALLOC(1, sizeof(struct BSL_TestUtils_Flat_Data_s));
    ASSERT_PROPERTY(obj);
    // double-buffer for this write
    obj->origbuf  = buf;
    obj->origsize = bufsize;
    obj->ptr      = NULL;
    obj->size     = 0;
    obj->file     = open_memstream(&obj->ptr, &obj->size);

    BSL_SeqWriter_t *writer = BSL_MALLOC(sizeof(BSL_SeqWriter_t));
    ASSERT_PROPERTY(writer);
    writer->user_data = obj;
    writer->write     = BSL_TestUtils_WriteBTSD_Write;
    writer->deinit    = BSL_TestUtils_WriteBTSD_Deinit;

    return writer;
}
