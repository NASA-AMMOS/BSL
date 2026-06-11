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
#undef NDEBUG // force assertions
#include <assert.h>

#include <m-string.h>

#include <BPSecLib_Private.h>
#include <CryptoInterface.h>
#include <mock_bpa/MockBPA.h>

#include <backend/SecParam.h>
#include <backend/SecurityActionSet.h>
#include <backend/UtilDefs_SeqReadWrite.h>
#include <policy_provider/SamplePolicyProvider.h>
#include <default_sc/DefaultSecContext.h>
#include <default_sc/rfc9173.h>

#include "bsl_test_utils.h"

#define quick_data(field, tgt) \
    field.len = sizeof(tgt);   \
    field.ptr = (uint8_t *)tgt

void BIBTestContext_Init(BIBTestContext *obj)
{
    BSL_Data_Init(&obj->hmac);
    BSL_SecOper_Init(&obj->sec_oper);

    BSL_SecParam_Init(&obj->param_test_key);
    BSL_SecParam_Init(&obj->param_sha_variant);
    BSL_SecParam_Init(&obj->param_hmac);
    BSL_SecParam_Init(&obj->param_wrapped_key);
    BSL_SecParam_Init(&obj->use_key_wrap);
    BSL_SecParam_Init(&obj->param_scope_flags);
    BSL_SecParam_Init(&obj->param_wrapped_key_aes);
}

void BIBTestContext_Deinit(BIBTestContext *obj)
{
    BSL_SecParam_Deinit(&obj->param_test_key);
    BSL_SecParam_Deinit(&obj->param_sha_variant);
    BSL_SecParam_Deinit(&obj->param_hmac);
    BSL_SecParam_Deinit(&obj->param_wrapped_key);
    BSL_SecParam_Deinit(&obj->use_key_wrap);
    BSL_SecParam_Deinit(&obj->param_scope_flags);
    BSL_SecParam_Deinit(&obj->param_wrapped_key_aes);

    BSL_SecOper_Deinit(&obj->sec_oper);
    BSL_Data_Deinit(&obj->hmac);
}

void BCBTestContext_Init(BCBTestContext *obj)
{
    BSL_SecOper_Init(&obj->sec_oper);

    BSL_SecParam_Init(&obj->param_aes_variant);
    BSL_SecParam_Init(&obj->param_scope_flags);
    BSL_SecParam_Init(&obj->param_test_key_id);
    BSL_SecParam_Init(&obj->param_init_vec);
    BSL_SecParam_Init(&obj->param_auth_tag);
    BSL_SecParam_Init(&obj->param_wrapped_key);
    BSL_SecParam_Init(&obj->use_key_wrap);
    BSL_SecParam_Init(&obj->param_key_enc_key);
    BSL_SecParam_Init(&obj->param_content_enc_key);
}

void BCBTestContext_Deinit(BCBTestContext *obj)
{
    BSL_SecParam_Deinit(&obj->param_aes_variant);
    BSL_SecParam_Deinit(&obj->param_scope_flags);
    BSL_SecParam_Deinit(&obj->param_test_key_id);
    BSL_SecParam_Deinit(&obj->param_init_vec);
    BSL_SecParam_Deinit(&obj->param_auth_tag);
    BSL_SecParam_Deinit(&obj->param_wrapped_key);
    BSL_SecParam_Deinit(&obj->use_key_wrap);
    BSL_SecParam_Deinit(&obj->param_key_enc_key);
    BSL_SecParam_Deinit(&obj->param_content_enc_key);

    BSL_SecOper_Deinit(&obj->sec_oper);
}

void BSL_TestUtils_InitBIB_AppendixA1(BIBTestContext *context, BSL_SecRole_e role, const char *key_id)
{
    BSL_TestUtils_DecodeBase16_cstr(&context->hmac, RFC9173_TestVectors_AppendixA1.hex_hmac);

    BSL_SecParam_InitTextstr(&context->param_test_key, BSL_SECPARAM_TYPE_KEY_ID, key_id);
    BSL_SecParam_InitUint64(&context->param_scope_flags, RFC9173_BIB_PARAMID_INTEG_SCOPE_FLAG, 0);
    BSL_SecParam_InitUint64(&context->param_sha_variant, RFC9173_BIB_PARAMID_SHA_VARIANT, RFC9173_BIB_SHA_HMAC512);
    BSL_SecParam_InitBytestr(&context->param_hmac, BSL_SECPARAM_TYPE_AUTH_TAG, context->hmac);
    BSL_SecParam_InitUint64(&context->use_key_wrap, BSL_SECPARAM_USE_KEY_WRAP, 0);

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

    BSL_SecParam_InitUint64(&context->param_scope_flags, RFC9173_BCB_SECPARAM_AADSCOPE, 0);
    BSL_SecParam_InitTextstr(&context->param_test_key_id, BSL_SECPARAM_TYPE_KEY_ID, RFC9173_EXAMPLE_A2_KEY);
    BSL_SecParam_InitUint64(&context->param_aes_variant, RFC9173_BCB_SECPARAM_AESVARIANT,
                            RFC9173_BCB_AES_VARIANT_A128GCM);
    BSL_SecParam_InitBytestr(&context->param_init_vec, RFC9173_BCB_SECPARAM_IV, context->init_vector);
    BSL_SecParam_InitBytestr(&context->param_auth_tag, BSL_SECPARAM_TYPE_AUTH_TAG, context->auth_tag);
    BSL_SecParam_InitBytestr(&context->param_wrapped_key, RFC9173_BCB_SECPARAM_WRAPPEDKEY, context->wrapped_key);
    BSL_SecParam_InitUint64(&context->use_key_wrap, BSL_SECPARAM_USE_KEY_WRAP, 1);

    BSL_SecOper_Populate(&context->sec_oper, 2, 1, 2, BSL_SECBLOCKTYPE_BCB, role, BSL_POLICYACTION_NOTHING);

    BSL_SecOper_AppendParam(&context->sec_oper, &context->param_init_vec);
    BSL_SecOper_AppendParam(&context->sec_oper, &context->param_aes_variant);
    BSL_SecOper_AppendParam(&context->sec_oper, &context->param_wrapped_key);
    BSL_SecOper_AppendParam(&context->sec_oper, &context->use_key_wrap);
    BSL_SecOper_AppendParam(&context->sec_oper, &context->param_scope_flags);
    if (role != BSL_SECROLE_SOURCE)
        BSL_SecOper_AppendParam(&context->sec_oper, &context->param_auth_tag);
    BSL_SecOper_AppendParam(&context->sec_oper, &context->param_test_key_id);
}

const struct RFC9173_TestVectors_AppendixA1 RFC9173_TestVectors_AppendixA1 = {
    // BIB Abstract Security block fields
    // Source: https://www.rfc-editor.org/rfc/rfc9173.html#appendix-A.1.3.2
    1, // bib_asb_sec_target
    1, // bib_asb_context_id
    1, // bib_asb_context_flags
    1, // bib_asb_sha_variant_key
    7, // bib_asb_sha_variant_value (HMAC 512/512)
    3, // bib_asb_scope_flags_key
    0, // bib_asb_scope_flags_value (No additional scope)

    // bundle_original: The full bundle without any security
    // Source: https://www.rfc-editor.org/rfc/rfc9173.html#appendix-A.1.1.3
    ("9f88070000820282010282028202018202820201820018281a000f424085010100"
     "005823526561647920746f2067656e657261746520612033322d6279746520706179"
     "6c6f6164ff"),

    // bundle_bib: The full bundle encoding with BIB block
    // Source: https://www.rfc-editor.org/rfc/rfc9173.html#appendix-A.1.4
    ("9f88070000820282010282028202018202820201820018281a000f4240850b0200"
     "005856810101018202820201828201078203008181820158403bdc69b3a34a2b5d3a"
     "8554368bd1e808f606219d2a10a846eae3886ae4ecc83c4ee550fdfb1cc636b904e2"
     "f1a73e303dcd4b6ccece003e95e8164dcc89a156e185010100005823526561647920"
     "746f2067656e657261746520612033322d62797465207061796c6f6164ff"),

    // payload_block: The CBOR of just the payload block
    // Source: https://www.rfc-editor.org/rfc/rfc9173.html#appendix-A.1.1.2
    ("85010100005823526561647920746f2067656e657261746520612033322d627974"
     "65207061796c6f6164"),

    // primary_block: CBOR of just the primary block
    // Source: https://www.rfc-editor.org/rfc/rfc9173.html#appendix-A.1.1.1
    ("88070000820282010282028202018202820201820018281a000f4240"),

    // bib_block: CBOR encoding of the BIB block (headers and all)
    // Source: https://www.rfc-editor.org/rfc/rfc9173.html#appendix-A.1.3.3
    ("850b0200005856810101018202820201828201078203008181820158403bdc69b3"
     "a34a2b5d3a8554368bd1e808f606219d2a10a846eae3886ae4ecc83c4ee550fdfb1c"
     "c636b904e2f1a73e303dcd4b6ccece003e95e8164dcc89a156e1"),

    // bib_abs_sec_block: Encoding of the BIB Block-Type-Specific Data (Abstract Security Block)
    // Source: https://www.rfc-editor.org/rfc/rfc9173.html#appendix-A.1.3.2
    ("810101018202820201828201078203008181820158403bdc69b3a34a2b5d3a8554"
     "368bd1e808f606219d2a10a846eae3886ae4ecc83c4ee550fdfb1cc636b904e2f1a7"
     "3e303dcd4b6ccece003e95e8164dcc89a156e1"),

    // hmac: The actual HMAC digest (not including result type)
    // Source: https://www.rfc-editor.org/rfc/rfc9173.html#appendix-A.1.3.2
    ("3bdc69b3a34a2b5d3a8554368bd1e808"
     "f606219d2a10a846eae3886ae4ecc83c"
     "4ee550fdfb1cc636b904e2f1a73e303d"
     "cd4b6ccece003e95e8164dcc89a156e1")
};

const struct RFC9173_TestVectorsA2 RFC9173_TestVectors_AppendixA2 = {
    1, 2,

    // Content enc key
    "71776572747975696f70617364666768",

    // Key encryption key
    "6162636465666768696a6b6c6d6e6f70",

    // Init vector
    "5477656c7665313231323132",

    // Original bundle with just payload
    ("9f88070000820282010282028202018202820201820018281a000f424085010100"
     "005823526561647920746f2067656e657261746520612033322d6279746520706179"
     "6c6f6164ff"),

    // Fully-encoded bundle with BCB
    ("9f88070000820282010282028202018202820201820018281a000f4240850c0201"
     "0058508101020182028202018482014c5477656c7665313231323132820201820358"
     "1869c411276fecddc4780df42c8a2af89296fabf34d7fae7008204008181820150ef"
     "a4b5ac0108e3816c5606479801bc04850101000058233a09c1e63fe23a7f66a59c73"
     "03837241e070b02619fc59c5214a22f08cd70795e73e9aff"),

    // Auth tag
    "efa4b5ac0108e3816c5606479801bc04",

    // Ciphertext
    ("a09c1e63fe23a7f66a59c7303837241"
     "e070b02619fc59c5214a22f08cd70795"
     "e73e9a")
};

const struct RFC9173_TestVectors_A4_Modified RFC9173_TestVectors_AppendixA4 = {
    .hex_bundle_original = ("9f88070000820282010282028202018202820201820018"
                             "281A000F424085010100005823526561647920746F2067"
                             "656E657261746520612033322D62797465207061796C6F"
                             "6164ff"),
    .hex_bundle_final    = ("9f88070000820282010282028202018202820201820018"
                             "281A000F4240850B030000585681010101820282020182"
                             "8201078203008181820158403BDC69B3A34A2B5D3A8554"
                             "368BD1E808F606219D2A10A846EAE3886AE4ECC83C4EE5"
                             "50FDFB1CC636B904E2F1A73E303DCD4B6CCECE003E95E8"
                             "164DCC89A156E1850C0201005850810102018202820201"
                             "8482014C5477656C766531323132313282020182035818"
                             "69C411276FECDDC4780DF42C8A2AF89296FABF34D7FAE7"
                             "008204008181820150EFA4B5AC0108E3816C5606479801"
                             "BC04850101000058233A09C1E63FE23A7F66A59C730383"
                             "7241E070B02619FC59C5214A22F08CD70795E73E9Aff"),
};

BSL_SecurityActionSet_t *BSL_TestUtils_InitMallocBIBActionSet(BIBTestContext *bib_context)
{
    BSL_SecurityActionSet_t *action_set = BSL_calloc(1, sizeof(BSL_SecurityActionSet_t));
    BSL_SecurityActionSet_Init(action_set);
    BSL_SecurityAction_t *act = BSL_calloc(1, sizeof(BSL_SecurityAction_t));
    BSL_SecurityAction_Init(act);
    BSL_SecurityAction_AppendSecOper(act, &bib_context->sec_oper);
    // ensure consistent context state
    BSL_SecOper_Init(&bib_context->sec_oper);
    BSL_SecurityActionSet_AppendAction(action_set, act);
    BSL_SecurityAction_Deinit(act);
    BSL_free(act);
    return action_set;
}

BSL_SecurityResponseSet_t *BSL_TestUtils_MallocEmptyPolicyResponse(void)
{
    return BSL_calloc(1, BSL_SecurityResponseSet_Sizeof());
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

int BSL_TestContext_Init(BSL_TestContext_t *ctx, bool setupDefaultSecCtxs)
{
    memset(ctx, 0, sizeof(BSL_TestContext_t));
    if (BSL_SUCCESS != BSL_API_InitLib(&ctx->bsl))
    {
        return 1;
    }
    mock_bpa_ctr_init(&ctx->mock_bpa_ctr);
    if (setupDefaultSecCtxs)
    {
        BSL_TestUtils_SetupDefaultSecurityContext(&ctx->bsl);
    }
    return BSL_SUCCESS;
}

int BSL_TestContext_Deinit(BSL_TestContext_t *ctx)
{
    mock_bpa_ctr_deinit(&ctx->mock_bpa_ctr);
    if (BSL_SUCCESS != BSL_API_DeinitLib(&ctx->bsl))
    {
        return 1;
    }
    memset(ctx, 0, sizeof(BSL_TestContext_t));
    return BSL_SUCCESS;
}

void BSL_TestUtils_SetupDefaultSecurityContext(BSL_LibCtx_t *bsl_lib)
{
    assert(bsl_lib != NULL);

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

    BSL_SecCtxDesc_t sec_desc;
    int              res;

    sec_desc.execute  = BSLX_BIB_Execute;
    sec_desc.validate = BSLX_BIB_Validate;
    res               = BSL_API_RegisterSecurityContext(bsl_lib, 1, sec_desc);
    assert(0 == res);

    sec_desc.execute  = BSLX_BCB_Execute;
    sec_desc.validate = BSLX_BCB_Validate;
    res               = BSL_API_RegisterSecurityContext(bsl_lib, 2, sec_desc);
    assert(0 == res);
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
    char ascii_buf[2 * bufflen + 1];
    BSL_Log_DumpAsHexString(ascii_buf, sizeof(ascii_buf), buff, bufflen);
    BSL_LOG_INFO("%s :: %s", message, ascii_buf);
}

int BSL_TestUtils_LoadBundleFromCBOR(BSL_TestContext_t *test_ctx, const char *cborhex)
{
    assert(test_ctx != NULL);
    assert(cborhex != NULL);

    string_t in_text;
    string_init_set_str(in_text, cborhex);
    BSL_Data_t in_data;
    BSL_Data_Init(&in_data);
    in_data.owned = 1;
    if (BSL_TestUtils_DecodeBase16(&in_data, in_text) != 0)
    {
        BSL_LOG_ERR("Failed to decode base16 text from: %s", cborhex);
        BSL_Data_Deinit(&in_data);
        string_clear(in_text);
        return -1;
    }
    string_clear(in_text);

    test_ctx->mock_bpa_ctr.encoded       = in_data;
    test_ctx->mock_bpa_ctr.encoded.owned = 1;

    MockBPA_Bundle_t *bundle = test_ctx->mock_bpa_ctr.bundle_ref.data;
    assert(bundle != NULL);

    int decode_status = mock_bpa_ctr_decode(&(test_ctx->mock_bpa_ctr));
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
    RFC9173_A1_Params params;
    BSL_SecParam_InitUint64(&params.sha_variant, RFC9173_TestVectors_AppendixA1.bib_asb_sha_variant_key,
                            RFC9173_TestVectors_AppendixA1.bib_asb_sha_variant_value);
    BSL_SecParam_InitUint64(&params.scope_flags, RFC9173_TestVectors_AppendixA1.bib_asb_scope_flags_key,
                            RFC9173_TestVectors_AppendixA1.bib_asb_scope_flags_value);
    BSL_SecParam_InitTextstr(&params.test_key_id, BSL_SECPARAM_TYPE_KEY_ID, key_id);
    BSL_SecParam_InitUint64(&params.use_key_wrap, BSL_SECPARAM_USE_KEY_WRAP, 0);
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
    BSL_CHKERR1(out);
    BSL_CHKERR1(in);

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

int BSL_TestUtils_DecodeBase16_cstr(BSL_Data_t *output, const char *input)
{
    m_string_t mstr;
    m_string_init_set_cstr(mstr, input);
    int res = BSL_TestUtils_DecodeBase16(output, mstr);
    m_string_clear(mstr);
    return res;
}

int BSL_TestUtils_ModifyEIDs(BSL_BundleRef_t *input_bundle, const char *src_eid, const char *dest_eid,
                             const char *report_to_eid)
{
    BSL_PrimaryBlock_t primary_block;
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
    BSL_free(obj);
}

BSL_SeqReader_t *BSL_TestUtils_FlatReader(const void *buf, size_t bufsize)
{
    struct BSL_TestUtils_Flat_Data_s *obj = BSL_calloc(1, sizeof(struct BSL_TestUtils_Flat_Data_s));
    ASSERT_PROPERTY(obj);
    obj->origbuf  = NULL;
    obj->origsize = NULL;
    obj->ptr      = (void *)buf;
    obj->size     = bufsize;
    obj->file     = fmemopen(obj->ptr, obj->size, "rb");

    BSL_SeqReader_t *reader = BSL_malloc(sizeof(BSL_SeqReader_t));
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

    BSL_free(obj);
}

BSL_SeqWriter_t *BSL_TestUtils_FlatWriter(void **buf, size_t *bufsize)
{
    struct BSL_TestUtils_Flat_Data_s *obj = BSL_calloc(1, sizeof(struct BSL_TestUtils_Flat_Data_s));
    ASSERT_PROPERTY(obj);
    // double-buffer for this write
    obj->origbuf  = buf;
    obj->origsize = bufsize;
    obj->ptr      = NULL;
    obj->size     = 0;
    obj->file     = open_memstream(&obj->ptr, &obj->size);

    BSL_SeqWriter_t *writer = BSL_malloc(sizeof(BSL_SeqWriter_t));
    ASSERT_PROPERTY(writer);
    writer->user_data = obj;
    writer->write     = BSL_TestUtils_WriteBTSD_Write;
    writer->deinit    = BSL_TestUtils_WriteBTSD_Deinit;

    return writer;
}
