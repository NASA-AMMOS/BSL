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

#include <dynamic/IdValPair.h>
#include <dynamic/SecurityActionSet.h>
#include <dynamic/UtilDefs_SeqReadWrite.h>
#include <sample_pp/SamplePolicyProvider.h>
#include <default_sc/DefaultSecContext.h>

#include "DefaultScUtils.h"

#define quick_data(field, tgt) BSL_Data_InitView(&(field), sizeof(tgt), (BSL_DataPtr_t)(tgt))

void BIBTestContext_Init(BIBTestContext *obj)
{
    BSL_SecOper_Init(&obj->sec_oper);

    BSL_IdValPair_Init(&obj->opt_test_key);
    BSL_IdValPair_Init(&obj->opt_sha_variant);
    BSL_IdValPair_Init(&obj->opt_use_key_wrap);
    BSL_IdValPair_Init(&obj->opt_scope_flags);
}

void BIBTestContext_Deinit(BIBTestContext *obj)
{
    BSL_IdValPair_Deinit(&obj->opt_test_key);
    BSL_IdValPair_Deinit(&obj->opt_sha_variant);
    BSL_IdValPair_Deinit(&obj->opt_use_key_wrap);
    BSL_IdValPair_Deinit(&obj->opt_scope_flags);

    BSL_SecOper_Deinit(&obj->sec_oper);
}

void BCBTestContext_Init(BCBTestContext *obj)
{
    BSL_SecOper_Init(&obj->sec_oper);

    BSL_IdValPair_Init(&obj->opt_aes_variant);
    BSL_IdValPair_Init(&obj->opt_scope_flags);
    BSL_IdValPair_Init(&obj->opt_test_key_id);
    BSL_IdValPair_Init(&obj->opt_use_key_wrap);
}

void BCBTestContext_Deinit(BCBTestContext *obj)
{
    BSL_IdValPair_Deinit(&obj->opt_aes_variant);
    BSL_IdValPair_Deinit(&obj->opt_scope_flags);
    BSL_IdValPair_Deinit(&obj->opt_test_key_id);
    BSL_IdValPair_Deinit(&obj->opt_use_key_wrap);

    BSL_SecOper_Deinit(&obj->sec_oper);
}

void BSL_TestUtils_InitBIB_AppendixA1(BIBTestContext *context, BSL_SecRole_e role, const char *key_id)
{
    BSL_IdValPair_SetTextstr(&context->opt_test_key, BSLX_BIB_OPT_KEY_ID, key_id);
    BSL_IdValPair_SetInt64(&context->opt_scope_flags, BSLX_BIB_OPT_SCOPE, 0);
    BSL_IdValPair_SetInt64(&context->opt_sha_variant, BSLX_BIB_OPT_SHA_VARIANT, RFC9173_BIB_SHA_HMAC512);
    BSL_IdValPair_SetInt64(&context->opt_use_key_wrap, BSLX_BIB_OPT_USE_KEY_WRAP, 0);

    BSL_SecOper_Populate(&context->sec_oper, RFC9173_CONTEXTID_BIB_HMAC_SHA2, 1, 2, BSL_SECBLOCKTYPE_BIB, role,
                         BSL_POLICYACTION_DROP_BLOCK);

    BSL_SecOper_AppendOption(&context->sec_oper, &context->opt_sha_variant);
    BSL_SecOper_AppendOption(&context->sec_oper, &context->opt_scope_flags);
    BSL_SecOper_AppendOption(&context->sec_oper, &context->opt_test_key);
    BSL_SecOper_AppendOption(&context->sec_oper, &context->opt_use_key_wrap);
}

void BSL_TestUtils_InitBCB_Appendix2(BCBTestContext *context, BSL_SecRole_e role)
{
    BSL_IdValPair_SetInt64(&context->opt_scope_flags, BSLX_BCB_OPT_SCOPE, 0);
    BSL_IdValPair_SetTextstr(&context->opt_test_key_id, BSLX_BCB_OPT_KEY_ID, RFC9173_EXAMPLE_A2_KEY);
    BSL_IdValPair_SetInt64(&context->opt_aes_variant, BSLX_BCB_OPT_AES_VARIANT, RFC9173_BCB_AES_VARIANT_A128GCM);
    BSL_IdValPair_SetInt64(&context->opt_use_key_wrap, BSLX_BCB_OPT_USE_KEY_WRAP, 1);

    BSL_SecOper_Populate(&context->sec_oper, RFC9173_CONTEXTID_BCB_AES_GCM, 1, 2, BSL_SECBLOCKTYPE_BCB, role,
                         BSL_POLICYACTION_NOTHING);

    BSL_SecOper_AppendOption(&context->sec_oper, &context->opt_aes_variant);
    BSL_SecOper_AppendOption(&context->sec_oper, &context->opt_use_key_wrap);
    BSL_SecOper_AppendOption(&context->sec_oper, &context->opt_scope_flags);
    BSL_SecOper_AppendOption(&context->sec_oper, &context->opt_test_key_id);
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

RFC9173_A1_Params BSL_TestUtils_GetRFC9173_A1Params(const char *key_id)
{
    RFC9173_A1_Params params;
    BSL_IdValPair_Init(&params.sha_variant);
    BSL_IdValPair_SetInt64(&params.sha_variant, RFC9173_TestVectors_AppendixA1.bib_asb_sha_variant_key,
                           RFC9173_TestVectors_AppendixA1.bib_asb_sha_variant_value);
    BSL_IdValPair_Init(&params.scope_flags);
    BSL_IdValPair_SetInt64(&params.scope_flags, RFC9173_TestVectors_AppendixA1.bib_asb_scope_flags_key,
                           RFC9173_TestVectors_AppendixA1.bib_asb_scope_flags_value);
    BSL_IdValPair_Init(&params.test_key_id);
    BSL_IdValPair_SetTextstr(&params.test_key_id, BSLX_BIB_OPT_KEY_ID, key_id);
    BSL_IdValPair_Init(&params.use_key_wrap);
    BSL_IdValPair_SetInt64(&params.use_key_wrap, BSLX_BIB_OPT_USE_KEY_WRAP, 0);
    return params;
}

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
        static const uint8_t iv[] = { 0x54, 0x77, 0x65, 0x6c, 0x76, 0x65, 0x31, 0x32, 0x31, 0x32, 0x31, 0x32 };
        memcpy(buf, iv, 12);
    }
    else // A3 KEY
    {
        static const uint8_t rfc9173A3_key[] = { 0x71, 0x77, 0x65, 0x72, 0x74, 0x79, 0x75, 0x69,
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

    uint8_t rfc9173A1_key[]     = { 0x1a, 0x2b, 0x1a, 0x2b, 0x1a, 0x2b, 0x1a, 0x2b,
                                    0x1a, 0x2b, 0x1a, 0x2b, 0x1a, 0x2b, 0x1a, 0x2b };
    uint8_t rfc9173A2_key[]     = { 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68,
                                    0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70 };
    uint8_t rfc9173A3_key[]     = { 0x71, 0x77, 0x65, 0x72, 0x74, 0x79, 0x75, 0x69,
                                    0x6f, 0x70, 0x61, 0x73, 0x64, 0x66, 0x67, 0x68 };
    uint8_t rfc9173A4_BCB_key[] = { 0x71, 0x77, 0x65, 0x72, 0x74, 0x79, 0x75, 0x69, 0x6f, 0x70, 0x61,
                                    0x73, 0x64, 0x66, 0x67, 0x68, 0x71, 0x77, 0x65, 0x72, 0x74, 0x79,
                                    0x75, 0x69, 0x6f, 0x70, 0x61, 0x73, 0x64, 0x66, 0x67, 0x68 };
    assert(0 == BSL_Crypto_AddRegistryKeyName(RFC9173_EXAMPLE_A1_KEY, rfc9173A1_key, sizeof(rfc9173A1_key)));
    assert(0 == BSL_Crypto_AddRegistryKeyName(RFC9173_EXAMPLE_A2_KEY, rfc9173A2_key, sizeof(rfc9173A2_key)));
    assert(0 == BSL_Crypto_AddRegistryKeyName(RFC9173_EXAMPLE_A3_KEY, rfc9173A3_key, sizeof(rfc9173A3_key)));
    assert(0
           == BSL_Crypto_AddRegistryKeyName(RFC9173_EXAMPLE_A4_BCB_KEY, rfc9173A4_BCB_key, sizeof(rfc9173A4_BCB_key)));

    BSL_SecCtxDesc_t sec_desc;
    int              res;

    sec_desc.execute  = BSLX_BIB_Execute;
    sec_desc.validate = BSLX_BIB_Validate;
    res               = BSL_API_RegisterSecurityContext(bsl_lib, RFC9173_CONTEXTID_BIB_HMAC_SHA2, sec_desc);
    assert(0 == res);

    sec_desc.execute  = BSLX_BCB_Execute;
    sec_desc.validate = BSLX_BCB_Validate;
    res               = BSL_API_RegisterSecurityContext(bsl_lib, RFC9173_CONTEXTID_BCB_AES_GCM, sec_desc);
    assert(0 == res);
}
