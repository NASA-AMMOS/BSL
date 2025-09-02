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
#ifndef _BSL_TEST_UTILS_H_
#define _BSL_TEST_UTILS_H_

#include <m-string.h>

#include <backend/PublicInterfaceImpl.h>
#include <backend/SecOperation.h>
#include <backend/SecParam.h>
#include <backend/SecResult.h>
#include <backend/SecurityActionSet.h>
#include <mock_bpa/ctr.h>

#ifdef __cplusplus
extern "C" {
#endif

#define TEST_CASE(...)
#define TEST_RANGE(...)
#define TEST_MATRIX(...)

/// @brief Key ID for the Appendix A1 key in OpenSSL
#define RFC9173_EXAMPLE_A1_KEY "9100"

/// @brief Key ID for the Appendix A2 key in OpenSSL
#define RFC9173_EXAMPLE_A2_KEY "9102"

/// @brief Key ID for the Appendix A3 key in OpenSSL
#define RFC9173_EXAMPLE_A3_KEY "9103"

/// @brief Key ID for the Appendix A4 key in OpenSSL
#define RFC9173_EXAMPLE_A4_BCB_KEY "9104"

/// @brief Sample policy provider ID
#define BSL_SAMPLE_PP_ID   1
#define BSL_SAMPLE_PP_ID_2 2

#define quick_data_t(field, tgt) \
    field.len = sizeof(tgt);     \
    field.ptr = ((uint8_t *)tgt)

static const uint8_t ApxA1_BIBBlock[] = {
    0x85, 0x0b, 0x02, 0x00, 0x00, 0x58, 0x56, 0x81, 0x01, 0x01, 0x01, 0x82, 0x02, 0x82, 0x02, 0x01, 0x82, 0x82, 0x01,
    0x07, 0x82, 0x03, 0x00, 0x81, 0x81, 0x82, 0x01, 0x58, 0x40, 0x3b, 0xdc, 0x69, 0xb3, 0xa3, 0x4a, 0x2b, 0x5d, 0x3a,
    0x85, 0x54, 0x36, 0x8b, 0xd1, 0xe8, 0x08, 0xf6, 0x06, 0x21, 0x9d, 0x2a, 0x10, 0xa8, 0x46, 0xea, 0xe3, 0x88, 0x6a,
    0xe4, 0xec, 0xc8, 0x3c, 0x4e, 0xe5, 0x50, 0xfd, 0xfb, 0x1c, 0xc6, 0x36, 0xb9, 0x04, 0xe2, 0xf1, 0xa7, 0x3e, 0x30,
    0x3d, 0xcd, 0x4b, 0x6c, 0xce, 0xce, 0x00, 0x3e, 0x95, 0xe8, 0x16, 0x4d, 0xcc, 0x89, 0xa1, 0x56, 0xe1
};
static const uint8_t ApxA1_AbsSecBlock[] = {
    0x81, 0x01, 0x01, 0x01, 0x82, 0x02, 0x82, 0x02, 0x01, 0x82, 0x82, 0x01, 0x07, 0x82, 0x03, 0x00, 0x81, 0x81,
    0x82, 0x01, 0x58, 0x40, 0x3b, 0xdc, 0x69, 0xb3, 0xa3, 0x4a, 0x2b, 0x5d, 0x3a, 0x85, 0x54, 0x36, 0x8b, 0xd1,
    0xe8, 0x08, 0xf6, 0x06, 0x21, 0x9d, 0x2a, 0x10, 0xa8, 0x46, 0xea, 0xe3, 0x88, 0x6a, 0xe4, 0xec, 0xc8, 0x3c,
    0x4e, 0xe5, 0x50, 0xfd, 0xfb, 0x1c, 0xc6, 0x36, 0xb9, 0x04, 0xe2, 0xf1, 0xa7, 0x3e, 0x30, 0x3d, 0xcd, 0x4b,
    0x6c, 0xce, 0xce, 0x00, 0x3e, 0x95, 0xe8, 0x16, 0x4d, 0xcc, 0x89, 0xa1, 0x56, 0xe1
};
static const uint8_t ApxA1_IPPT[] = { 0x00, 0x58, 0x23, 0x52, 0x65, 0x61, 0x64, 0x79, 0x20, 0x74, 0x6f, 0x20, 0x67,
                                      0x65, 0x6e, 0x65, 0x72, 0x61, 0x74, 0x65, 0x20, 0x61, 0x20, 0x33, 0x32, 0x2d,
                                      0x62, 0x79, 0x74, 0x65, 0x20, 0x70, 0x61, 0x79, 0x6c, 0x6f, 0x61, 0x64 };
static const uint8_t ApxA1_HMAC[] = { 0x3b, 0xdc, 0x69, 0xb3, 0xa3, 0x4a, 0x2b, 0x5d, 0x3a, 0x85, 0x54, 0x36, 0x8b,
                                      0xd1, 0xe8, 0x08, 0xf6, 0x06, 0x21, 0x9d, 0x2a, 0x10, 0xa8, 0x46, 0xea, 0xe3,
                                      0x88, 0x6a, 0xe4, 0xec, 0xc8, 0x3c, 0x4e, 0xe5, 0x50, 0xfd, 0xfb, 0x1c, 0xc6,
                                      0x36, 0xb9, 0x04, 0xe2, 0xf1, 0xa7, 0x3e, 0x30, 0x3d, 0xcd, 0x4b, 0x6c, 0xce,
                                      0xce, 0x00, 0x3e, 0x95, 0xe8, 0x16, 0x4d, 0xcc, 0x89, 0xa1, 0x56, 0xe1 };
static const uint8_t ApxA1_Key[]  = { 0x1a, 0x2b, 0x1a, 0x2b, 0x1a, 0x2b, 0x1a, 0x2b,
                                      0x1a, 0x2b, 0x1a, 0x2b, 0x1a, 0x2b, 0x1a, 0x2b };

typedef struct
{
    BSL_Data_t ippt;
    BSL_Data_t hmac;

    BSL_SecParam_t param_test_key;
    BSL_SecParam_t param_sha_variant;
    BSL_SecParam_t param_hmac;
    BSL_SecParam_t param_wrapped_key;
    BSL_SecParam_t use_key_wrap;
    BSL_SecParam_t param_scope_flags;

    BSL_SecParam_t param_wrapped_key_aes;

    BSL_SecOper_t sec_oper;
} BIBTestContext;

void BIBTestContext_Deinit(BIBTestContext *obj);

void BSL_TestUtils_InitBIB_AppendixA1(BIBTestContext *context, BSL_SecRole_e role, const char *key_id);

static const uint8_t ApxA2_InitVec[]       = { 0x54, 0x77, 0x65, 0x6c, 0x76, 0x65, 0x31, 0x32, 0x31, 0x32, 0x31, 0x32 };
static const uint8_t ApxA2_AuthTag[]       = { 0xef, 0xa4, 0xb5, 0xac, 0x01, 0x08, 0xe3, 0x81,
                                               0x6c, 0x56, 0x06, 0x47, 0x98, 0x01, 0xbc, 0x04 };
static const uint8_t ApxA2_KeyEncKey[]     = { 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68,
                                               0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70 };
static const uint8_t ApxA2_ContentEncKey[] = { 0x71, 0x77, 0x65, 0x72, 0x74, 0x79, 0x75, 0x69,
                                               0x6f, 0x70, 0x61, 0x73, 0x64, 0x66, 0x67, 0x68 };
static const uint8_t ApxA2_Ciphertext[]    = { 0x3a, 0x09, 0xc1, 0xe6, 0x3f, 0xe2, 0x3a, 0x7f, 0x66, 0xa5, 0x9c, 0x73,
                                               0x03, 0x83, 0x72, 0x41, 0xe0, 0x70, 0xb0, 0x26, 0x19, 0xfc, 0x59, 0xc5,
                                               0x21, 0x4a, 0x22, 0xf0, 0x8c, 0xd7, 0x07, 0x95, 0xe7, 0x3e, 0x9a };
static const uint8_t ApxA2_WrappedKey[]    = { 0x69, 0xc4, 0x11, 0x27, 0x6f, 0xec, 0xdd, 0xc4, 0x78, 0x0d, 0xf4, 0x2c,
                                               0x8a, 0x2a, 0xf8, 0x92, 0x96, 0xfa, 0xbf, 0x34, 0xd7, 0xfa, 0xe7, 0x00 };
static const uint8_t ApxA2_PayloadData[]   = { 0x52, 0x65, 0x61, 0x64, 0x79, 0x20, 0x74, 0x6f, 0x20, 0x67, 0x65, 0x6e,
                                               0x65, 0x72, 0x61, 0x74, 0x65, 0x20, 0x61, 0x20, 0x33, 0x32, 0x2d, 0x62,
                                               0x79, 0x74, 0x65, 0x20, 0x70, 0x61, 0x79, 0x6c, 0x6f, 0x61, 0x64 };

typedef struct
{
    BSL_Data_t init_vector;
    BSL_Data_t auth_tag;
    BSL_Data_t wrapped_key;
    BSL_Data_t key_enc_key;
    BSL_Data_t content_enc_key;

    BSL_SecParam_t param_aes_variant;
    BSL_SecParam_t param_scope_flags;
    BSL_SecParam_t param_test_key_id;
    BSL_SecParam_t param_init_vec;
    BSL_SecParam_t param_auth_tag;
    BSL_SecParam_t param_wrapped_key;
    BSL_SecParam_t use_wrap_key;
    BSL_SecParam_t param_key_enc_key;
    BSL_SecParam_t param_content_enc_key;

    BSL_SecOper_t sec_oper;
} BCBTestContext;

void BSL_TestUtils_InitBCB_Appendix2(BCBTestContext *context, BSL_SecRole_e role);

/// @brief Hard-coded single struct with fields populated from test vector in Appendix A1 for BIB.
static const struct RFC9173_TestVectors_AppendixA1
{
    uint64_t prim_bp_version;
    uint64_t prim_flags;
    uint64_t prim_crc_type;
    uint64_t prim_seq_number;
    uint64_t prim_lifetime;
    uint64_t payload_type_code;
    uint64_t payload_block_num;
    uint64_t payload_flags;
    uint16_t payload_crc_type;

    uint64_t bib_asb_sec_target;
    int64_t bib_asb_context_id;
    uint64_t bib_asb_context_flags;
    uint64_t bib_asb_sha_variant_key;
    uint64_t bib_asb_sha_variant_value;
    uint64_t bib_asb_scope_flags_key;
    uint64_t bib_asb_scope_flags_value;

    const char *cbor_bundle_original;
    const char *cbor_bundle_bib;
    const char *cbor_payload_block;
    const char *cbor_primary_block;
    const char *cbor_bib_block;
    const char *cbor_bib_abs_sec_block;
    const char *cbor_hmac;
} RFC9173_TestVectors_AppendixA1 = {
    // Bundle primary and payload block fields.
    // Source: https://www.rfc-editor.org/rfc/rfc9173.html#appendix-A.1.1.1
    7,       // prim_bp_version
    0,       // prim_flags
    0,       // prim_crc_type
    40,      // prim_seq_num
    1000000, // prim_lifetime
    1,       // payload_type_code
    1,       // payload_block_num
    0,       // payload_flags
    0,       // payload_crc_type

    // BIB Abstract Security block fields
    // Source: https://www.rfc-editor.org/rfc/rfc9173.html#appendix-A.1.3.2
    1, // bib_asb_sec_target
    1, // bib_asb_context_id
    1, // bib_asb_context_flags
    1, // bib_asb_sha_variant_key
    7, // bib_asb_sha_variant_value (HMAC 512/512)
    3, // bib_asb_scope_flags_key
    0, // bib_asb_scope_flags_value (No additional scope)

    // TODO(bvb) - Encodings of endpoints.

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

// static const struct RFC9173_TestVectors_AppendixA2
typedef struct RFC9173_TestVectorsA2
{
    uint64_t bcb_asb_sec_target;
    uint64_t bcb_asb_context;

    const char *cbor_content_enc_key;
    const char *cbor_key_enc_key;
    const char *cbor_init_vector;
    const char *cbor_bundle_original;
    const char *cbor_bundle_bcb;
    const char *cbor_auth_tag;
    const char *cbor_ciphertext;
} RFC9173_TestVectorsA2;
static const RFC9173_TestVectorsA2 RFC9173_TestVectors_AppendixA2 = {
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

// A4, but BCB only targets payload, not BIB
static const struct RFC9173_TestVectors_A4_Modified
{
    const char *cbor_bundle_original;
    const char *cbor_bundle_final;

} RFC9173_TestVectors_AppendixA4 = {
    .cbor_bundle_original = ("9f88070000820282010282028202018202820201820018"
                             "281A000F424085010100005823526561647920746F2067"
                             "656E657261746520612033322D62797465207061796C6F"
                             "6164ff"),
    .cbor_bundle_final    = ("9f88070000820282010282028202018202820201820018"
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

typedef struct
{
    BSL_SecParam_t sha_variant;
    BSL_SecParam_t scope_flags;
    BSL_SecParam_t test_key_id;
    BSL_SecParam_t use_wrap_key;
} RFC9173_A1_Params;

RFC9173_A1_Params BSL_TestUtils_GetRFC9173_A1Params(const char *key_id);

typedef struct
{
    BSL_SecParam_t auth_code;
    BSL_SecParam_t content_enc_key;
    BSL_SecParam_t init_vector;
    BSL_SecParam_t key_enc_key;
    BSL_SecParam_t test_key_id;
    BSL_SecParam_t wrapped_key;
    int64_t       context_id;
    uint64_t       context_flags;
    uint64_t       scope_flag;
} RFC9173_AppendixA2_BCB;

RFC9173_A1_Params BSL_TestUtils_GetRFC9173_A2Params(const char *key_id);

typedef struct BSL_TestContext_s
{
    BSL_LibCtx_t   bsl;
    mock_bpa_ctr_t mock_bpa_ctr;
    uint64_t       key_id;
} BSL_TestContext_t;

BSL_SecurityActionSet_t   *BSL_TestUtils_InitMallocBIBActionSet(BIBTestContext *bib_context);
BSL_SecurityResponseSet_t *BSL_TestUtils_MallocEmptyPolicyResponse(void);

void BSL_TestUtils_SetupDefaultSecurityContext(BSL_LibCtx_t *bsl_lib);

int                  BSL_TestUtils_LoadBundleFromCBOR(BSL_TestContext_t *test_ctx, const char *cbor_seq);
BSL_HostEIDPattern_t BSL_TestUtils_GetEidPatternFromText(const char *text);

void BSL_TestUtils_PrintHexToBuffer(const char *message, uint8_t *buff, size_t bufflen);
bool BSL_TestUtils_IsB16StrEqualTo(const char *b16_string, BSL_Data_t encoded_val);

/** Encode to base16 text form.
 * This is defined in Section 8 of RFC 4648 @cite rfc4648.
 * @note This function uses heap allocation for its output.
 *
 * @param[out] output The output buffer, which will be appended to.
 * @param[in] input The input buffer to read.
 * @param uppercase True to use upper-case letters, false to use lower-case.
 * @return Zero upon success.
 */
int BSL_TestUtils_EncodeBase16(string_t output, const BSL_Data_t *input, bool uppercase);

/** Decode base16 text form.
 * This is defined in Section 8 of RFC 4648 @cite rfc4648.
 * @note This function uses heap allocation for its output.
 *
 * @param[out] output The output buffer, which will be sized to its data.
 * @param[in] input The input buffer to read, which must be null terminated.
 * Whitespace in the input must have already been removed with strip_space().
 * @return Zero upon success.
 */
int BSL_TestUtils_DecodeBase16(BSL_Data_t *output, const string_t input);

/**
 * Modify bundle's source eid, destination eid, and report-to eid
 * @param[in, out] input_bundle bundle to modify
 * @param[in] src_eid EID to set bundle source EID to. Set to NULL if bundle source EID should remain unchanged.
 * @param[in] dest_eid EID to set bundle destination EID to. Set to NULL if bundle destination EID should remain
 * unchanged.
 * @param[in] report_to_eid EID to set bundle report-to EID to. Set to NULL if bundle report-to EID should remain
 * unchanged.
 */
int BSL_TestUtils_ModifyEIDs(BSL_BundleRef_t *input_bundle, const char *src_eid, const char *dest_eid,
                             const char *report_to_eid);

int rfc9173_byte_gen_fn_a1(unsigned char *buf, int len);
int rfc9173_byte_gen_fn_a2_kek(unsigned char *buf, int len);
int rfc9173_byte_gen_fn_a2_cek(unsigned char *buf, int len);
int rfc9173_byte_gen_fn_a4(unsigned char *buf, int len);

/** Initialize a flat-buffer reader object.
 */
BSL_SeqReader_t *BSL_TestUtils_FlatReader(const void *buf, size_t bufsize);

/** Initialize a flat-buffer reader object.
 */
BSL_SeqWriter_t *BSL_TestUtils_FlatWriter(void **buf, size_t *bufsize);

#ifdef __cplusplus
} // extern "C"
#endif

#endif
