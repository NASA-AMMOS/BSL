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
#ifndef _BSL_DEFAULTSCUTILS_H_
#define _BSL_DEFAULTSCUTILS_H_

#include <m-string.h>

#include <backend/PublicInterfaceImpl.h>
#include <backend/SecOperation.h>
#include <backend/SecParam.h>
#include <backend/SecResult.h>
#include <backend/SecurityActionSet.h>
#include <mock_bpa/ctr.h>

#include "TestUtils.h"

#ifdef __cplusplus
extern "C" {
#endif

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

typedef struct
{
    BSL_Data_t hmac;

    BSL_SecParam_t param_test_key;
    BSL_SecParam_t param_sha_variant;
    BSL_SecParam_t param_wrapped_key;
    BSL_SecParam_t use_key_wrap;
    BSL_SecParam_t param_scope_flags;

    BSL_SecParam_t param_wrapped_key_aes;

    BSL_SecOper_t sec_oper;
} BIBTestContext;

void BIBTestContext_Init(BIBTestContext *obj);
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
    BSL_SecParam_t use_key_wrap;
    BSL_SecParam_t param_key_enc_key;
    BSL_SecParam_t param_content_enc_key;

    BSL_SecOper_t sec_oper;
} BCBTestContext;

void BCBTestContext_Init(BCBTestContext *obj);
void BCBTestContext_Deinit(BCBTestContext *obj);

void BSL_TestUtils_InitBCB_Appendix2(BCBTestContext *context, BSL_SecRole_e role);

/// @brief Hard-coded single struct with fields populated from test vector in Appendix A1 for BIB.
extern const struct RFC9173_TestVectors_AppendixA1
{
    uint64_t bib_asb_sec_target;
    int64_t  bib_asb_context_id;
    uint64_t bib_asb_context_flags;
    uint64_t bib_asb_sha_variant_key;
    uint64_t bib_asb_sha_variant_value;
    uint64_t bib_asb_scope_flags_key;
    uint64_t bib_asb_scope_flags_value;

    const char *hex_bundle_original;
    const char *hex_bundle_bib;
    const char *hex_payload_block;
    const char *hex_primary_block;
    const char *hex_bib_block;
    const char *hex_bib_abs_sec_block;
    const char *hex_hmac;
} RFC9173_TestVectors_AppendixA1;

// static const struct RFC9173_TestVectors_AppendixA2
extern const struct RFC9173_TestVectorsA2
{
    uint64_t bcb_asb_sec_target;
    uint64_t bcb_asb_context;

    const char *hex_content_enc_key;
    const char *hex_key_enc_key;
    const char *hex_init_vector;
    const char *hex_bundle_original;
    const char *hex_bundle_bcb;
    const char *hex_auth_tag;
    const char *hex_ciphertext;
} RFC9173_TestVectors_AppendixA2;

// A4, but BCB only targets payload, not BIB
extern const struct RFC9173_TestVectors_A4_Modified
{
    const char *hex_bundle_original;
    const char *hex_bundle_final;

} RFC9173_TestVectors_AppendixA4;

typedef struct
{
    BSL_SecParam_t sha_variant;
    BSL_SecParam_t scope_flags;
    BSL_SecParam_t test_key_id;
    BSL_SecParam_t use_key_wrap;
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
    int64_t        context_id;
    uint64_t       context_flags;
    uint64_t       scope_flag;
} RFC9173_AppendixA2_BCB;

RFC9173_A1_Params BSL_TestUtils_GetRFC9173_A2Params(const char *key_id);

BSL_SecurityActionSet_t   *BSL_TestUtils_InitMallocBIBActionSet(BIBTestContext *bib_context);
BSL_SecurityResponseSet_t *BSL_TestUtils_MallocEmptyPolicyResponse(void);

void BSL_TestUtils_SetupDefaultSecurityContext(BSL_LibCtx_t *bsl_lib);

int rfc9173_byte_gen_fn_a1(unsigned char *buf, int len);
int rfc9173_byte_gen_fn_a2_kek(unsigned char *buf, int len);
int rfc9173_byte_gen_fn_a2_cek(unsigned char *buf, int len);
int rfc9173_byte_gen_fn_a4(unsigned char *buf, int len);

#ifdef __cplusplus
} // extern "C"
#endif

#endif // _BSL_DEFAULTSCUTILS_H_
