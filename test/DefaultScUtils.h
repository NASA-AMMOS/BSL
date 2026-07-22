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

#include "TestUtils.h"

#include <bsl/crypto/CryptoInterface.h>
#include <bsl/dynamic/PublicInterfaceImpl.h>
#include <bsl/dynamic/SecOperation.h>
#include <bsl/dynamic/SecurityActionSet.h>
#include <bsl/dynamic/Variant.h>
#include <bsl/sample_pp/SamplePolicyProvider.h>
#include <bsl/mock_bpa/ctr.h>

#include <m-string.h>

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

/// Test helper function
static inline int BSL_Crypto_AddRegistryKeyName(const char *name, const uint8_t *ptr, size_t len)
{
    BSL_Crypto_KeyHandle_t keyhandle;
    BSL_Crypto_LoadKey(ptr, len, &keyhandle);
    BSL_Data_t key_id = BSL_DATA_INIT_VIEW_CSTR(name);
    int        res    = BSL_Crypto_AddRegistryKey(&key_id, keyhandle);
    BSL_Crypto_ReleaseKeyHandle(keyhandle);
    return res;
}

/// Test helper function
static inline int BSL_Crypto_GetRegistryKeyName(const char *name, BSL_Crypto_KeyHandle_t *handle)
{
    BSL_Data_t key_id = BSL_DATA_INIT_VIEW_CSTR(name);
    return BSL_Crypto_GetRegistryKey(&key_id, handle);
}

/// Test helper function
static inline int BSL_Crypto_RemoveRegistryKeyName(const char *name)
{
    BSL_Data_t key_id = BSL_DATA_INIT_VIEW_CSTR(name);
    return BSL_Crypto_RemoveRegistryKey(&key_id);
}

/// @brief Sample policy provider ID
#define BSL_SAMPLE_PP_ID   1
#define BSL_SAMPLE_PP_ID_2 2

typedef struct
{
    //    BSL_Data_t hmac;

    BSL_SecOper_t sec_oper;
} BIBTestContext;

void BIBTestContext_Init(BIBTestContext *obj);
void BIBTestContext_Deinit(BIBTestContext *obj);

void BSL_TestUtils_InitBIB_AppendixA1(BIBTestContext *context, BSL_SecRole_e role, const char *key_id);

typedef struct
{
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

void BSL_TestUtils_GetRFC9173_A1Params(BSLP_PolicyRule_t *rule, const char *key_id);

void BSL_TestUtils_GetRFC9173_A2Params(BSLP_PolicyRule_t *rule, const char *key_id);

BSL_SecurityActionSet_t *BSL_TestUtils_InitMallocBIBActionSet(BIBTestContext *bib_context);

void BSL_TestUtils_SetupDefaultSecurityContext(BSL_LibCtx_t *bsl_lib);

int rfc9173_byte_gen_fn_a1(unsigned char *buf, int len);
int rfc9173_byte_gen_fn_a2_kek(unsigned char *buf, int len);
int rfc9173_byte_gen_fn_a2_cek(unsigned char *buf, int len);
int rfc9173_byte_gen_fn_a4(unsigned char *buf, int len);

#ifdef __cplusplus
} // extern "C"
#endif

#endif // _BSL_DEFAULTSCUTILS_H_
