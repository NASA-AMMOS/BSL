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
 * @ingroup unit-tests
 *
 * @brief Specific low-level tests of the COSE Context
 *
 * Notes:
 *  - These tests use constructs defined in the BSL to exercise the context.
 *  - It uses test inputs and vectors from the COSE Context draft @cite draft-ietf-dtn-bpsec-cose.
 *  - It does NOT use any of the "Plumbing" inside the BSL.
 */
#include <stdlib.h>
#include <stdio.h>
#include <unity.h>

#include <bsl/BPSecLib_Private.h>
#include <bsl/mock_bpa/MockBPA.h>
#include <bsl/crypto/CryptoInterface.h>

#include <bsl/dynamic/PublicInterfaceImpl.h>
#include <bsl/cose_sc/CoseContext.h>
#include <bsl/cose_sc/CoseMsg.h>

#include "TestUtils.h"

static BSL_TestContext_t LocalTestCtx;

void suiteSetUp(void)
{
    TEST_ASSERT_EQUAL_INT(0, BSL_HostDescriptors_Set(MockBPA_Agent_Descriptors(NULL)));
    mock_bpa_LogOpen();
    mock_bpa_LogSetLeastSeverity(LOG_DEBUG); // FIXME
}

int suiteTearDown(int failures)
{
    mock_bpa_LogClose();
    BSL_HostDescriptors_Clear();
    return failures;
}

void setUp(void)
{
    BSL_CryptoInit();
    TEST_ASSERT_EQUAL(0, BSL_TestContext_Init(&LocalTestCtx));
}

void tearDown(void)
{
    BSL_CryptoDeinit();
    TEST_ASSERT_EQUAL(0, BSL_TestContext_Deinit(&LocalTestCtx));
}

/// valid starting point
static void set_CoseSc_InvalidOptions_Source_baseline(BSL_SecOper_t *sec_oper)
{
    {
        BSL_IdValPair_t option;
        BSL_IdValPair_Init(&option);
        {
            BSL_Data_t keyid = BSL_DATA_INIT_VIEW_CSTR("example");
            BSL_IdValPair_SetBytestr(&option, BSLX_COSESC_OPTION_KEY_ID, keyid);
        }
        BSL_SecOper_AppendOption(sec_oper, &option);
        BSL_IdValPair_Deinit(&option);
    }
    {
        BSL_IdValPair_t option;
        BSL_IdValPair_Init(&option);
        BSL_IdValPair_SetInt64(&option, BSLX_COSESC_OPTION_TGT_ALG, BSLX_COSEMSG_ALG_HMAC_SHA_384_384);
        BSL_SecOper_AppendOption(sec_oper, &option);
        BSL_IdValPair_Deinit(&option);
    }
}

/// Common input bundle from Appendix A
static const char *exA_nosec = "9f890700028201692f2f6473742f7376638201692f2f7372632f7376638201662f2f"
                               "7372632f821b000000bd51281400001a000f42404482a081c9860101000246656865"
                               "6c6c6f444ec359d2ff";

void test_CoseSc_InvalidOptions_Source(void)
{
    setenv("BSL_TEST_LOCAL_IPN_EID", "dtn://src/", 1);
    TEST_ASSERT_EQUAL(0, BSL_TestUtils_LoadBundleFromCBOR(&LocalTestCtx, exA_nosec));

    BSL_SecOper_t sec_oper;
    BSL_SecOper_Init(&sec_oper);
    BSL_SecOper_Populate(&sec_oper, BSLX_COSESC_CTX_ID, 1, 3, BSL_SECBLOCKTYPE_BIB, BSL_SECROLE_SOURCE,
                         BSL_POLICYACTION_DROP_BUNDLE);

    // valid starting point
    set_CoseSc_InvalidOptions_Source_baseline(&sec_oper);
    TEST_ASSERT_TRUE(BSLX_CoseSc_Validate(&LocalTestCtx.bsl, &LocalTestCtx.mock_bpa_ctr.bundle_ref, &sec_oper));

    set_CoseSc_InvalidOptions_Source_baseline(&sec_oper);
    BSLB_IdValPairPtrMap_erase(sec_oper._options, BSLX_COSESC_OPTION_KEY_ID);
    TEST_ASSERT_FALSE(BSLX_CoseSc_Validate(&LocalTestCtx.bsl, &LocalTestCtx.mock_bpa_ctr.bundle_ref, &sec_oper));

    set_CoseSc_InvalidOptions_Source_baseline(&sec_oper);
    BSLB_IdValPairPtrMap_erase(sec_oper._options, BSLX_COSESC_OPTION_TGT_ALG);
    TEST_ASSERT_FALSE(BSLX_CoseSc_Validate(&LocalTestCtx.bsl, &LocalTestCtx.mock_bpa_ctr.bundle_ref, &sec_oper));

    BSL_SecOper_Deinit(&sec_oper);
}

void test_CoseSc_InvalidOptions_Verifier(void)
{
    setenv("BSL_TEST_LOCAL_IPN_EID", "dtn://dst/", 1);
    TEST_ASSERT_EQUAL(0, BSL_TestUtils_LoadBundleFromCBOR(&LocalTestCtx, exA_nosec));

    BSL_SecOper_t sec_oper;
    BSL_SecOper_Init(&sec_oper);
    BSL_SecOper_Populate(&sec_oper, BSLX_COSESC_CTX_ID, 1, 3, BSL_SECBLOCKTYPE_BIB, BSL_SECROLE_VERIFIER,
                         BSL_POLICYACTION_DROP_BUNDLE);

    // no options is a valid start
    TEST_ASSERT_TRUE(BSLX_CoseSc_Validate(&LocalTestCtx.bsl, &LocalTestCtx.mock_bpa_ctr.bundle_ref, &sec_oper));

    // check different variety of bad values or combinations
    {
        BSL_IdValPair_t option;
        BSL_IdValPair_Init(&option);
        BSL_IdValPair_SetInt64(&option, BSLX_COSESC_OPTION_KEY_ID, 123);
        BSL_SecOper_AppendOption(&sec_oper, &option);
        BSL_IdValPair_Deinit(&option);
    }
    TEST_ASSERT_FALSE(BSLX_CoseSc_Validate(&LocalTestCtx.bsl, &LocalTestCtx.mock_bpa_ctr.bundle_ref, &sec_oper));
    BSLB_IdValPairPtrMap_reset(sec_oper._options);

    {
        BSL_IdValPair_t option;
        BSL_IdValPair_Init(&option);
        BSL_IdValPair_SetTextstr(&option, BSLX_COSESC_OPTION_TGT_ALG, "bad");
        BSL_SecOper_AppendOption(&sec_oper, &option);
        BSL_IdValPair_Deinit(&option);
    }
    TEST_ASSERT_FALSE(BSLX_CoseSc_Validate(&LocalTestCtx.bsl, &LocalTestCtx.mock_bpa_ctr.bundle_ref, &sec_oper));
    BSLB_IdValPairPtrMap_reset(sec_oper._options);

    {
        BSL_IdValPair_t option;
        BSL_IdValPair_Init(&option);
        // not valid alg for BIB
        BSL_IdValPair_SetInt64(&option, BSLX_COSESC_OPTION_TGT_ALG, BSLX_COSEMSG_ALG_AES_GCM_256);
        BSL_SecOper_AppendOption(&sec_oper, &option);
        BSL_IdValPair_Deinit(&option);
    }
    TEST_ASSERT_FALSE(BSLX_CoseSc_Validate(&LocalTestCtx.bsl, &LocalTestCtx.mock_bpa_ctr.bundle_ref, &sec_oper));
    BSLB_IdValPairPtrMap_reset(sec_oper._options);

    {
        BSL_IdValPair_t option;
        BSL_IdValPair_Init(&option);
        BSL_IdValPair_SetTextstr(&option, BSLX_COSESC_OPTION_KEY_ALG, "bad");
        BSL_SecOper_AppendOption(&sec_oper, &option);
        BSL_IdValPair_Deinit(&option);
    }
    TEST_ASSERT_FALSE(BSLX_CoseSc_Validate(&LocalTestCtx.bsl, &LocalTestCtx.mock_bpa_ctr.bundle_ref, &sec_oper));
    BSLB_IdValPairPtrMap_reset(sec_oper._options);

    {
        BSL_IdValPair_t option;
        BSL_IdValPair_Init(&option);
        BSL_IdValPair_SetInt64(&option, BSLX_COSESC_OPTION_AAD_SCOPE, 123);
        BSL_SecOper_AppendOption(&sec_oper, &option);
        BSL_IdValPair_Deinit(&option);
    }
    TEST_ASSERT_FALSE(BSLX_CoseSc_Validate(&LocalTestCtx.bsl, &LocalTestCtx.mock_bpa_ctr.bundle_ref, &sec_oper));
    BSLB_IdValPairPtrMap_reset(sec_oper._options);

    { // completely wrong type
        BSL_IdValPair_t option;
        BSL_IdValPair_Init(&option);
        {
            BSL_Data_t val;
            BSL_Data_Init(&val);
            TEST_ASSERT_EQUAL(0, BSL_TestUtils_DecodeBase16_cstr(&val, "626869"));
            BSL_IdValPair_SetRaw(&option, BSLX_COSESC_OPTION_AAD_SCOPE, val.ptr, val.len);
            BSL_Data_Deinit(&val);
        }
        BSL_SecOper_AppendOption(&sec_oper, &option);
        BSL_IdValPair_Deinit(&option);
    }
    TEST_ASSERT_FALSE(BSLX_CoseSc_Validate(&LocalTestCtx.bsl, &LocalTestCtx.mock_bpa_ctr.bundle_ref, &sec_oper));
    BSLB_IdValPairPtrMap_reset(sec_oper._options);

    { // bad key type
        BSL_IdValPair_t option;
        BSL_IdValPair_Init(&option);
        {
            BSL_Data_t val;
            BSL_Data_Init(&val);
            TEST_ASSERT_EQUAL(0, BSL_TestUtils_DecodeBase16_cstr(&val, "a14002"));
            BSL_IdValPair_SetRaw(&option, BSLX_COSESC_OPTION_AAD_SCOPE, val.ptr, val.len);
            BSL_Data_Deinit(&val);
        }
        BSL_SecOper_AppendOption(&sec_oper, &option);
        BSL_IdValPair_Deinit(&option);
    }
    TEST_ASSERT_FALSE(BSLX_CoseSc_Validate(&LocalTestCtx.bsl, &LocalTestCtx.mock_bpa_ctr.bundle_ref, &sec_oper));
    BSLB_IdValPairPtrMap_reset(sec_oper._options);

    { // bad value type
        BSL_IdValPair_t option;
        BSL_IdValPair_Init(&option);
        {
            BSL_Data_t val;
            BSL_Data_Init(&val);
            TEST_ASSERT_EQUAL(0, BSL_TestUtils_DecodeBase16_cstr(&val, "a10140"));
            BSL_IdValPair_SetRaw(&option, BSLX_COSESC_OPTION_AAD_SCOPE, val.ptr, val.len);
            BSL_Data_Deinit(&val);
        }
        BSL_SecOper_AppendOption(&sec_oper, &option);
        BSL_IdValPair_Deinit(&option);
    }
    TEST_ASSERT_FALSE(BSLX_CoseSc_Validate(&LocalTestCtx.bsl, &LocalTestCtx.mock_bpa_ctr.bundle_ref, &sec_oper));
    BSLB_IdValPairPtrMap_reset(sec_oper._options);

    {
        BSL_IdValPair_t option;
        BSL_IdValPair_Init(&option);
        BSL_IdValPair_SetTextstr(&option, BSLX_COSESC_OPTION_IV_COUNTER_OFFSET, "bad");
        BSL_SecOper_AppendOption(&sec_oper, &option);
        BSL_IdValPair_Deinit(&option);
    }
    TEST_ASSERT_FALSE(BSLX_CoseSc_Validate(&LocalTestCtx.bsl, &LocalTestCtx.mock_bpa_ctr.bundle_ref, &sec_oper));
    BSLB_IdValPairPtrMap_reset(sec_oper._options);

    BSL_SecOper_Deinit(&sec_oper);
}

/// Key ID for Example A.1
static const char *exA_1_kid = "ExampleA.1";
/// Symmetric key for Example A.1
static const char *exA_1_sk = "3a5c74e32ab4558a99581ec3a816576812aabe895db04494cda2"
                              "5b711d7b5ed4077466e677860648412f1bf8c91d0624";
/// Result bundle for Example A.1
static const char *exA_1_mac0 = "9f890700028201692f2f6473742f7376638201692f2f7372632f7376638201662f2f"
                                "7372632f821b000000bd51281400001a000f42404482a081c9850b03000058608101"
                                "03018201662f2f7372632f818205a2000120018181821158458443a10106a1044a45"
                                "78616d706c65412e31f65830ec8260a38a1a00fef2cd4aae063f50f01c5645e84c6c"
                                "4893ca895eed44ef60a5f50f9adf5cc5654499b881e5896378058601010002466568"
                                "656c6c6f444ec359d2ff";

/**
 * @brief Purpose: Exercise BIB applying security to a target payload block.
 *
 * Steps:
 *  - Get an unsecured bundle with a primary and payload block
 *  - Decode it into a BSL_BundleCtx struct
 *  - Create a BIB security operation with hard-coded options
 *  - Run ::BSLX_CoseSc_Validate function and confirm result is 0.
 *  - Run ::BSLX_CoseSc_Execute function and confirm result is 0.
 *  - Check the operation after the above function to confirm 1 result (a COSE_Mac0 message)
 *  - Capture the MAC tag and ensure it matches the value in the test vector.
 */
void test_AppendixA_Example1_BIB_Source(void)
{
    setenv("BSL_TEST_LOCAL_IPN_EID", "dtn://src/", 1);
    BSL_Crypto_KeyHandle_t keyhandle;
    {
        BSL_Data_t keymat;
        BSL_Data_Init(&keymat);
        TEST_ASSERT_EQUAL(0, BSL_TestUtils_DecodeBase16_cstr(&keymat, exA_1_sk));
        TEST_ASSERT_EQUAL_INT(0, BSL_Crypto_LoadKey(keymat.ptr, keymat.len, &keyhandle));
        BSL_Data_Deinit(&keymat);

        BSL_IdValPair_SetInt64(BSL_Crypto_SetKeyParameter(keyhandle, BSLX_COSEMSG_KEY_PARAM_ALG),
                               BSLX_COSEMSG_KEY_PARAM_ALG, BSLX_COSEMSG_ALG_HMAC_SHA_384_384);

        BSL_Data_t keyid = BSL_DATA_INIT_VIEW_CSTR(exA_1_kid);
        TEST_ASSERT_EQUAL_INT(0, BSL_Crypto_AddRegistryKey(&keyid, keyhandle));
    }

    TEST_ASSERT_EQUAL(0, BSL_TestUtils_LoadBundleFromCBOR(&LocalTestCtx, exA_nosec));

    BSL_SecOper_t sec_oper;
    BSL_SecOper_Init(&sec_oper);
    BSL_SecOper_Populate(&sec_oper, BSLX_COSESC_CTX_ID, 1, 3, BSL_SECBLOCKTYPE_BIB, BSL_SECROLE_SOURCE,
                         BSL_POLICYACTION_DROP_BUNDLE);

    {
        BSL_IdValPair_t option;
        BSL_IdValPair_Init(&option);
        {
            BSL_Data_t keyid = BSL_DATA_INIT_VIEW_CSTR(exA_1_kid);
            BSL_IdValPair_SetBytestr(&option, BSLX_COSESC_OPTION_KEY_ID, keyid);
        }
        BSL_SecOper_AppendOption(&sec_oper, &option);
        BSL_IdValPair_Deinit(&option);
    }
    {
        BSL_IdValPair_t option;
        BSL_IdValPair_Init(&option);
        BSL_IdValPair_SetInt64(&option, BSLX_COSESC_OPTION_TGT_ALG, BSLX_COSEMSG_ALG_HMAC_SHA_384_384);
        BSL_SecOper_AppendOption(&sec_oper, &option);
        BSL_IdValPair_Deinit(&option);
    }
    {
        BSL_IdValPair_t option;
        BSL_IdValPair_Init(&option);
        {
            BSLX_CoseSc_AadScope_t scope;
            BSLX_CoseSc_AadScope_init(scope);
            BSLX_CoseSc_AadScope_set_at(scope, 0, 0x1);
            BSLX_CoseSc_AadScope_set_at(scope, -1, 0x1);

            BSL_Data_t value;
            BSL_Data_Init(&value);
            int res = BSL_CBOR_Encode_Twopass(&value, (BSL_CBOR_Encode_f)&BSLX_CoseSc_AadScope_Encode, &scope);
            TEST_ASSERT_EQUAL_INT_MESSAGE(BSL_SUCCESS, res, "Failed BSL_CBOR_Encode_Twopass()");
            BSLX_CoseSc_AadScope_clear(scope);

            BSL_IdValPair_SetRaw(&option, BSLX_COSESC_OPTION_AAD_SCOPE, value.ptr, value.len);
            BSL_Data_Deinit(&value);
        }
        BSL_SecOper_AppendOption(&sec_oper, &option);
        BSL_IdValPair_Deinit(&option);
    }

    bool valid_status = BSLX_CoseSc_Validate(&LocalTestCtx.bsl, &LocalTestCtx.mock_bpa_ctr.bundle_ref, &sec_oper);
    TEST_ASSERT_TRUE(valid_status);

    // Confirm running operation as source executes without error
    int exec_status =
        BSL_ExecBIBSource(&BSLX_CoseSc_Execute, &LocalTestCtx.bsl, &LocalTestCtx.mock_bpa_ctr.bundle_ref, &sec_oper);
    TEST_ASSERT_EQUAL(BSL_SUCCESS, exec_status);

    // Confirm it produced only 1 result
    TEST_ASSERT_EQUAL(1, BSL_SecOper_CountResults(&sec_oper));
    const BSL_IdValPair_t *result = BSL_SecOper_FindResult(&sec_oper, BSLX_COSESC_RESULT_COSE_MAC0);
    TEST_ASSERT_NOT_NULL(result);
    TEST_ASSERT_EQUAL(BSLX_COSESC_RESULT_COSE_MAC0, BSL_IdValPair_GetId(result));
    TEST_ASSERT_TRUE(BSL_IdValPair_IsBytestr(result));

    // Inspect in the result
    BSLX_CoseMsg_Mac0_t msg;
    BSLX_CoseMsg_Mac0_Init(&msg);
    {
        BSL_Data_t in_buf;
        TEST_ASSERT_EQUAL(BSL_SUCCESS, BSL_IdValPair_GetAsBytestr(result, &in_buf));
        TEST_ASSERT_EQUAL(BSL_SUCCESS, BSL_CBOR_Decode(&in_buf, (BSL_CBOR_Decode_f)&BSLX_CoseMsg_Mac0_Decode, &msg));
        BSL_Data_Deinit(&in_buf);
    }
    BSLX_CoseMsg_Mac0_Deinit(&msg);

    // Full output content
    TEST_ASSERT_EQUAL(0, BSL_TestUtils_EncodeBundleToCBOR(&LocalTestCtx));
    TEST_ASSERT_TRUE(BSL_TestUtils_IsB16StrEqualTo(exA_1_mac0, LocalTestCtx.mock_bpa_ctr.encoded));

    {
        BSL_Crypto_KeyStats_t stats;
        BSL_Crypto_GetKeyStatistics(keyhandle, &stats);
        TEST_ASSERT_EQUAL_size_t(1, stats.stats[BSL_CRYPTO_KEYSTATS_TIMES_USED]);
        TEST_ASSERT_EQUAL_size_t(95, stats.stats[BSL_CRYPTO_KEYSTATS_BYTES_PROCESSED]);
    }

    BSL_SecOper_Deinit(&sec_oper);
    BSL_Crypto_ReleaseKeyHandle(keyhandle);
}

enum OptMismatch_e
{
    OPT_MISMATCH_NONE,
    OPT_MISMATCH_BAD_KEY_ID,
    OPT_MISMATCH_KEY_ALG,
    OPT_MISMATCH_TGT_ALG,
    OPT_MISMATCH_NO_AAD_SCOPE,
    OPT_MISMATCH_MODIFY_BLK_0,
    OPT_MISMATCH_MODIFY_BLK_1,
    OPT_MISMATCH_MODIFY_BLK_3,
};

TEST_MATRIX([ BSL_SECROLE_VERIFIER, BSL_SECROLE_ACCEPTOR ], [ 0, 1, 2, 3, 4, 5, 6, 7 ])
void test_AppendixA_Example1_BIB_VerifyAccept(BSL_SecRole_e role, int mismatch)
{
    setenv("BSL_TEST_LOCAL_IPN_EID", "dtn://dst/", 1);
    BSL_Crypto_KeyHandle_t keyhandle;
    {
        BSL_Data_t keymat;
        BSL_Data_Init(&keymat);
        TEST_ASSERT_EQUAL(0, BSL_TestUtils_DecodeBase16_cstr(&keymat, exA_1_sk));
        TEST_ASSERT_EQUAL_INT(0, BSL_Crypto_LoadKey(keymat.ptr, keymat.len, &keyhandle));
        BSL_Data_Deinit(&keymat);

        BSL_IdValPair_SetInt64(BSL_Crypto_SetKeyParameter(keyhandle, BSLX_COSEMSG_KEY_PARAM_ALG),
                               BSLX_COSEMSG_KEY_PARAM_ALG, BSLX_COSEMSG_ALG_HMAC_SHA_384_384);

        BSL_Data_t keyid = BSL_DATA_INIT_VIEW_CSTR(exA_1_kid);
        TEST_ASSERT_EQUAL_INT(0, BSL_Crypto_AddRegistryKey(&keyid, keyhandle));
    }

    TEST_ASSERT_EQUAL(0, BSL_TestUtils_LoadBundleFromCBOR(&LocalTestCtx, exA_1_mac0));

    MockBPA_CanonicalBlock_t *alter_blk = NULL;
    if (mismatch == OPT_MISMATCH_MODIFY_BLK_0)
    {
        // manipulate encoded form
        BSL_Data_t *blk_enc = &LocalTestCtx.mock_bpa_ctr.bundle->primary_block.encoded;
        ((uint8_t *)blk_enc->ptr)[0] += 1;
    }
    else if ((mismatch == OPT_MISMATCH_MODIFY_BLK_1) || (mismatch == OPT_MISMATCH_MODIFY_BLK_3))
    {
        MockBPA_CanonicalBlock_t **found =
            MockBPA_BlockByNum_get(LocalTestCtx.mock_bpa_ctr.bundle->blocks_num, OPT_MISMATCH_MODIFY_BLK_1 ? 1 : 3);
        TEST_ASSERT_NOT_NULL(found);
        alter_blk = *found;
        TEST_ASSERT_NOT_NULL(alter_blk);

        ((uint8_t *)alter_blk->btsd)[alter_blk->btsd_len - 1] += 1;
    }

    BSL_SecOper_t sec_oper;
    BSL_SecOper_Init(&sec_oper);
    BSL_SecOper_Populate(&sec_oper, BSLX_COSESC_CTX_ID, 1, 3, BSL_SECBLOCKTYPE_BIB, role, BSL_POLICYACTION_DROP_BUNDLE);

    const char *opt_key_id = (mismatch == OPT_MISMATCH_BAD_KEY_ID) ? "other" : exA_1_kid;
    {
        BSL_IdValPair_t option;
        BSL_IdValPair_Init(&option);
        {
            BSL_Data_t kid;
            BSL_Data_InitView(&kid, strlen(opt_key_id), (BSL_DataPtr_t)opt_key_id);
            BSL_IdValPair_SetBytestr(&option, BSLX_COSESC_OPTION_KEY_ID, kid);
        }
        BSL_SecOper_AppendOption(&sec_oper, &option);
        BSL_IdValPair_Deinit(&option);
    }
    {
        BSL_IdValPair_t option;
        BSL_IdValPair_Init(&option);
        BSL_IdValPair_SetInt64(&option, BSLX_COSESC_OPTION_KEY_ALG,
                               (mismatch == OPT_MISMATCH_KEY_ALG) ? BSLX_COSEMSG_ALG_HMAC_SHA_256_256
                                                                  : BSLX_COSEMSG_ALG_HMAC_SHA_384_384);
        BSL_SecOper_AppendOption(&sec_oper, &option);
        BSL_IdValPair_Deinit(&option);
    }
    {
        BSL_IdValPair_t option;
        BSL_IdValPair_Init(&option);
        BSL_IdValPair_SetInt64(&option, BSLX_COSESC_OPTION_TGT_ALG,
                               (mismatch == OPT_MISMATCH_TGT_ALG) ? BSLX_COSEMSG_ALG_HMAC_SHA_256_256
                                                                  : BSLX_COSEMSG_ALG_HMAC_SHA_384_384);
        BSL_SecOper_AppendOption(&sec_oper, &option);
        BSL_IdValPair_Deinit(&option);
    }
    if (mismatch != OPT_MISMATCH_NO_AAD_SCOPE)
    {
        BSLX_CoseSc_AadScope_t scope;
        BSLX_CoseSc_AadScope_init(scope);
        BSLX_CoseSc_AadScope_set_at(scope, 0, 0x1);
        BSLX_CoseSc_AadScope_set_at(scope, -1, 0x1);

        BSL_Data_t value;
        BSL_Data_Init(&value);
        int res = BSL_CBOR_Encode_Twopass(&value, (BSL_CBOR_Encode_f)&BSLX_CoseSc_AadScope_Encode, &scope);
        TEST_ASSERT_EQUAL_INT_MESSAGE(BSL_SUCCESS, res, "Failed BSL_CBOR_Encode_Twopass()");
        BSLX_CoseSc_AadScope_clear(scope);

        BSL_IdValPair_t option;
        BSL_IdValPair_Init(&option);
        BSL_IdValPair_SetRaw(&option, BSLX_COSESC_OPTION_AAD_SCOPE, value.ptr, value.len);
        BSL_SecOper_AppendOption(&sec_oper, &option);
        BSL_IdValPair_Deinit(&option);
        BSL_Data_Deinit(&value);
    }

    bool valid_status = BSLX_CoseSc_Validate(&LocalTestCtx.bsl, &LocalTestCtx.mock_bpa_ctr.bundle_ref, &sec_oper);
    TEST_ASSERT_EQUAL(true, valid_status);

    const int expect_status = ((mismatch == OPT_MISMATCH_NONE) || (mismatch == OPT_MISMATCH_NO_AAD_SCOPE))
                                  ? BSL_SUCCESS
                                  : BSL_ERR_SECURITY_OPERATION_FAILED;
    // Confirm running operation as source executes without error
    int exec_status = BSL_ExecBIBVerifierAcceptor(&BSLX_CoseSc_Execute, &LocalTestCtx.bsl,
                                                  &LocalTestCtx.mock_bpa_ctr.bundle_ref, &sec_oper);
    TEST_ASSERT_EQUAL_INT(expect_status, exec_status);

    if (alter_blk)
    {
        // put back for output comparison
        ((uint8_t *)alter_blk->btsd)[alter_blk->btsd_len - 1] -= 1;
    }

    TEST_ASSERT_EQUAL(0, BSL_TestUtils_EncodeBundleToCBOR(&LocalTestCtx));
    if ((role == BSL_SECROLE_VERIFIER) || (BSL_SUCCESS != exec_status))
    {
        // Full output content
        TEST_ASSERT_TRUE(BSL_TestUtils_IsB16StrEqualTo(exA_1_mac0, LocalTestCtx.mock_bpa_ctr.encoded));
    }
    else
    {
        TEST_ASSERT_TRUE(BSL_TestUtils_IsB16StrEqualTo(exA_nosec, LocalTestCtx.mock_bpa_ctr.encoded));

        {
            BSL_Crypto_KeyStats_t stats;
            BSL_Crypto_GetKeyStatistics(keyhandle, &stats);
            TEST_ASSERT_EQUAL_size_t(1, stats.stats[BSL_CRYPTO_KEYSTATS_TIMES_USED]);
            TEST_ASSERT_EQUAL_size_t(95, stats.stats[BSL_CRYPTO_KEYSTATS_BYTES_PROCESSED]);
        }
    }

    BSL_SecOper_Deinit(&sec_oper);
    BSL_Crypto_ReleaseKeyHandle(keyhandle);
}

/// Common input bundle for CCSDS/ESA
static const char *ccsds_mac_nosec = "9f89070001820282040982028201018202820101821b000000bec0f18301"
                                     "001b0000000202fbf00042179d8506040100458202820100850a03010043"
                                     "82030185070201004319f61885010100004568656c6c6fff";

static const char *ccsds_mac_kid = "ExampleA.5";
/// Symmetric key for test
static const char *ccsds_mac_sk = "0e8a982b921d1086241798032fedc1f883eab72e4e43bb2d11cfae38ad7a972e";
/// Result bundle for test
static const char *ccsds_mac_bib =
    "9F89070001820282040982028201018202820101821B000000BEC0F18301001B0000000202FBF00042179D850B050000589D81010301820282"
    "0100818205A200012001818182186158858543A10106A0F658309AC51C5D72F96E44099C521298691C087ECF7DA8EC99A9CFB8A6FCB5A44A4B"
    "054FF1669289F7EAF7719EBBF95FBABB3A818340A20124044A4578616D706C65412E355838442B1844E188743A7569623749A0FBE09C8540EE"
    "EC72EE419744EAA8E70B8FFAD13FDE7C1FADCB4EDC68A641A6191683C43D87990F5797758506040100458202820100850A0301004382030185"
    "070201004319F61885010100004568656C6C6FFF";

static int ccsds_mac_rng(unsigned char *buf, int len)
{
    if (len == 48) // CEK
    {
        BSL_Data_t data;
        BSL_Data_Init(&data);
        TEST_ASSERT_EQUAL(
            0, BSL_TestUtils_DecodeBase16_cstr(
                   &data,
                   "71776572747975696f7061736466676871776572747975696f7061736466676864456712646567f4646a3368106667bb"));
        memcpy(buf, data.ptr, data.len);
        BSL_Data_Deinit(&data);
        return 1;
    }
    return 0;
}

void test_CCSDS_Example_Mac_Source(void)
{
    setenv("BSL_TEST_LOCAL_IPN_EID", "ipn:1.0", 1);
    BSL_Crypto_SetRngGenerator(ccsds_mac_rng);
    BSL_Crypto_KeyHandle_t keyhandle;
    {
        BSL_Data_t keymat;
        BSL_Data_Init(&keymat);
        TEST_ASSERT_EQUAL(0, BSL_TestUtils_DecodeBase16_cstr(&keymat, ccsds_mac_sk));
        TEST_ASSERT_EQUAL_INT(0, BSL_Crypto_LoadKey(keymat.ptr, keymat.len, &keyhandle));
        BSL_Data_Deinit(&keymat);

        BSL_IdValPair_SetInt64(BSL_Crypto_SetKeyParameter(keyhandle, BSLX_COSEMSG_KEY_PARAM_ALG),
                               BSLX_COSEMSG_KEY_PARAM_ALG, BSLX_COSEMSG_ALG_AES_KW_256);

        BSL_Data_t keyid = BSL_DATA_INIT_VIEW_CSTR(ccsds_mac_kid);
        TEST_ASSERT_EQUAL_INT(0, BSL_Crypto_AddRegistryKey(&keyid, keyhandle));
    }

    TEST_ASSERT_EQUAL(0, BSL_TestUtils_LoadBundleFromCBOR(&LocalTestCtx, ccsds_mac_nosec));

    BSL_SecOper_t sec_oper;
    BSL_SecOper_Init(&sec_oper);
    BSL_SecOper_Populate(&sec_oper, BSLX_COSESC_CTX_ID, 1, 5, BSL_SECBLOCKTYPE_BIB, BSL_SECROLE_SOURCE,
                         BSL_POLICYACTION_DROP_BUNDLE);

    {
        BSL_IdValPair_t option;
        BSL_IdValPair_Init(&option);
        {
            BSL_Data_t keyid = BSL_DATA_INIT_VIEW_CSTR(ccsds_mac_kid);
            BSL_IdValPair_SetBytestr(&option, BSLX_COSESC_OPTION_KEY_ID, keyid);
        }
        BSL_SecOper_AppendOption(&sec_oper, &option);
        BSL_IdValPair_Deinit(&option);
    }
    {
        BSL_IdValPair_t option;
        BSL_IdValPair_Init(&option);
        BSL_IdValPair_SetInt64(&option, BSLX_COSESC_OPTION_TGT_ALG, BSLX_COSEMSG_ALG_HMAC_SHA_384_384);
        BSL_SecOper_AppendOption(&sec_oper, &option);
        BSL_IdValPair_Deinit(&option);
    }
    {
        BSL_IdValPair_t option;
        BSL_IdValPair_Init(&option);
        {
            BSLX_CoseSc_AadScope_t scope;
            BSLX_CoseSc_AadScope_init(scope);
            BSLX_CoseSc_AadScope_set_at(scope, 0, 0x1);
            BSLX_CoseSc_AadScope_set_at(scope, -1, 0x1);

            BSL_Data_t value;
            BSL_Data_Init(&value);
            int res = BSL_CBOR_Encode_Twopass(&value, (BSL_CBOR_Encode_f)&BSLX_CoseSc_AadScope_Encode, &scope);
            TEST_ASSERT_EQUAL_INT_MESSAGE(BSL_SUCCESS, res, "Failed BSL_CBOR_Encode_Twopass()");
            BSLX_CoseSc_AadScope_clear(scope);

            BSL_IdValPair_SetRaw(&option, BSLX_COSESC_OPTION_AAD_SCOPE, value.ptr, value.len);
            BSL_Data_Deinit(&value);
        }
        BSL_SecOper_AppendOption(&sec_oper, &option);
        BSL_IdValPair_Deinit(&option);
    }

    bool valid_status = BSLX_CoseSc_Validate(&LocalTestCtx.bsl, &LocalTestCtx.mock_bpa_ctr.bundle_ref, &sec_oper);
    TEST_ASSERT_TRUE(valid_status);

    // Confirm running operation as source executes without error
    int exec_status =
        BSL_ExecBIBSource(&BSLX_CoseSc_Execute, &LocalTestCtx.bsl, &LocalTestCtx.mock_bpa_ctr.bundle_ref, &sec_oper);
    TEST_ASSERT_EQUAL(BSL_SUCCESS, exec_status);

    // Confirm it produced only 1 result
    TEST_ASSERT_EQUAL(1, BSL_SecOper_CountResults(&sec_oper));
    const BSL_IdValPair_t *result = BSL_SecOper_FindResult(&sec_oper, BSLX_COSESC_RESULT_COSE_MAC);
    TEST_ASSERT_NOT_NULL(result);
    TEST_ASSERT_EQUAL(BSLX_COSESC_RESULT_COSE_MAC, BSL_IdValPair_GetId(result));
    TEST_ASSERT_TRUE(BSL_IdValPair_IsBytestr(result));

    // Inspect in the result
    BSLX_CoseMsg_Mac_t msg;
    BSLX_CoseMsg_Mac_Init(&msg);
    {
        BSL_Data_t in_buf;
        TEST_ASSERT_EQUAL(BSL_SUCCESS, BSL_IdValPair_GetAsBytestr(result, &in_buf));
        TEST_ASSERT_EQUAL(BSL_SUCCESS, BSL_CBOR_Decode(&in_buf, (BSL_CBOR_Decode_f)&BSLX_CoseMsg_Mac_Decode, &msg));
        BSL_Data_Deinit(&in_buf);
    }
    BSLX_CoseMsg_Mac_Deinit(&msg);

    // Full output content
    TEST_ASSERT_EQUAL(0, BSL_TestUtils_EncodeBundleToCBOR(&LocalTestCtx));
    TEST_ASSERT_TRUE(BSL_TestUtils_IsB16StrEqualTo(ccsds_mac_bib, LocalTestCtx.mock_bpa_ctr.encoded));

    {
        BSL_Crypto_KeyStats_t stats;
        BSL_Crypto_GetKeyStatistics(keyhandle, &stats);
        TEST_ASSERT_EQUAL_size_t(1, stats.stats[BSL_CRYPTO_KEYSTATS_TIMES_USED]);
        TEST_ASSERT_EQUAL_size_t(48, stats.stats[BSL_CRYPTO_KEYSTATS_BYTES_PROCESSED]);
    }

    BSL_SecOper_Deinit(&sec_oper);
    BSL_Crypto_ReleaseKeyHandle(keyhandle);
}

// no use of OPT_MISMATCH_MODIFY_BLK_3 here (tag is in the ciphertext)
TEST_MATRIX([ BSL_SECROLE_VERIFIER, BSL_SECROLE_ACCEPTOR ], [ 0, 1, 2, 3, 4, 5 ])
void test_CCSDS_Example_Mac_VerifyAccept(BSL_SecRole_e role, int mismatch)
{
    setenv("BSL_TEST_LOCAL_IPN_EID", "dtn://dst/", 1);
    BSL_Crypto_KeyHandle_t keyhandle;
    {
        BSL_Data_t keymat;
        BSL_Data_Init(&keymat);
        TEST_ASSERT_EQUAL(0, BSL_TestUtils_DecodeBase16_cstr(&keymat, ccsds_mac_sk));
        TEST_ASSERT_EQUAL_INT(0, BSL_Crypto_LoadKey(keymat.ptr, keymat.len, &keyhandle));
        BSL_Data_Deinit(&keymat);

        BSL_IdValPair_SetInt64(BSL_Crypto_SetKeyParameter(keyhandle, BSLX_COSEMSG_KEY_PARAM_ALG),
                               BSLX_COSEMSG_KEY_PARAM_ALG, BSLX_COSEMSG_ALG_AES_KW_256);

        BSL_Data_t keyid = BSL_DATA_INIT_VIEW_CSTR(ccsds_mac_kid);
        TEST_ASSERT_EQUAL_INT(0, BSL_Crypto_AddRegistryKey(&keyid, keyhandle));
    }

    TEST_ASSERT_EQUAL(0, BSL_TestUtils_LoadBundleFromCBOR(&LocalTestCtx, ccsds_mac_bib));

    MockBPA_CanonicalBlock_t *alter_blk = NULL;
    if (mismatch == OPT_MISMATCH_MODIFY_BLK_0)
    {
        // manipulate encoded form
        BSL_Data_t *blk_enc = &LocalTestCtx.mock_bpa_ctr.bundle->primary_block.encoded;
        ((uint8_t *)blk_enc->ptr)[0] += 1;
    }
    else if ((mismatch == OPT_MISMATCH_MODIFY_BLK_1) || (mismatch == OPT_MISMATCH_MODIFY_BLK_3))
    {
        MockBPA_CanonicalBlock_t **found =
            MockBPA_BlockByNum_get(LocalTestCtx.mock_bpa_ctr.bundle->blocks_num, OPT_MISMATCH_MODIFY_BLK_1 ? 1 : 3);
        TEST_ASSERT_NOT_NULL(found);
        alter_blk = *found;
        TEST_ASSERT_NOT_NULL(alter_blk);

        ((uint8_t *)alter_blk->btsd)[alter_blk->btsd_len - 1] += 1;
    }

    BSL_SecOper_t sec_oper;
    BSL_SecOper_Init(&sec_oper);
    BSL_SecOper_Populate(&sec_oper, BSLX_COSESC_CTX_ID, 1, 5, BSL_SECBLOCKTYPE_BIB, role, BSL_POLICYACTION_DROP_BUNDLE);

    const char *opt_key_id = (mismatch == OPT_MISMATCH_BAD_KEY_ID) ? "other" : ccsds_mac_kid;
    {
        BSL_IdValPair_t option;
        BSL_IdValPair_Init(&option);
        {
            BSL_Data_t kid;
            BSL_Data_InitView(&kid, strlen(opt_key_id), (BSL_DataPtr_t)opt_key_id);
            BSL_IdValPair_SetBytestr(&option, BSLX_COSESC_OPTION_KEY_ID, kid);
        }
        BSL_SecOper_AppendOption(&sec_oper, &option);
        BSL_IdValPair_Deinit(&option);
    }
    {
        BSL_IdValPair_t option;
        BSL_IdValPair_Init(&option);
        BSL_IdValPair_SetInt64(&option, BSLX_COSESC_OPTION_KEY_ALG,
                               (mismatch == OPT_MISMATCH_KEY_ALG) ? BSLX_COSEMSG_ALG_AES_KW_128
                                                                  : BSLX_COSEMSG_ALG_AES_KW_256);
        BSL_SecOper_AppendOption(&sec_oper, &option);
        BSL_IdValPair_Deinit(&option);
    }
    {
        BSL_IdValPair_t option;
        BSL_IdValPair_Init(&option);
        BSL_IdValPair_SetInt64(&option, BSLX_COSESC_OPTION_TGT_ALG,
                               (mismatch == OPT_MISMATCH_TGT_ALG) ? BSLX_COSEMSG_ALG_HMAC_SHA_256_256
                                                                  : BSLX_COSEMSG_ALG_HMAC_SHA_384_384);
        BSL_SecOper_AppendOption(&sec_oper, &option);
        BSL_IdValPair_Deinit(&option);
    }
    if (mismatch != OPT_MISMATCH_NO_AAD_SCOPE)
    {
        BSLX_CoseSc_AadScope_t scope;
        BSLX_CoseSc_AadScope_init(scope);
        BSLX_CoseSc_AadScope_set_at(scope, 0, 0x1);
        BSLX_CoseSc_AadScope_set_at(scope, -1, 0x1);

        BSL_Data_t value;
        BSL_Data_Init(&value);
        int res = BSL_CBOR_Encode_Twopass(&value, (BSL_CBOR_Encode_f)&BSLX_CoseSc_AadScope_Encode, &scope);
        TEST_ASSERT_EQUAL_INT_MESSAGE(BSL_SUCCESS, res, "Failed BSL_CBOR_Encode_Twopass()");
        BSLX_CoseSc_AadScope_clear(scope);

        BSL_IdValPair_t option;
        BSL_IdValPair_Init(&option);
        BSL_IdValPair_SetRaw(&option, BSLX_COSESC_OPTION_AAD_SCOPE, value.ptr, value.len);
        BSL_SecOper_AppendOption(&sec_oper, &option);
        BSL_IdValPair_Deinit(&option);
        BSL_Data_Deinit(&value);
    }

    bool valid_status = BSLX_CoseSc_Validate(&LocalTestCtx.bsl, &LocalTestCtx.mock_bpa_ctr.bundle_ref, &sec_oper);
    TEST_ASSERT_EQUAL(true, valid_status);

    const int expect_status = ((mismatch == OPT_MISMATCH_NONE) || (mismatch == OPT_MISMATCH_NO_AAD_SCOPE))
                                  ? BSL_SUCCESS
                                  : BSL_ERR_SECURITY_OPERATION_FAILED;
    // Confirm running operation as source executes without error
    int exec_status = BSL_ExecBCBVerifierAcceptor(&BSLX_CoseSc_Execute, &LocalTestCtx.bsl,
                                                  &LocalTestCtx.mock_bpa_ctr.bundle_ref, &sec_oper);
    TEST_ASSERT_EQUAL_INT(expect_status, exec_status);

    if (alter_blk)
    {
        // put back for output comparison
        ((uint8_t *)alter_blk->btsd)[alter_blk->btsd_len - 1] -= 1;
    }

    TEST_ASSERT_EQUAL(0, BSL_TestUtils_EncodeBundleToCBOR(&LocalTestCtx));
    if ((role == BSL_SECROLE_VERIFIER) || (BSL_SUCCESS != exec_status))
    {
        // Full output content
        TEST_ASSERT_TRUE(BSL_TestUtils_IsB16StrEqualTo(ccsds_mac_bib, LocalTestCtx.mock_bpa_ctr.encoded));
    }
    else
    {
        // successful acceptance
        TEST_ASSERT_TRUE(BSL_TestUtils_IsB16StrEqualTo(ccsds_mac_nosec, LocalTestCtx.mock_bpa_ctr.encoded));

        {
            BSL_Crypto_KeyStats_t stats;
            BSL_Crypto_GetKeyStatistics(keyhandle, &stats);
            TEST_ASSERT_EQUAL_size_t(1, stats.stats[BSL_CRYPTO_KEYSTATS_TIMES_USED]);
            TEST_ASSERT_EQUAL_size_t(48, stats.stats[BSL_CRYPTO_KEYSTATS_BYTES_PROCESSED]);
        }
    }

    BSL_SecOper_Deinit(&sec_oper);
    BSL_Crypto_ReleaseKeyHandle(keyhandle);
}

static const char *exA_4_kid = "ExampleA.4";
/// Symmetric key for Example A.4
static const char *exA_4_sk = "13bf9cead057c0aca2c9e52471ca4b19ddfaf4c0784e3f3e8e39"
                              "99dbae4ce45c";
/// Base IV for Example A.4
static const char *exA_4_biv = "6f3093eba5d85143c3dc0000";
/// Result bundle for Example A.4 with different BCB block flags
static const char *exA_4_enc0 = "9f890700028201692f2f6473742f7376638201692f2f7372632f7376638201662f2f"
                                "7372632f821b000000bd51281400001a000f42404482a081c9850c03010058318101"
                                "03018201662f2f7372632f818205a20001200181818210578343a10103a2044a4578"
                                "616d706c65412e340642484af68601010002561fd25f64a2eee2ff1a1ab29812ba22"
                                "1874380974c13b442086c017ff";

void test_AppendixA_Example4_BCB_Source(void)
{
    setenv("BSL_TEST_LOCAL_IPN_EID", "dtn://src/", 1);
    BSL_Crypto_KeyHandle_t keyhandle;
    {
        {
            BSL_Data_t keymat;
            BSL_Data_Init(&keymat);
            TEST_ASSERT_EQUAL(0, BSL_TestUtils_DecodeBase16_cstr(&keymat, exA_4_sk));
            TEST_ASSERT_EQUAL_INT(0, BSL_Crypto_LoadKey(keymat.ptr, keymat.len, &keyhandle));
            BSL_Data_Deinit(&keymat);
        }
        BSL_IdValPair_SetInt64(BSL_Crypto_SetKeyParameter(keyhandle, BSLX_COSEMSG_KEY_PARAM_ALG),
                               BSLX_COSEMSG_KEY_PARAM_ALG, BSLX_COSEMSG_ALG_AES_GCM_256);
        {
            BSL_Data_t buf;
            BSL_Data_Init(&buf);
            TEST_ASSERT_EQUAL(0, BSL_TestUtils_DecodeBase16_cstr(&buf, exA_4_biv));
            BSL_IdValPair_SetBytestr(BSL_Crypto_SetKeyParameter(keyhandle, BSLX_COSEMSG_KEY_PARAM_BASEIV),
                                     BSLX_COSEMSG_KEY_PARAM_BASEIV, buf);
            BSL_Data_Deinit(&buf);
        }

        BSL_Data_t keyid = BSL_DATA_INIT_VIEW_CSTR(exA_4_kid);
        TEST_ASSERT_EQUAL_INT(0, BSL_Crypto_AddRegistryKey(&keyid, keyhandle));
    }

    TEST_ASSERT_EQUAL(0, BSL_TestUtils_LoadBundleFromCBOR(&LocalTestCtx, exA_nosec));

    BSL_SecOper_t sec_oper;
    BSL_SecOper_Init(&sec_oper);
    BSL_SecOper_Populate(&sec_oper, BSLX_COSESC_CTX_ID, 1, 3, BSL_SECBLOCKTYPE_BCB, BSL_SECROLE_SOURCE,
                         BSL_POLICYACTION_DROP_BUNDLE);

    {
        BSL_IdValPair_t option;
        BSL_IdValPair_Init(&option);
        {
            BSL_Data_t keyid = BSL_DATA_INIT_VIEW_CSTR(exA_4_kid);
            BSL_IdValPair_SetBytestr(&option, BSLX_COSESC_OPTION_KEY_ID, keyid);
        }
        BSL_SecOper_AppendOption(&sec_oper, &option);
        BSL_IdValPair_Deinit(&option);
    }
    {
        BSL_IdValPair_t option;
        BSL_IdValPair_Init(&option);
        // offset to match Partial IV of example A.4
        BSL_IdValPair_SetInt64(&option, BSLX_COSESC_OPTION_IV_COUNTER_OFFSET, 0x484a);
        BSL_SecOper_AppendOption(&sec_oper, &option);
        BSL_IdValPair_Deinit(&option);
    }
    {
        BSL_IdValPair_t option;
        BSL_IdValPair_Init(&option);
        BSL_IdValPair_SetInt64(&option, BSLX_COSESC_OPTION_TGT_ALG, BSLX_COSEMSG_ALG_AES_GCM_256);
        BSL_SecOper_AppendOption(&sec_oper, &option);
        BSL_IdValPair_Deinit(&option);
    }
    {
        BSL_IdValPair_t option;
        BSL_IdValPair_Init(&option);
        {
            BSLX_CoseSc_AadScope_t scope;
            BSLX_CoseSc_AadScope_init(scope);
            BSLX_CoseSc_AadScope_set_at(scope, 0, 0x1);
            BSLX_CoseSc_AadScope_set_at(scope, -1, 0x1);

            BSL_Data_t value;
            BSL_Data_Init(&value);
            int res = BSL_CBOR_Encode_Twopass(&value, (BSL_CBOR_Encode_f)&BSLX_CoseSc_AadScope_Encode, &scope);
            TEST_ASSERT_EQUAL_INT_MESSAGE(BSL_SUCCESS, res, "Failed BSL_CBOR_Encode_Twopass()");
            BSLX_CoseSc_AadScope_clear(scope);

            BSL_IdValPair_SetRaw(&option, BSLX_COSESC_OPTION_AAD_SCOPE, value.ptr, value.len);
            BSL_Data_Deinit(&value);
        }
        BSL_SecOper_AppendOption(&sec_oper, &option);
        BSL_IdValPair_Deinit(&option);
    }

    bool valid_status = BSLX_CoseSc_Validate(&LocalTestCtx.bsl, &LocalTestCtx.mock_bpa_ctr.bundle_ref, &sec_oper);
    TEST_ASSERT_TRUE(valid_status);

    // Confirm running operation as source executes without error
    int exec_status =
        BSL_ExecBCBSource(&BSLX_CoseSc_Execute, &LocalTestCtx.bsl, &LocalTestCtx.mock_bpa_ctr.bundle_ref, &sec_oper);
    TEST_ASSERT_EQUAL(BSL_SUCCESS, exec_status);

    // Confirm it produced only 1 result
    TEST_ASSERT_EQUAL(1, BSL_SecOper_CountResults(&sec_oper));
    const BSL_IdValPair_t *result = BSL_SecOper_FindResult(&sec_oper, BSLX_COSESC_RESULT_COSE_ENCRYPT0);
    TEST_ASSERT_NOT_NULL(result);
    TEST_ASSERT_EQUAL(BSLX_COSESC_RESULT_COSE_ENCRYPT0, BSL_IdValPair_GetId(result));
    TEST_ASSERT_TRUE(BSL_IdValPair_IsBytestr(result));

    // Inspect in the result
    BSLX_CoseMsg_Encrypt0_t msg;
    BSLX_CoseMsg_Encrypt0_Init(&msg);
    {
        BSL_Data_t in_buf;
        TEST_ASSERT_EQUAL(BSL_SUCCESS, BSL_IdValPair_GetAsBytestr(result, &in_buf));
        TEST_ASSERT_EQUAL(BSL_SUCCESS,
                          BSL_CBOR_Decode(&in_buf, (BSL_CBOR_Decode_f)&BSLX_CoseMsg_Encrypt0_Decode, &msg));
        BSL_Data_Deinit(&in_buf);
    }
    BSLX_CoseMsg_Encrypt0_Deinit(&msg);

    // Full output content
    TEST_ASSERT_EQUAL(0, BSL_TestUtils_EncodeBundleToCBOR(&LocalTestCtx));
    TEST_ASSERT_TRUE(BSL_TestUtils_IsB16StrEqualTo(exA_4_enc0, LocalTestCtx.mock_bpa_ctr.encoded));

    {
        BSL_Crypto_KeyStats_t stats;
        BSL_Crypto_GetKeyStatistics(keyhandle, &stats);
        TEST_ASSERT_EQUAL_size_t(1, stats.stats[BSL_CRYPTO_KEYSTATS_TIMES_USED]);
        TEST_ASSERT_EQUAL_size_t(98, stats.stats[BSL_CRYPTO_KEYSTATS_BYTES_PROCESSED]);
    }

    BSL_SecOper_Deinit(&sec_oper);
    BSL_Crypto_ReleaseKeyHandle(keyhandle);
}

// no use of OPT_MISMATCH_MODIFY_BLK_3 here (tag is in the ciphertext)
TEST_MATRIX([ BSL_SECROLE_VERIFIER, BSL_SECROLE_ACCEPTOR ], [ 0, 1, 2, 3, 4, 5 ])
void test_AppendixA_Example4_BCB_VerifyAccept(BSL_SecRole_e role, int mismatch)
{
    setenv("BSL_TEST_LOCAL_IPN_EID", "dtn://dst/", 1);
    BSL_Crypto_KeyHandle_t keyhandle;
    {
        BSL_Data_t keymat;
        BSL_Data_Init(&keymat);
        TEST_ASSERT_EQUAL(0, BSL_TestUtils_DecodeBase16_cstr(&keymat, exA_4_sk));
        TEST_ASSERT_EQUAL_INT(0, BSL_Crypto_LoadKey(keymat.ptr, keymat.len, &keyhandle));
        BSL_Data_Deinit(&keymat);

        BSL_IdValPair_SetInt64(BSL_Crypto_SetKeyParameter(keyhandle, BSLX_COSEMSG_KEY_PARAM_ALG),
                               BSLX_COSEMSG_KEY_PARAM_ALG, BSLX_COSEMSG_ALG_AES_GCM_256);
        {
            BSL_Data_t buf;
            BSL_Data_Init(&buf);
            TEST_ASSERT_EQUAL(0, BSL_TestUtils_DecodeBase16_cstr(&buf, exA_4_biv));
            BSL_IdValPair_SetBytestr(BSL_Crypto_SetKeyParameter(keyhandle, BSLX_COSEMSG_KEY_PARAM_BASEIV),
                                     BSLX_COSEMSG_KEY_PARAM_BASEIV, buf);
            BSL_Data_Deinit(&buf);
        }

        BSL_Data_t keyid = BSL_DATA_INIT_VIEW_CSTR(exA_4_kid);
        TEST_ASSERT_EQUAL_INT(0, BSL_Crypto_AddRegistryKey(&keyid, keyhandle));
    }

    TEST_ASSERT_EQUAL(0, BSL_TestUtils_LoadBundleFromCBOR(&LocalTestCtx, exA_4_enc0));

    MockBPA_CanonicalBlock_t *alter_blk = NULL;
    if (mismatch == OPT_MISMATCH_MODIFY_BLK_0)
    {
        // manipulate encoded form
        BSL_Data_t *blk_enc = &LocalTestCtx.mock_bpa_ctr.bundle->primary_block.encoded;
        ((uint8_t *)blk_enc->ptr)[0] += 1;
    }
    else if ((mismatch == OPT_MISMATCH_MODIFY_BLK_1) || (mismatch == OPT_MISMATCH_MODIFY_BLK_3))
    {
        MockBPA_CanonicalBlock_t **found =
            MockBPA_BlockByNum_get(LocalTestCtx.mock_bpa_ctr.bundle->blocks_num, OPT_MISMATCH_MODIFY_BLK_1 ? 1 : 3);
        TEST_ASSERT_NOT_NULL(found);
        alter_blk = *found;
        TEST_ASSERT_NOT_NULL(alter_blk);

        ((uint8_t *)alter_blk->btsd)[alter_blk->btsd_len - 1] += 1;
    }

    BSL_SecOper_t sec_oper;
    BSL_SecOper_Init(&sec_oper);
    BSL_SecOper_Populate(&sec_oper, BSLX_COSESC_CTX_ID, 1, 3, BSL_SECBLOCKTYPE_BCB, role, BSL_POLICYACTION_DROP_BUNDLE);

    const char *opt_key_id = (mismatch == OPT_MISMATCH_BAD_KEY_ID) ? "other" : exA_4_kid;
    {
        BSL_IdValPair_t option;
        BSL_IdValPair_Init(&option);
        {
            BSL_Data_t kid;
            BSL_Data_InitView(&kid, strlen(opt_key_id), (BSL_DataPtr_t)opt_key_id);
            BSL_IdValPair_SetBytestr(&option, BSLX_COSESC_OPTION_KEY_ID, kid);
        }
        BSL_SecOper_AppendOption(&sec_oper, &option);
        BSL_IdValPair_Deinit(&option);
    }
    {
        BSL_IdValPair_t option;
        BSL_IdValPair_Init(&option);
        BSL_IdValPair_SetInt64(&option, BSLX_COSESC_OPTION_KEY_ALG,
                               (mismatch == OPT_MISMATCH_KEY_ALG) ? BSLX_COSEMSG_ALG_AES_GCM_128
                                                                  : BSLX_COSEMSG_ALG_AES_GCM_256);
        BSL_SecOper_AppendOption(&sec_oper, &option);
        BSL_IdValPair_Deinit(&option);
    }
    {
        BSL_IdValPair_t option;
        BSL_IdValPair_Init(&option);
        BSL_IdValPair_SetInt64(&option, BSLX_COSESC_OPTION_TGT_ALG,
                               (mismatch == OPT_MISMATCH_TGT_ALG) ? BSLX_COSEMSG_ALG_AES_GCM_128
                                                                  : BSLX_COSEMSG_ALG_AES_GCM_256);
        BSL_SecOper_AppendOption(&sec_oper, &option);
        BSL_IdValPair_Deinit(&option);
    }
    if (mismatch != OPT_MISMATCH_NO_AAD_SCOPE)
    {
        BSLX_CoseSc_AadScope_t scope;
        BSLX_CoseSc_AadScope_init(scope);
        BSLX_CoseSc_AadScope_set_at(scope, 0, 0x1);
        BSLX_CoseSc_AadScope_set_at(scope, -1, 0x1);

        BSL_Data_t value;
        BSL_Data_Init(&value);
        int res = BSL_CBOR_Encode_Twopass(&value, (BSL_CBOR_Encode_f)&BSLX_CoseSc_AadScope_Encode, &scope);
        TEST_ASSERT_EQUAL_INT_MESSAGE(BSL_SUCCESS, res, "Failed BSL_CBOR_Encode_Twopass()");
        BSLX_CoseSc_AadScope_clear(scope);

        BSL_IdValPair_t option;
        BSL_IdValPair_Init(&option);
        BSL_IdValPair_SetRaw(&option, BSLX_COSESC_OPTION_AAD_SCOPE, value.ptr, value.len);
        BSL_SecOper_AppendOption(&sec_oper, &option);
        BSL_IdValPair_Deinit(&option);
        BSL_Data_Deinit(&value);
    }

    bool valid_status = BSLX_CoseSc_Validate(&LocalTestCtx.bsl, &LocalTestCtx.mock_bpa_ctr.bundle_ref, &sec_oper);
    TEST_ASSERT_EQUAL(true, valid_status);

    const int expect_status = ((mismatch == OPT_MISMATCH_NONE) || (mismatch == OPT_MISMATCH_NO_AAD_SCOPE))
                                  ? BSL_SUCCESS
                                  : BSL_ERR_SECURITY_OPERATION_FAILED;
    // Confirm running operation as source executes without error
    int exec_status = BSL_ExecBCBVerifierAcceptor(&BSLX_CoseSc_Execute, &LocalTestCtx.bsl,
                                                  &LocalTestCtx.mock_bpa_ctr.bundle_ref, &sec_oper);
    TEST_ASSERT_EQUAL_INT(expect_status, exec_status);

    if (alter_blk)
    {
        // put back for output comparison
        ((uint8_t *)alter_blk->btsd)[alter_blk->btsd_len - 1] -= 1;
    }

    TEST_ASSERT_EQUAL(0, BSL_TestUtils_EncodeBundleToCBOR(&LocalTestCtx));
    if ((role == BSL_SECROLE_VERIFIER) || (BSL_SUCCESS != exec_status))
    {
        // Full output content
        TEST_ASSERT_TRUE(BSL_TestUtils_IsB16StrEqualTo(exA_4_enc0, LocalTestCtx.mock_bpa_ctr.encoded));
    }
    else
    {
        // successful acceptance
        TEST_ASSERT_TRUE(BSL_TestUtils_IsB16StrEqualTo(exA_nosec, LocalTestCtx.mock_bpa_ctr.encoded));

        {
            BSL_Crypto_KeyStats_t stats;
            BSL_Crypto_GetKeyStatistics(keyhandle, &stats);
            TEST_ASSERT_EQUAL_size_t(1, stats.stats[BSL_CRYPTO_KEYSTATS_TIMES_USED]);
            TEST_ASSERT_EQUAL_size_t(98, stats.stats[BSL_CRYPTO_KEYSTATS_BYTES_PROCESSED]);
        }
    }

    BSL_SecOper_Deinit(&sec_oper);
    BSL_Crypto_ReleaseKeyHandle(keyhandle);
}

static const char *exA_5_kid = "ExampleA.5";
/// Symmetric key for Example A.5
static const char *exA_5_sk = "0e8a982b921d1086241798032fedc1f883eab72e4e43bb2d11cfae38ad7a972e";
/// Result bundle for Example A.5 with different BCB block flags
static const char *exA_5_enc = "9f890700028201692f2f6473742f7376638201692f2f7372632f7376638201662f2f"
                               "7372632f821b000000bd51281400001a000f42404482a081c9850c030100586d8101"
                               "03018201662f2f7372632f818205a200012001818182186058518443a10103a1054c"
                               "6f3093eba5d85143c3dc484af6818340a20124044a4578616d706c65412e35582891"
                               "7f2045e1169502756252bf119a94cdac6a9d8944245b5a9a26d403a6331159e3d691"
                               "a708e9984d8601010002561fd25f64a2ee33e774abe16700bcfd9cf12ea5f7d84144"
                               "47abdef0ff";

static int cose_exA_5_rng(unsigned char *buf, int len)
{
    if (len == 12) // IV
    {
        BSL_Data_t data;
        BSL_Data_Init(&data);
        TEST_ASSERT_EQUAL(0, BSL_TestUtils_DecodeBase16_cstr(&data, "6f3093eba5d85143c3dc484a"));
        memcpy(buf, data.ptr, data.len);
        BSL_Data_Deinit(&data);
        return 1;
    }
    else if (len == 32) // CEK
    {
        BSL_Data_t data;
        BSL_Data_Init(&data);
        TEST_ASSERT_EQUAL(0, BSL_TestUtils_DecodeBase16_cstr(
                                 &data, "13bf9cead057c0aca2c9e52471ca4b19ddfaf4c0784e3f3e8e3999dbae4ce45c"));
        memcpy(buf, data.ptr, data.len);
        BSL_Data_Deinit(&data);
        return 1;
    }
    return 0;
}

void test_AppendixA_Example5_BCB_Source(void)
{
    setenv("BSL_TEST_LOCAL_IPN_EID", "dtn://src/", 1);
    BSL_Crypto_SetRngGenerator(cose_exA_5_rng);
    BSL_Crypto_KeyHandle_t keyhandle;
    {
        {
            BSL_Data_t keymat;
            BSL_Data_Init(&keymat);
            TEST_ASSERT_EQUAL(0, BSL_TestUtils_DecodeBase16_cstr(&keymat, exA_5_sk));
            TEST_ASSERT_EQUAL_INT(0, BSL_Crypto_LoadKey(keymat.ptr, keymat.len, &keyhandle));
            BSL_Data_Deinit(&keymat);
        }
        BSL_IdValPair_SetInt64(BSL_Crypto_SetKeyParameter(keyhandle, BSLX_COSEMSG_KEY_PARAM_ALG),
                               BSLX_COSEMSG_KEY_PARAM_ALG, BSLX_COSEMSG_ALG_AES_KW_256);

        BSL_Data_t keyid = BSL_DATA_INIT_VIEW_CSTR(exA_5_kid);
        TEST_ASSERT_EQUAL_INT(0, BSL_Crypto_AddRegistryKey(&keyid, keyhandle));
    }

    TEST_ASSERT_EQUAL(0, BSL_TestUtils_LoadBundleFromCBOR(&LocalTestCtx, exA_nosec));

    BSL_SecOper_t sec_oper;
    BSL_SecOper_Init(&sec_oper);
    BSL_SecOper_Populate(&sec_oper, BSLX_COSESC_CTX_ID, 1, 3, BSL_SECBLOCKTYPE_BCB, BSL_SECROLE_SOURCE,
                         BSL_POLICYACTION_DROP_BUNDLE);

    {
        BSL_IdValPair_t option;
        BSL_IdValPair_Init(&option);
        {
            BSL_Data_t keyid = BSL_DATA_INIT_VIEW_CSTR(exA_5_kid);
            BSL_IdValPair_SetBytestr(&option, BSLX_COSESC_OPTION_KEY_ID, keyid);
        }
        BSL_SecOper_AppendOption(&sec_oper, &option);
        BSL_IdValPair_Deinit(&option);
    }
    {
        BSL_IdValPair_t option;
        BSL_IdValPair_Init(&option);
        BSL_IdValPair_SetInt64(&option, BSLX_COSESC_OPTION_TGT_ALG, BSLX_COSEMSG_ALG_AES_GCM_256);
        BSL_SecOper_AppendOption(&sec_oper, &option);
        BSL_IdValPair_Deinit(&option);
    }
    {
        BSL_IdValPair_t option;
        BSL_IdValPair_Init(&option);
        {
            BSLX_CoseSc_AadScope_t scope;
            BSLX_CoseSc_AadScope_init(scope);
            BSLX_CoseSc_AadScope_set_at(scope, 0, 0x1);
            BSLX_CoseSc_AadScope_set_at(scope, -1, 0x1);

            BSL_Data_t value;
            BSL_Data_Init(&value);
            int res = BSL_CBOR_Encode_Twopass(&value, (BSL_CBOR_Encode_f)&BSLX_CoseSc_AadScope_Encode, &scope);
            TEST_ASSERT_EQUAL_INT_MESSAGE(BSL_SUCCESS, res, "Failed BSL_CBOR_Encode_Twopass()");
            BSLX_CoseSc_AadScope_clear(scope);

            BSL_IdValPair_SetRaw(&option, BSLX_COSESC_OPTION_AAD_SCOPE, value.ptr, value.len);
            BSL_Data_Deinit(&value);
        }
        BSL_SecOper_AppendOption(&sec_oper, &option);
        BSL_IdValPair_Deinit(&option);
    }

    bool valid_status = BSLX_CoseSc_Validate(&LocalTestCtx.bsl, &LocalTestCtx.mock_bpa_ctr.bundle_ref, &sec_oper);
    TEST_ASSERT_TRUE(valid_status);

    // Confirm running operation as source executes without error
    int exec_status =
        BSL_ExecBCBSource(&BSLX_CoseSc_Execute, &LocalTestCtx.bsl, &LocalTestCtx.mock_bpa_ctr.bundle_ref, &sec_oper);
    TEST_ASSERT_EQUAL(BSL_SUCCESS, exec_status);

    // Confirm it produced only 1 result
    TEST_ASSERT_EQUAL(1, BSL_SecOper_CountResults(&sec_oper));
    const BSL_IdValPair_t *result = BSL_SecOper_FindResult(&sec_oper, BSLX_COSESC_RESULT_COSE_ENCRYPT);
    TEST_ASSERT_NOT_NULL(result);
    TEST_ASSERT_EQUAL(BSLX_COSESC_RESULT_COSE_ENCRYPT, BSL_IdValPair_GetId(result));
    TEST_ASSERT_TRUE(BSL_IdValPair_IsBytestr(result));

    // Inspect in the result
    BSLX_CoseMsg_Encrypt_t msg;
    BSLX_CoseMsg_Encrypt_Init(&msg);
    {
        BSL_Data_t in_buf;
        TEST_ASSERT_EQUAL(BSL_SUCCESS, BSL_IdValPair_GetAsBytestr(result, &in_buf));
        TEST_ASSERT_EQUAL(BSL_SUCCESS, BSL_CBOR_Decode(&in_buf, (BSL_CBOR_Decode_f)&BSLX_CoseMsg_Encrypt_Decode, &msg));
        BSL_Data_Deinit(&in_buf);
    }
    BSLX_CoseMsg_Encrypt_Deinit(&msg);

    // Full output content
    TEST_ASSERT_EQUAL(0, BSL_TestUtils_EncodeBundleToCBOR(&LocalTestCtx));
    TEST_ASSERT_TRUE(BSL_TestUtils_IsB16StrEqualTo(exA_5_enc, LocalTestCtx.mock_bpa_ctr.encoded));

    {
        BSL_Crypto_KeyStats_t stats;
        BSL_Crypto_GetKeyStatistics(keyhandle, &stats);
        TEST_ASSERT_EQUAL_size_t(1, stats.stats[BSL_CRYPTO_KEYSTATS_TIMES_USED]);
        TEST_ASSERT_EQUAL_size_t(32, stats.stats[BSL_CRYPTO_KEYSTATS_BYTES_PROCESSED]);
    }

    BSL_SecOper_Deinit(&sec_oper);
    BSL_Crypto_ReleaseKeyHandle(keyhandle);
}

// no use of OPT_MISMATCH_MODIFY_BLK_3 here (tag is in the ciphertext)
TEST_MATRIX([ BSL_SECROLE_VERIFIER, BSL_SECROLE_ACCEPTOR ], [ 0, 1, 2, 3, 4, 5 ])
void test_AppendixA_Example5_BCB_VerifyAccept(BSL_SecRole_e role, int mismatch)
{
    setenv("BSL_TEST_LOCAL_IPN_EID", "dtn://dst/", 1);
    BSL_Crypto_KeyHandle_t keyhandle;
    {
        BSL_Data_t keymat;
        BSL_Data_Init(&keymat);
        TEST_ASSERT_EQUAL(0, BSL_TestUtils_DecodeBase16_cstr(&keymat, exA_5_sk));
        TEST_ASSERT_EQUAL_INT(0, BSL_Crypto_LoadKey(keymat.ptr, keymat.len, &keyhandle));
        BSL_Data_Deinit(&keymat);

        BSL_IdValPair_SetInt64(BSL_Crypto_SetKeyParameter(keyhandle, BSLX_COSEMSG_KEY_PARAM_ALG),
                               BSLX_COSEMSG_KEY_PARAM_ALG, BSLX_COSEMSG_ALG_AES_KW_256);

        BSL_Data_t keyid = BSL_DATA_INIT_VIEW_CSTR(exA_5_kid);
        TEST_ASSERT_EQUAL_INT(0, BSL_Crypto_AddRegistryKey(&keyid, keyhandle));
    }

    TEST_ASSERT_EQUAL(0, BSL_TestUtils_LoadBundleFromCBOR(&LocalTestCtx, exA_5_enc));

    MockBPA_CanonicalBlock_t *alter_blk = NULL;
    if (mismatch == OPT_MISMATCH_MODIFY_BLK_0)
    {
        // manipulate encoded form
        BSL_Data_t *blk_enc = &LocalTestCtx.mock_bpa_ctr.bundle->primary_block.encoded;
        ((uint8_t *)blk_enc->ptr)[0] += 1;
    }
    else if ((mismatch == OPT_MISMATCH_MODIFY_BLK_1) || (mismatch == OPT_MISMATCH_MODIFY_BLK_3))
    {
        MockBPA_CanonicalBlock_t **found =
            MockBPA_BlockByNum_get(LocalTestCtx.mock_bpa_ctr.bundle->blocks_num, OPT_MISMATCH_MODIFY_BLK_1 ? 1 : 3);
        TEST_ASSERT_NOT_NULL(found);
        alter_blk = *found;
        TEST_ASSERT_NOT_NULL(alter_blk);

        ((uint8_t *)alter_blk->btsd)[alter_blk->btsd_len - 1] += 1;
    }

    BSL_SecOper_t sec_oper;
    BSL_SecOper_Init(&sec_oper);
    BSL_SecOper_Populate(&sec_oper, BSLX_COSESC_CTX_ID, 1, 3, BSL_SECBLOCKTYPE_BCB, role, BSL_POLICYACTION_DROP_BUNDLE);

    const char *opt_key_id = (mismatch == OPT_MISMATCH_BAD_KEY_ID) ? "other" : exA_5_kid;
    {
        BSL_IdValPair_t option;
        BSL_IdValPair_Init(&option);
        {
            BSL_Data_t kid;
            BSL_Data_InitView(&kid, strlen(opt_key_id), (BSL_DataPtr_t)opt_key_id);
            BSL_IdValPair_SetBytestr(&option, BSLX_COSESC_OPTION_KEY_ID, kid);
        }
        BSL_SecOper_AppendOption(&sec_oper, &option);
        BSL_IdValPair_Deinit(&option);
    }
    {
        BSL_IdValPair_t option;
        BSL_IdValPair_Init(&option);
        BSL_IdValPair_SetInt64(&option, BSLX_COSESC_OPTION_KEY_ALG,
                               (mismatch == OPT_MISMATCH_KEY_ALG) ? BSLX_COSEMSG_ALG_AES_KW_128
                                                                  : BSLX_COSEMSG_ALG_AES_KW_256);
        BSL_SecOper_AppendOption(&sec_oper, &option);
        BSL_IdValPair_Deinit(&option);
    }
    {
        BSL_IdValPair_t option;
        BSL_IdValPair_Init(&option);
        BSL_IdValPair_SetInt64(&option, BSLX_COSESC_OPTION_TGT_ALG,
                               (mismatch == OPT_MISMATCH_TGT_ALG) ? BSLX_COSEMSG_ALG_AES_GCM_128
                                                                  : BSLX_COSEMSG_ALG_AES_GCM_256);
        BSL_SecOper_AppendOption(&sec_oper, &option);
        BSL_IdValPair_Deinit(&option);
    }
    if (mismatch != OPT_MISMATCH_NO_AAD_SCOPE)
    {
        BSLX_CoseSc_AadScope_t scope;
        BSLX_CoseSc_AadScope_init(scope);
        BSLX_CoseSc_AadScope_set_at(scope, 0, 0x1);
        BSLX_CoseSc_AadScope_set_at(scope, -1, 0x1);

        BSL_Data_t value;
        BSL_Data_Init(&value);
        int res = BSL_CBOR_Encode_Twopass(&value, (BSL_CBOR_Encode_f)&BSLX_CoseSc_AadScope_Encode, &scope);
        TEST_ASSERT_EQUAL_INT_MESSAGE(BSL_SUCCESS, res, "Failed BSL_CBOR_Encode_Twopass()");
        BSLX_CoseSc_AadScope_clear(scope);

        BSL_IdValPair_t option;
        BSL_IdValPair_Init(&option);
        BSL_IdValPair_SetRaw(&option, BSLX_COSESC_OPTION_AAD_SCOPE, value.ptr, value.len);
        BSL_SecOper_AppendOption(&sec_oper, &option);
        BSL_IdValPair_Deinit(&option);
        BSL_Data_Deinit(&value);
    }

    bool valid_status = BSLX_CoseSc_Validate(&LocalTestCtx.bsl, &LocalTestCtx.mock_bpa_ctr.bundle_ref, &sec_oper);
    TEST_ASSERT_EQUAL(true, valid_status);

    const int expect_status = ((mismatch == OPT_MISMATCH_NONE) || (mismatch == OPT_MISMATCH_NO_AAD_SCOPE))
                                  ? BSL_SUCCESS
                                  : BSL_ERR_SECURITY_OPERATION_FAILED;
    // Confirm running operation as source executes without error
    int exec_status = BSL_ExecBCBVerifierAcceptor(&BSLX_CoseSc_Execute, &LocalTestCtx.bsl,
                                                  &LocalTestCtx.mock_bpa_ctr.bundle_ref, &sec_oper);
    TEST_ASSERT_EQUAL_INT(expect_status, exec_status);

    if (alter_blk)
    {
        // put back for output comparison
        ((uint8_t *)alter_blk->btsd)[alter_blk->btsd_len - 1] -= 1;
    }

    TEST_ASSERT_EQUAL(0, BSL_TestUtils_EncodeBundleToCBOR(&LocalTestCtx));
    if ((role == BSL_SECROLE_VERIFIER) || (BSL_SUCCESS != exec_status))
    {
        // Full output content
        TEST_ASSERT_TRUE(BSL_TestUtils_IsB16StrEqualTo(exA_5_enc, LocalTestCtx.mock_bpa_ctr.encoded));
    }
    else
    {
        // successful acceptance
        TEST_ASSERT_TRUE(BSL_TestUtils_IsB16StrEqualTo(exA_nosec, LocalTestCtx.mock_bpa_ctr.encoded));

        {
            BSL_Crypto_KeyStats_t stats;
            BSL_Crypto_GetKeyStatistics(keyhandle, &stats);
            TEST_ASSERT_EQUAL_size_t(1, stats.stats[BSL_CRYPTO_KEYSTATS_TIMES_USED]);
            TEST_ASSERT_EQUAL_size_t(32, stats.stats[BSL_CRYPTO_KEYSTATS_BYTES_PROCESSED]);
        }
    }

    BSL_SecOper_Deinit(&sec_oper);
    BSL_Crypto_ReleaseKeyHandle(keyhandle);
}

static const char *exA_6_kid = "ExampleA.6";
/// Symmetric key for Example A.6
static const char *exA_6_sk = "6c4e5271e211e0c8329ab8f363097f16516a459f12a4060cf0164968fdccbd63";
/// Result bundle for Example A.6 with different BCB block flags
static const char *exA_6_enc = "9f890700028201692f2f6473742f7376638201692f2f7372632f7376638201662f2f"
                               "7372632f821b000000bd51281400001a000f42404482a081c9850c03010058578101"
                               "03018201662f2f7372632f818205a2000120018181821860583b8443a10103a1054c"
                               "6f3093eba5d85143c3dc484af6818343a1012aa2044a4578616d706c65412e363350"
                               "2fa8c8352aea17faf7407271a5e90eb8408601010002566d0664951176f40600518b"
                               "5c32a2a2137871f1f045ad44d7042de5ff";

static int cose_exA_6_rng(unsigned char *buf, int len)
{
    if (len == 12) // IV
    {
        BSL_Data_t data;
        BSL_Data_Init(&data);
        TEST_ASSERT_EQUAL(0, BSL_TestUtils_DecodeBase16_cstr(&data, "6f3093eba5d85143c3dc484a"));
        memcpy(buf, data.ptr, data.len);
        BSL_Data_Deinit(&data);
        return 1;
    }
    else if (len == 16) // salt
    {
        BSL_Data_t data;
        BSL_Data_Init(&data);
        TEST_ASSERT_EQUAL(0, BSL_TestUtils_DecodeBase16_cstr(&data, "2fa8c8352aea17faf7407271a5e90eb8"));
        memcpy(buf, data.ptr, data.len);
        BSL_Data_Deinit(&data);
        return 1;
    }
    return 0;
}

void test_AppendixA_Example6_BCB_Source(void)
{
    setenv("BSL_TEST_LOCAL_IPN_EID", "dtn://src/", 1);
    BSL_Crypto_SetRngGenerator(cose_exA_6_rng);
    BSL_Crypto_KeyHandle_t keyhandle;
    {
        {
            BSL_Data_t keymat;
            BSL_Data_Init(&keymat);
            TEST_ASSERT_EQUAL(0, BSL_TestUtils_DecodeBase16_cstr(&keymat, exA_6_sk));
            TEST_ASSERT_EQUAL_INT(0, BSL_Crypto_LoadKey(keymat.ptr, keymat.len, &keyhandle));
            BSL_Data_Deinit(&keymat);
        }
        BSL_IdValPair_SetInt64(BSL_Crypto_SetKeyParameter(keyhandle, BSLX_COSEMSG_KEY_PARAM_ALG),
                               BSLX_COSEMSG_KEY_PARAM_ALG, BSLX_COSEMSG_ALG_DIRECT_HKDF_SHA_512);

        BSL_Data_t keyid = BSL_DATA_INIT_VIEW_CSTR(exA_6_kid);
        BSL_Crypto_AddRegistryKey(&keyid, keyhandle);
    }

    TEST_ASSERT_EQUAL(0, BSL_TestUtils_LoadBundleFromCBOR(&LocalTestCtx, exA_nosec));

    BSL_SecOper_t sec_oper;
    BSL_SecOper_Init(&sec_oper);
    BSL_SecOper_Populate(&sec_oper, BSLX_COSESC_CTX_ID, 1, 3, BSL_SECBLOCKTYPE_BCB, BSL_SECROLE_SOURCE,
                         BSL_POLICYACTION_DROP_BUNDLE);

    {
        BSL_IdValPair_t option;
        BSL_IdValPair_Init(&option);
        {
            BSL_Data_t keyid = BSL_DATA_INIT_VIEW_CSTR(exA_6_kid);
            BSL_IdValPair_SetBytestr(&option, BSLX_COSESC_OPTION_KEY_ID, keyid);
        }
        BSL_SecOper_AppendOption(&sec_oper, &option);
        BSL_IdValPair_Deinit(&option);
    }
    {
        BSL_IdValPair_t option;
        BSL_IdValPair_Init(&option);
        BSL_IdValPair_SetInt64(&option, BSLX_COSESC_OPTION_SALT_LENGTH, 16);
        BSL_SecOper_AppendOption(&sec_oper, &option);
        BSL_IdValPair_Deinit(&option);
    }
    {
        BSL_IdValPair_t option;
        BSL_IdValPair_Init(&option);
        BSL_IdValPair_SetInt64(&option, BSLX_COSESC_OPTION_TGT_ALG, BSLX_COSEMSG_ALG_AES_GCM_256);
        BSL_SecOper_AppendOption(&sec_oper, &option);
        BSL_IdValPair_Deinit(&option);
    }
    {
        BSL_IdValPair_t option;
        BSL_IdValPair_Init(&option);
        {
            BSLX_CoseSc_AadScope_t scope;
            BSLX_CoseSc_AadScope_init(scope);
            BSLX_CoseSc_AadScope_set_at(scope, 0, 0x1);
            BSLX_CoseSc_AadScope_set_at(scope, -1, 0x1);

            BSL_Data_t value;
            BSL_Data_Init(&value);
            int res = BSL_CBOR_Encode_Twopass(&value, (BSL_CBOR_Encode_f)&BSLX_CoseSc_AadScope_Encode, &scope);
            TEST_ASSERT_EQUAL_INT_MESSAGE(BSL_SUCCESS, res, "Failed BSL_CBOR_Encode_Twopass()");
            BSLX_CoseSc_AadScope_clear(scope);

            BSL_IdValPair_SetRaw(&option, BSLX_COSESC_OPTION_AAD_SCOPE, value.ptr, value.len);
            BSL_Data_Deinit(&value);
        }
        BSL_SecOper_AppendOption(&sec_oper, &option);
        BSL_IdValPair_Deinit(&option);
    }

    bool valid_status = BSLX_CoseSc_Validate(&LocalTestCtx.bsl, &LocalTestCtx.mock_bpa_ctr.bundle_ref, &sec_oper);
    TEST_ASSERT_TRUE(valid_status);

    // Confirm running operation as source executes without error
    int exec_status =
        BSL_ExecBCBSource(&BSLX_CoseSc_Execute, &LocalTestCtx.bsl, &LocalTestCtx.mock_bpa_ctr.bundle_ref, &sec_oper);
    TEST_ASSERT_EQUAL(BSL_SUCCESS, exec_status);

    // Confirm it produced only 1 result
    TEST_ASSERT_EQUAL(1, BSL_SecOper_CountResults(&sec_oper));
    const BSL_IdValPair_t *result = BSL_SecOper_FindResult(&sec_oper, BSLX_COSESC_RESULT_COSE_ENCRYPT);
    TEST_ASSERT_NOT_NULL(result);
    TEST_ASSERT_EQUAL(BSLX_COSESC_RESULT_COSE_ENCRYPT, BSL_IdValPair_GetId(result));
    TEST_ASSERT_TRUE(BSL_IdValPair_IsBytestr(result));

    // Inspect in the result
    BSLX_CoseMsg_Encrypt_t msg;
    BSLX_CoseMsg_Encrypt_Init(&msg);
    {
        BSL_Data_t in_buf;
        TEST_ASSERT_EQUAL(BSL_SUCCESS, BSL_IdValPair_GetAsBytestr(result, &in_buf));
        TEST_ASSERT_EQUAL(BSL_SUCCESS, BSL_CBOR_Decode(&in_buf, (BSL_CBOR_Decode_f)&BSLX_CoseMsg_Encrypt_Decode, &msg));
        BSL_Data_Deinit(&in_buf);
    }
    BSLX_CoseMsg_Encrypt_Deinit(&msg);

    // Full output content
    TEST_ASSERT_EQUAL(0, BSL_TestUtils_EncodeBundleToCBOR(&LocalTestCtx));
    TEST_ASSERT_TRUE(BSL_TestUtils_IsB16StrEqualTo(exA_6_enc, LocalTestCtx.mock_bpa_ctr.encoded));

    {
        BSL_Crypto_KeyStats_t stats;
        BSL_Crypto_GetKeyStatistics(keyhandle, &stats);
        TEST_ASSERT_EQUAL_size_t(1, stats.stats[BSL_CRYPTO_KEYSTATS_TIMES_USED]);
        TEST_ASSERT_EQUAL_size_t(32, stats.stats[BSL_CRYPTO_KEYSTATS_BYTES_PROCESSED]);
    }

    BSL_SecOper_Deinit(&sec_oper);
    BSL_Crypto_ReleaseKeyHandle(keyhandle);
}
