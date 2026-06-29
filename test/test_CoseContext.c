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

#include <BPSecLib_Private.h>
#include <mock_bpa/MockBPA.h>
#include <CryptoInterface.h>

#include <backend/PublicInterfaceImpl.h>
#include <cose_sc/CoseContext.h>
#include <cose_sc/CoseMsg.h>

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
    setenv("BSL_TEST_LOCAL_IPN_EID", "dtn://src/", 1);
    TEST_ASSERT_EQUAL(0, BSL_TestContext_Init(&LocalTestCtx));
}

void tearDown(void)
{
    BSL_CryptoDeinit();
    TEST_ASSERT_EQUAL(0, BSL_TestContext_Deinit(&LocalTestCtx));
}

/// Common input bundle from Appendix A
static const char *exA_nosec = "9f890700028201692f2f6473742f7376638201692f2f7372632f7376638201662f2f"
                               "7372632f821b000000bd51281400001a000f42404482a081c9860101000246656865"
                               "6c6c6f444ec359d2ff";

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
 *  - Capture the outcome from the above function to confirm 1 result (a COSE_Mac0 message)
 *  - Capture the MAC tag and ensure it matches the value in the test vector.
 */
void test_AppendixA_Example1_BIB_Source(void)
{
    {
        BSL_Data_t keymat;
        BSL_Data_Init(&keymat);
        TEST_ASSERT_EQUAL(0, BSL_TestUtils_DecodeBase16_cstr(&keymat, exA_1_sk));
        BSL_Crypto_AddRegistryKey(exA_1_kid, keymat.ptr, keymat.len);
        BSL_Data_Deinit(&keymat);
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
            BSL_Data_t kid;
            BSL_Data_InitView(&kid, strlen(exA_1_kid), (BSL_DataPtr_t)exA_1_kid);
            BSL_IdValPair_SetBytestr(&option, BSLX_COSESC_OPTION_KEY_ID, kid);
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
            if (BSL_SUCCESS != res)
            {
                TEST_FAIL_MESSAGE("Failed to encode AAD Scope");
            }
            BSLX_CoseSc_AadScope_clear(scope);

            BSL_IdValPair_SetRaw(&option, BSLX_COSESC_OPTION_AAD_SCOPE, value.ptr, value.len);
            BSL_Data_Deinit(&value);
        }
        BSL_SecOper_AppendOption(&sec_oper, &option);
        BSL_IdValPair_Deinit(&option);
    }

    BSL_SecOutcome_t *outcome = BSL_calloc(1, BSL_SecOutcome_Sizeof());
    BSL_SecOutcome_Init(outcome, &sec_oper);

    bool valid_status = BSLX_CoseSc_Validate(&LocalTestCtx.bsl, &LocalTestCtx.mock_bpa_ctr.bundle_ref, &sec_oper);
    TEST_ASSERT_TRUE(valid_status);

    // Confirm running operation as source executes without error
    int exec_status = BSL_ExecBIBSource(&BSLX_CoseSc_Execute, &LocalTestCtx.bsl, &LocalTestCtx.mock_bpa_ctr.bundle_ref,
                                        &sec_oper, outcome);
    TEST_ASSERT_EQUAL(BSL_SUCCESS, exec_status);

    // Confirm it produced only 1 result
    TEST_ASSERT_EQUAL(1, BSL_SecOutcome_CountResults(outcome));
    const BSL_IdValPair_t *result = BSL_SecOutcome_GetResultAtIndex(outcome, 0);
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
    // Confirm the actual HMAC tag matches what is in the RFC
    TEST_ASSERT_TRUE(BSL_TestUtils_IsB16StrEqualTo(
        "ec8260a38a1a00fef2cd4aae063f50f01c5645e84c6c4893ca895eed44ef60a5f50f9adf5cc5654499b881e589637805", msg.tag));

    // Full output content
    TEST_ASSERT_EQUAL(0, BSL_TestUtils_ComapreBundleAsCBOR(&LocalTestCtx, exA_1_mac0));

    BSLX_CoseMsg_Mac0_Deinit(&msg);
    BSL_SecOutcome_Deinit(outcome);
    BSL_free(outcome);
    BSL_SecOper_Deinit(&sec_oper);
}

enum OptMismatch_e
{
    OPT_MISMATCH_NONE,
    OPT_MISMATCH_BAD_KEY_ID,
    OPT_MISMATCH_ALG,
    OPT_MISMATCH_NO_AAD_SCOPE,
    OPT_MISMATCH_MODIFY_BLK_0,
    OPT_MISMATCH_MODIFY_BLK_1,
    OPT_MISMATCH_MODIFY_BLK_3,
};

TEST_MATRIX([ BSL_SECROLE_VERIFIER, BSL_SECROLE_ACCEPTOR ], [ 0, 1, 2, 3, 4, 5, 6 ])
void test_AppendixA_Example1_BIB_VerifyAccept(BSL_SecRole_e role, int mismatch)
{
    {
        BSL_Data_t keymat;
        BSL_Data_Init(&keymat);
        TEST_ASSERT_EQUAL(0, BSL_TestUtils_DecodeBase16_cstr(&keymat, exA_1_sk));
        BSL_Crypto_AddRegistryKey(exA_1_kid, keymat.ptr, keymat.len);
        BSL_Data_Deinit(&keymat);
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
        BSL_IdValPair_SetInt64(&option, BSLX_COSESC_OPTION_TGT_ALG,
                               (mismatch == OPT_MISMATCH_ALG) ? BSLX_COSEMSG_ALG_HMAC_SHA_256_256
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
        if (BSL_SUCCESS != res)
        {
            TEST_FAIL_MESSAGE("Failed to encode AAD Scope");
        }
        BSLX_CoseSc_AadScope_clear(scope);

        BSL_IdValPair_t option;
        BSL_IdValPair_Init(&option);
        BSL_IdValPair_SetRaw(&option, BSLX_COSESC_OPTION_AAD_SCOPE, value.ptr, value.len);
        BSL_SecOper_AppendOption(&sec_oper, &option);
        BSL_IdValPair_Deinit(&option);
        BSL_Data_Deinit(&value);
    }

    BSL_SecOutcome_t *outcome = BSL_calloc(1, BSL_SecOutcome_Sizeof());
    BSL_SecOutcome_Init(outcome, &sec_oper);

    bool valid_status = BSLX_CoseSc_Validate(&LocalTestCtx.bsl, &LocalTestCtx.mock_bpa_ctr.bundle_ref, &sec_oper);
    TEST_ASSERT_EQUAL_INT(opt_key_id == exA_1_kid ? true : false, valid_status);

    const int expect_status = ((mismatch == OPT_MISMATCH_NONE) || (mismatch == OPT_MISMATCH_NO_AAD_SCOPE))
                                  ? BSL_SUCCESS
                                  : BSL_ERR_SECURITY_OPERATION_FAILED;
    // Confirm running operation as source executes without error
    int exec_status = BSL_ExecBIBVerifierAcceptor(&BSLX_CoseSc_Execute, &LocalTestCtx.bsl,
                                                  &LocalTestCtx.mock_bpa_ctr.bundle_ref, &sec_oper, outcome);
    TEST_ASSERT_EQUAL_INT(expect_status, exec_status);

    if (alter_blk)
    {
        // put back for output comparison
        ((uint8_t *)alter_blk->btsd)[alter_blk->btsd_len - 1] -= 1;
    }

    if ((role == BSL_SECROLE_VERIFIER) || (BSL_SUCCESS != exec_status))
    {
        // Full output content
        TEST_ASSERT_EQUAL(0, BSL_TestUtils_ComapreBundleAsCBOR(&LocalTestCtx, exA_1_mac0));
    }
    else
    {
        TEST_ASSERT_EQUAL(0, BSL_TestUtils_ComapreBundleAsCBOR(&LocalTestCtx, exA_nosec));
    }

    BSL_SecOutcome_Deinit(outcome);
    BSL_free(outcome);
    BSL_SecOper_Deinit(&sec_oper);
}
