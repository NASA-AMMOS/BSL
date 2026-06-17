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
    setenv("BSL_TEST_LOCAL_IPN_EID", "ipn:2.1", 1);
    TEST_ASSERT_EQUAL(0, BSL_TestContext_Init(&LocalTestCtx));
}

void tearDown(void)
{
    BSL_CryptoDeinit();
    TEST_ASSERT_EQUAL(0, BSL_TestContext_Deinit(&LocalTestCtx));
}

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
    const char *hex_bundle = "9f890700028201692f2f6473742f7376638201692f2f7372632f7376638201662f2f"
                             "7372632f821b000000bd51281400001a000f42404482a081c9860101000246656865"
                             "6c6c6f444ec359d2ff";
    TEST_ASSERT_EQUAL(0, BSL_TestUtils_LoadBundleFromCBOR(&LocalTestCtx, hex_bundle));

    BSL_SecOper_t sec_oper;
    BSL_SecOper_Init(&sec_oper);
    BSL_SecOper_Populate(&sec_oper, BSLX_COSESC_CTX_ID, 1, 0, BSL_SECBLOCKTYPE_BIB, BSL_SECROLE_SOURCE,
                         BSL_POLICYACTION_DROP_BUNDLE);

    {
        BSL_SecParam_t param;
        BSL_SecParam_Init(&param);
        {
            BSL_Data_t kid;
            BSL_Data_InitView(&kid, 4, (BSL_DataPtr_t) "1234");
            BSL_SecParam_SetBytestr(&param, BSLX_COSESC_OPT_KEYID, kid);
        }
        BSL_SecOper_AppendOption(&sec_oper, &param);
        BSL_SecParam_Deinit(&param);
    }
    {
        BSL_SecParam_t param;
        BSL_SecParam_Init(&param);
        BSL_SecParam_SetUint64(&param, BSLX_COSESC_OPT_TGT_ALG, 123 /*FIXME*/);
        BSL_SecOper_AppendOption(&sec_oper, &param);
        BSL_SecParam_Deinit(&param);
    }

    //    BSL_SecOper_AppendParam(&sec_oper, &context->param_sha_variant);
    //    BSL_SecOper_AppendParam(&sec_oper, &context->param_scope_flags);
    //    BSL_SecOper_AppendParam(&sec_oper, &context->param_test_key);
    //    BSL_SecOper_AppendParam(&sec_oper, &context->use_key_wrap);

    BSL_SecOutcome_t *outcome = BSL_calloc(1, BSL_SecOutcome_Sizeof());
    BSL_SecOutcome_Init(outcome, &sec_oper);

    bool valid_status = BSLX_CoseSc_Validate(&LocalTestCtx.bsl, &LocalTestCtx.mock_bpa_ctr.bundle_ref, &sec_oper);
    TEST_ASSERT_TRUE(valid_status);

    /// Confirm running operation as source executes without error
    int exec_status = BSLX_CoseSc_Execute(&LocalTestCtx.bsl, &LocalTestCtx.mock_bpa_ctr.bundle_ref, &sec_oper, outcome);
    TEST_ASSERT_EQUAL(BSL_SUCCESS, exec_status);

#if 0
    /// Confirm it produced only 1 result
    TEST_ASSERT_EQUAL(1, BSL_SecOutcome_CountResults(outcome));
    const BSL_SecResult_t *bib_result = BSL_SecOutcome_GetResultAtIndex(outcome, 0);
    TEST_ASSERT_NOT_NULL(bib_result);

    /// Confirm the context and result result is the right ID (Defined in RFC)
    TEST_ASSERT_EQUAL(RFC9173_CONTEXTID_BIB_HMAC_SHA2, bib_result->context_id);
    TEST_ASSERT_EQUAL(RFC9173_BIB_RESULTID_HMAC, bib_result->result_id);
    TEST_ASSERT_EQUAL(1, bib_result->target_block_num);

    {
        /// Confirm the actual HMAC signature matches what is in the RFC
        BSL_Data_t view;
        TEST_ASSERT_EQUAL(0, BSL_SecResult_GetAsBytestr(bib_result, &view));
        TEST_ASSERT_EQUAL(sizeof(ApxA1_HMAC), view.len);
        TEST_ASSERT_EQUAL_MEMORY(ApxA1_HMAC, view.ptr, sizeof(ApxA1_HMAC));
    }
#endif

    BSL_SecOutcome_Deinit(outcome);
    BSL_free(outcome);
    BSL_SecOper_Deinit(&sec_oper);
}
