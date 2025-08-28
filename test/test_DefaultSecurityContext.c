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
/** @file
 *
 * @brief Specific low-level tests of the Default Security Context
 *
 * Notes:
 *  - These tests use constructs defined in the BSL to exercise the Default Security Context
 *  - It uses test inputs and vectors from RFC9173 Appendix A.
 *  - It does NOT use any of the "Plumbing" inside the BSL.
 *  - It only directly calls the interfaces exposed by the Default Security Context.
 *  - BCB internally is functionally complete, however it needs better integration with BPA to overwrite BTSD.
 *
 * @ingroup unit-tests
 */
#include <stdlib.h>
#include <stdio.h>
#include <unity.h>

#include <BPSecLib_Private.h>
#include <mock_bpa/MockBPA.h>
#include <CryptoInterface.h>

#include <backend/PublicInterfaceImpl.h>
#include <security_context/DefaultSecContext.h>
#include <security_context/DefaultSecContext_Private.h>
#include <security_context/rfc9173.h>

#include "bsl_test_utils.h"

static BSL_TestContext_t LocalTestCtx;

void suiteSetUp(void)
{
//    BSL_openlog();
    assert(0 == bsl_mock_bpa_agent_init());
}

int suiteTearDown(int failures)
{
    bsl_mock_bpa_agent_deinit();
    BSL_closelog();
    return failures;
}

void setUp(void)
{
    setenv("BSL_TEST_LOCAL_IPN_EID", "ipn:2.1", 1);
    memset(&LocalTestCtx, 0, sizeof(LocalTestCtx));
    TEST_ASSERT_EQUAL(0, BSL_API_InitLib(&LocalTestCtx.bsl));
    mock_bpa_ctr_init(&LocalTestCtx.mock_bpa_ctr);
    BSL_TestUtils_SetupDefaultSecurityContext(&LocalTestCtx.bsl);
}

void tearDown(void)
{
    mock_bpa_ctr_deinit(&LocalTestCtx.mock_bpa_ctr);
    BSL_CryptoDeinit();
    TEST_ASSERT_EQUAL(0, BSL_API_DeinitLib(&LocalTestCtx.bsl));
}

/**
 * @brief Purpose: Exercise BIB applying security to a target payload block.
 *
 * Steps:
 *  - Get an unsecured bundle with a primary and payload block (From RFC9173)
 *  - Decode it into a BSL_BundleCtx struct
 *  - Create a BIB security operation with hard-coded arguments (From RFC9173 A1 ASB)
 *  - Run the DefaultSecuritContext's BSLX_BIB_Execute function and confirm result is 0.
 *  - Capture the outcome from the above function to confirm 1 result (the authentication code)
 *  - Capture the auth code and ensure it matches the value in the test vector.
 *
 * Notes:
 *  - Common repeated patterns are in the process of being factored out
 *  - All values are drawn from RFC9173 Appendix A.
 */
void test_RFC9173_AppendixA_Example1_BIB_Source(void)
{
    BSL_Crypto_SetRngGenerator(rfc9173_byte_gen_fn_a1);

    TEST_ASSERT_EQUAL(
        0, BSL_TestUtils_LoadBundleFromCBOR(&LocalTestCtx, RFC9173_TestVectors_AppendixA1.cbor_bundle_original));
    mock_bpa_ctr_t *mock_bpa_ctr = &LocalTestCtx.mock_bpa_ctr;

    BIBTestContext bib_test_context;
    BSL_TestUtils_InitBIB_AppendixA1(&bib_test_context, BSL_SECROLE_SOURCE, RFC9173_EXAMPLE_A1_KEY);

    BSL_SecOutcome_t *sec_outcome = BSL_CALLOC(1, BSL_SecOutcome_Sizeof());
    BSL_SecOutcome_Init(sec_outcome, &bib_test_context.sec_oper, BSL_SecOutcome_Sizeof());

    /// Confirm running BIB as source executes without error
    int bib_exec_status =
        BSLX_BIB_Execute(&LocalTestCtx.bsl, &mock_bpa_ctr->bundle_ref, &bib_test_context.sec_oper, sec_outcome);
    TEST_ASSERT_EQUAL(BSL_SUCCESS, bib_exec_status);

    /// Confirm it produced only 1 result
    TEST_ASSERT_EQUAL(1, BSL_SecOutcome_CountResults(sec_outcome));
    const BSL_SecResult_t *bib_result = BSL_SecOutcome_GetResultAtIndex(sec_outcome, 0);

    /// Confirm the context and result result is the right ID (Defined in RFC)
    TEST_ASSERT_EQUAL(RFC9173_CONTEXTID_BIB_HMAC_SHA2, bib_result->context_id);
    TEST_ASSERT_EQUAL(RFC9173_BIB_RESULTID_HMAC, bib_result->result_id);
    TEST_ASSERT_EQUAL(1, bib_result->target_block_num);

    /// Confirm the actual HMAC signature matches what is in the RFC
    TEST_ASSERT_EQUAL(sizeof(ApxA1_HMAC), bib_result->_bytelen);
    TEST_ASSERT_TRUE(memcmp(ApxA1_HMAC, bib_result->_bytes, sizeof(ApxA1_HMAC)) == 0);

    BSL_SecOutcome_Deinit(sec_outcome);
    BSL_SecOper_Deinit(&bib_test_context.sec_oper);
    BSL_FREE(sec_outcome);
}

// /// @brief Purpose: Exercise BIB verifying a security block.
// void test_DefaultSecuritContext_RFC9173_A1_BIB_Verifier(void) {}

// /// @brief Purpose: Exercise BIB verifying a security block with cryptographic mismatch.
// void test_DefaultSecuritContext_RFC9173_A1_BIB_Verifier_Failure(void) {}

/**
 * @brief Purpose: Exercise BCB applying security to a target payload block.
 *
 * Steps:
 *  - Get an unsecured bundle with a primary and payload block (From RFC9173)
 *  - Decode it into a BSL_BundleCtx struct
 *  - Create a BCB security operation with hard-coded arguments (From RFC9173 A2 ASB)
 *  - Run the DefaultSecuritContext's BSLX_BCB_Execute function and confirm result is 0.
 *  - Capture the outcome from the above function to confirm 1 result (the auth tag) is present
 *  - Capture the auth tag and ensure it matches the value in the test vector.
 *
 * Notes:
 *  - Incomplete since it does not modify the bundle BTSD (This still needs to be worked out)
 */
void test_RFC9173_AppendixA_Example2_BCB_Source(void)
{
    BSL_Crypto_SetRngGenerator(rfc9173_byte_gen_fn_a2_cek);
    // Loads the bundle
    TEST_ASSERT_EQUAL(
        0, BSL_TestUtils_LoadBundleFromCBOR(&LocalTestCtx, RFC9173_TestVectors_AppendixA1.cbor_bundle_original));
    mock_bpa_ctr_t *mock_bpa_ctr = &LocalTestCtx.mock_bpa_ctr;

    BCBTestContext bcb_test_context;
    BSL_TestUtils_InitBCB_Appendix2(&bcb_test_context, BSL_SECROLE_SOURCE);

    BSL_SecOutcome_t *outcome = BSL_CALLOC(1, BSL_SecOutcome_Sizeof());
    BSL_SecOutcome_Init(outcome, &bcb_test_context.sec_oper, 10000);

    // Execute BCB as source, confirm result is 0 (success)
    int bcb_exec_result =
        BSLX_BCB_Execute(&LocalTestCtx.bsl, &mock_bpa_ctr->bundle_ref, &bcb_test_context.sec_oper, outcome);
    TEST_ASSERT_EQUAL(BSL_SUCCESS, bcb_exec_result);

    // Confirm the output produces one result (the AES-GCM auth code)
    TEST_ASSERT_EQUAL(1, BSL_SecOutcome_CountResults(outcome));
    const BSL_SecResult_t *auth_tag_result = BSL_SecOutcome_GetResultAtIndex(outcome, 0);

    // Confirm that AUTHTAG result id is there
    TEST_ASSERT_EQUAL(RFC9173_BCB_RESULTID_AUTHTAG, auth_tag_result->result_id);

    // Confirm expected vs actual auth tag byte length's match and they are equal
    TEST_ASSERT_EQUAL(sizeof(ApxA2_AuthTag), auth_tag_result->_bytelen);
    TEST_ASSERT_EQUAL_MEMORY(ApxA2_AuthTag, auth_tag_result->_bytes, sizeof(ApxA2_AuthTag));

    MockBPA_CanonicalBlock_t **target_ptr = MockBPA_BlockByNum_get(mock_bpa_ctr->bundle->blocks_num, 1);
    TEST_ASSERT_NOT_NULL(target_ptr);
    MockBPA_CanonicalBlock_t *target_block = *target_ptr;
    TEST_ASSERT_NOT_NULL(target_block);

    TEST_ASSERT_EQUAL_size_t(sizeof(ApxA2_Ciphertext), target_block->btsd_len);
    uint8_t logstr[500];
    BSL_LOG_INFO("EXPECTED payload: %s",
                 BSL_Log_DumpAsHexString(logstr, sizeof(logstr), ApxA2_Ciphertext, sizeof(ApxA2_Ciphertext)));
    BSL_LOG_INFO("ACTUAL payload:   %s",
                 BSL_Log_DumpAsHexString(logstr, sizeof(logstr), target_block->btsd, target_block->btsd_len));
    TEST_ASSERT_EQUAL_MEMORY(ApxA2_Ciphertext, target_block->btsd, sizeof(ApxA2_Ciphertext));

    BSL_SecOutcome_Deinit(outcome);
    BSL_SecOper_Deinit(&bcb_test_context.sec_oper);
    BSL_FREE(outcome);
}

void test_RFC9173_AppendixA_Example2_BCB_Acceptor(void)
{
    TEST_ASSERT_EQUAL(0,
                      BSL_TestUtils_LoadBundleFromCBOR(&LocalTestCtx, RFC9173_TestVectors_AppendixA2.cbor_bundle_bcb));
    mock_bpa_ctr_t *mock_bpa_ctr = &LocalTestCtx.mock_bpa_ctr;

    BCBTestContext bcb_test_context;
    BSL_TestUtils_InitBCB_Appendix2(&bcb_test_context, BSL_SECROLE_ACCEPTOR);

    BSL_SecOutcome_t *outcome = BSL_CALLOC(1, BSL_SecOutcome_Sizeof());
    BSL_SecOutcome_Init(outcome, &bcb_test_context.sec_oper, 10000);

    /// Confirm that BCB executes with SUCCESS
    int bcb_exec_result =
        BSLX_BCB_Execute(&LocalTestCtx.bsl, &mock_bpa_ctr->bundle_ref, &bcb_test_context.sec_oper, outcome);
    TEST_ASSERT_EQUAL(BSL_SUCCESS, bcb_exec_result);

    /// Confirm that running as ACCEPTOR consumes result.
#if 0
    // TODO why is this failing?
    size_t result_count = BSL_SecOutcome_CountResults(outcome);
    TEST_ASSERT_EQUAL(0, result_count);
#endif

    /// Confirm that the target block is decrypted correctly.
    MockBPA_CanonicalBlock_t **target_ptr = MockBPA_BlockByNum_get(mock_bpa_ctr->bundle->blocks_num, 1);
    TEST_ASSERT_NOT_NULL(target_ptr);
    MockBPA_CanonicalBlock_t *target_block = *target_ptr;
    TEST_ASSERT_NOT_NULL(target_block);

    TEST_ASSERT_EQUAL_size_t(sizeof(ApxA2_PayloadData), target_block->btsd_len);
    uint8_t logstr[500];
    BSL_LOG_INFO("EXPECTED payload: %s",
                 BSL_Log_DumpAsHexString(logstr, sizeof(logstr), ApxA2_PayloadData, sizeof(ApxA2_PayloadData)));
    BSL_LOG_INFO("ACTUAL payload:   %s",
                 BSL_Log_DumpAsHexString(logstr, sizeof(logstr), target_block->btsd, target_block->btsd_len));
    TEST_ASSERT_EQUAL_MEMORY(ApxA2_PayloadData, target_block->btsd, sizeof(ApxA2_PayloadData));

    BSL_SecOutcome_Deinit(outcome);
    BSL_SecOper_Deinit(&bcb_test_context.sec_oper);
    BSL_FREE(outcome);
}

int rfc3394_cek(unsigned char *buf, int len)
{
    if (len == 12) // IV
    {
        uint8_t iv[] = { 0x54, 0x77, 0x65, 0x6c, 0x76, 0x65, 0x31, 0x32, 0x31, 0x32, 0x31, 0x32 };
        memcpy(buf, iv, len);
    }
    else
    {
        uint8_t cek_buf[] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                              0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF };
        memcpy(buf, cek_buf, len);
    }
    return 1;
}

TEST_MATRIX([ true, false ], [ true, false ])
void ntest_sec_source_keywrap(bool wrap, bool bib)
{
    string_t cek_str;
    string_init_set_str(cek_str, "00112233445566778899AABBCCDDEEFF");
    BSL_Data_t cek_data;
    BSL_Data_Init(&cek_data);
    TEST_ASSERT_EQUAL(BSL_TestUtils_DecodeBase16(&cek_data, cek_str), 0);
    string_clear(cek_str);

    string_t kek_str;
    string_init_set_str(kek_str, "000102030405060708090A0B0C0D0E0F");
    BSL_Data_t kek_data;
    BSL_Data_Init(&kek_data);
    TEST_ASSERT_EQUAL(BSL_TestUtils_DecodeBase16(&kek_data, kek_str), 0);
    string_clear(kek_str);

    string_t wrapped_key_str;
    string_init_set_str(wrapped_key_str, "1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5");
    BSL_Data_t wrapped_key_data;
    BSL_Data_Init(&wrapped_key_data);
    TEST_ASSERT_EQUAL(BSL_TestUtils_DecodeBase16(&wrapped_key_data, wrapped_key_str), 0);
    string_clear(wrapped_key_str);

    string_t result_data_str;
    if (bib)
    {
        // sign
        string_init_set_str(result_data_str, "756D484ED764AEF06A35C53D6033B5311258EE21748B5FD53A53C8F55793D7A6B021E0CEC"
                                             "4A5C461CA6C179649EC7BBFC1EA89639409B809086B820216EFCF7B");
    }
    else
    {
        // authtag
        string_init_set_str(result_data_str, "F6DC43C2EE046C7AE713F0531B2BCB48");
    }
    BSL_Data_t result_data;
    BSL_Data_Init(&result_data);
    TEST_ASSERT_EQUAL(BSL_TestUtils_DecodeBase16(&result_data, result_data_str), 0);
    string_clear(result_data_str);

    TEST_ASSERT_EQUAL(
        0, BSL_TestUtils_LoadBundleFromCBOR(&LocalTestCtx, RFC9173_TestVectors_AppendixA1.cbor_bundle_original));
    mock_bpa_ctr_t *mock_bpa_ctr = &LocalTestCtx.mock_bpa_ctr;

    BSL_SecOutcome_t      *sec_outcome = BSL_CALLOC(1, BSL_SecOutcome_Sizeof());
    const BSL_SecResult_t *result;
    BIBTestContext         bibcontext;
    BCBTestContext         bcbcontext;
    if (bib)
    {
        if (wrap)
        {
            BSL_Crypto_AddRegistryKey("kek_wrap", kek_data.ptr, kek_data.len);
            BSL_SecParam_InitStr(&bibcontext.param_test_key, BSL_SECPARAM_TYPE_KEY_ID, "kek_wrap");
            BSL_SecParam_InitInt64(&bibcontext.use_key_wrap, BSL_SECPARAM_USE_KEY_WRAP, 1);
            BSL_Crypto_SetRngGenerator(rfc3394_cek);
        }
        else
        {
            BSL_Crypto_AddRegistryKey("cek_wrap", cek_data.ptr, cek_data.len);
            BSL_SecParam_InitStr(&bibcontext.param_test_key, BSL_SECPARAM_TYPE_KEY_ID, "cek_wrap");
            BSL_SecParam_InitInt64(&bibcontext.use_key_wrap, BSL_SECPARAM_USE_KEY_WRAP, 0);
        }
        BSL_SecParam_InitInt64(&bibcontext.param_scope_flags, RFC9173_BIB_PARAMID_INTEG_SCOPE_FLAG, 0);
        BSL_SecParam_InitInt64(&bibcontext.param_sha_variant, RFC9173_BIB_PARAMID_SHA_VARIANT, RFC9173_BIB_SHA_HMAC512);

        BSL_SecOper_Init(&bibcontext.sec_oper);
        BSL_SecOper_Populate(&bibcontext.sec_oper, 1, 1, 2, BSL_SECBLOCKTYPE_BIB, BSL_SECROLE_SOURCE,
                             BSL_POLICYACTION_DROP_BLOCK);
        BSL_SecOper_AppendParam(&bibcontext.sec_oper, &bibcontext.param_sha_variant);
        BSL_SecOper_AppendParam(&bibcontext.sec_oper, &bibcontext.param_scope_flags);
        BSL_SecOper_AppendParam(&bibcontext.sec_oper, &bibcontext.param_test_key);
        BSL_SecOper_AppendParam(&bibcontext.sec_oper, &bibcontext.use_key_wrap);

        BSL_SecOutcome_Init(sec_outcome, &bibcontext.sec_oper, BSL_SecOutcome_Sizeof());

        int bib_exec_status =
            BSLX_BIB_Execute(&LocalTestCtx.bsl, &mock_bpa_ctr->bundle_ref, &bibcontext.sec_oper, sec_outcome);
        TEST_ASSERT_EQUAL(BSL_SUCCESS, bib_exec_status);

        TEST_ASSERT_EQUAL(1, BSL_SecOutcome_CountResults(sec_outcome));
        result = BSL_SecOutcome_GetResultAtIndex(sec_outcome, 0);

        TEST_ASSERT_EQUAL(RFC9173_BIB_RESULTID_HMAC, result->result_id);
        TEST_ASSERT_EQUAL(1, result->target_block_num);
    }
    else
    {
        BSL_Crypto_SetRngGenerator(rfc3394_cek);
        if (wrap)
        {
            BSL_Crypto_AddRegistryKey("kek_wrap", kek_data.ptr, kek_data.len);
            BSL_SecParam_InitStr(&bcbcontext.param_test_key_id, BSL_SECPARAM_TYPE_KEY_ID, "kek_wrap");
            BSL_SecParam_InitInt64(&bcbcontext.use_wrap_key, BSL_SECPARAM_USE_KEY_WRAP, 1);
        }
        else
        {
            BSL_Crypto_AddRegistryKey("cek_wrap", cek_data.ptr, cek_data.len);
            BSL_SecParam_InitStr(&bcbcontext.param_test_key_id, BSL_SECPARAM_TYPE_KEY_ID, "cek_wrap");
            BSL_SecParam_InitInt64(&bcbcontext.use_wrap_key, BSL_SECPARAM_USE_KEY_WRAP, 0);
        }
        BSL_SecParam_InitInt64(&bcbcontext.param_scope_flags, RFC9173_BCB_SECPARAM_AADSCOPE,
                               RFC9173_BCB_AADSCOPEFLAGID_INC_NONE);
        BSL_SecParam_InitInt64(&bcbcontext.param_aes_variant, RFC9173_BCB_SECPARAM_AESVARIANT,
                               RFC9173_BCB_AES_VARIANT_A128GCM);

        BSL_SecOper_Init(&bcbcontext.sec_oper);
        BSL_SecOper_Populate(&bcbcontext.sec_oper, 2, 1, 2, BSL_SECBLOCKTYPE_BCB, BSL_SECROLE_SOURCE,
                             BSL_POLICYACTION_DROP_BLOCK);
        BSL_SecOper_AppendParam(&bcbcontext.sec_oper, &bcbcontext.param_aes_variant);
        BSL_SecOper_AppendParam(&bcbcontext.sec_oper, &bcbcontext.param_scope_flags);
        BSL_SecOper_AppendParam(&bcbcontext.sec_oper, &bcbcontext.param_test_key_id);
        BSL_SecOper_AppendParam(&bcbcontext.sec_oper, &bcbcontext.use_wrap_key);

        BSL_SecOutcome_Init(sec_outcome, &bcbcontext.sec_oper, BSL_SecOutcome_Sizeof());

        int bcb_exec_status =
            BSLX_BCB_Execute(&LocalTestCtx.bsl, &mock_bpa_ctr->bundle_ref, &bcbcontext.sec_oper, sec_outcome);
        TEST_ASSERT_EQUAL(BSL_SUCCESS, bcb_exec_status);

        TEST_ASSERT_EQUAL(1, BSL_SecOutcome_CountResults(sec_outcome));
        result = BSL_SecOutcome_GetResultAtIndex(sec_outcome, 0);

        TEST_ASSERT_EQUAL(RFC9173_BCB_RESULTID_AUTHTAG, result->result_id);
        TEST_ASSERT_EQUAL(1, result->target_block_num);
    }

    uint8_t logstr[500];
    if (wrap)
    {
        int got = 0;
        for (size_t i = 0; i < BSL_SecOutcome_CountParams(sec_outcome); i++)
        {
            const BSL_SecParam_t *sec_param = BSL_SecOutcome_GetParamAt(sec_outcome, i);
            if (sec_param->param_id == ((bib) ? RFC9173_BIB_PARAMID_WRAPPED_KEY : RFC9173_BCB_SECPARAM_WRAPPEDKEY))
            {
                got++;
                BSL_LOG_INFO("GOT WRAPPED KEY PARAM:");
                BSL_LOG_INFO(
                    "EXPECTED wrapped key: %s",
                    BSL_Log_DumpAsHexString(logstr, sizeof(logstr), wrapped_key_data.ptr, wrapped_key_data.len));
                BSL_LOG_INFO("ACTUAL wrapped key:   %s",
                             BSL_Log_DumpAsHexString(logstr, sizeof(logstr), sec_param->_bytes, sec_param->_bytelen));
                TEST_ASSERT_EQUAL(wrapped_key_data.len, sec_param->_bytelen);
                TEST_ASSERT_EQUAL_MEMORY(wrapped_key_data.ptr, sec_param->_bytes, wrapped_key_data.len);
            }
        }
        TEST_ASSERT_EQUAL(1, got);
    }

    BSL_LOG_INFO("EXPECTED result: %s",
                 BSL_Log_DumpAsHexString(logstr, sizeof(logstr), result_data.ptr, result_data.len));
    BSL_LOG_INFO("ACTUAL result:   %s",
                 BSL_Log_DumpAsHexString(logstr, sizeof(logstr), result->_bytes, result->_bytelen));
    TEST_ASSERT_EQUAL(result_data.len, result->_bytelen);
    TEST_ASSERT_EQUAL_MEMORY(result_data.ptr, result->_bytes, result_data.len);

    if (!bib)
    {
        string_t pt_str;
        string_init_set_str(pt_str, "15585e19f60c0978ede4105e529f9b0006c13c9804a9c75ab46d4ed46f1097cfa03967");
        BSL_Data_t pt_data;
        BSL_Data_Init(&pt_data);
        TEST_ASSERT_EQUAL(BSL_TestUtils_DecodeBase16(&pt_data, pt_str), 0);
        string_clear(pt_str);

        MockBPA_CanonicalBlock_t **target_ptr = MockBPA_BlockByNum_get(mock_bpa_ctr->bundle->blocks_num, 1);
        TEST_ASSERT_NOT_NULL(target_ptr);
        MockBPA_CanonicalBlock_t *target_block = *target_ptr;
        TEST_ASSERT_NOT_NULL(target_block);

        BSL_LOG_INFO("EXPECTED payload: %s", BSL_Log_DumpAsHexString(logstr, sizeof(logstr), pt_data.ptr, pt_data.len));
        BSL_LOG_INFO("ACTUAL payload:   %s",
                     BSL_Log_DumpAsHexString(logstr, sizeof(logstr), target_block->btsd, target_block->btsd_len));
        TEST_ASSERT_EQUAL_MEMORY(pt_data.ptr, target_block->btsd, pt_data.len);

        BSL_Data_Deinit(&pt_data);
    }

    BSL_SecOutcome_Deinit(sec_outcome);
    if (bib)
    {
        BSL_SecOper_Deinit(&bibcontext.sec_oper);
    }
    else
    {
        BSL_SecOper_Deinit(&bcbcontext.sec_oper);
    }

    BSL_Data_Deinit(&result_data);
    BSL_Data_Deinit(&cek_data);
    BSL_Data_Deinit(&kek_data);
    BSL_Data_Deinit(&wrapped_key_data);
    BSL_FREE(sec_outcome);
}

TEST_MATRIX([ true, false ])
void test_sec_accept_keyunwrap(bool bib)
{

    const char *bundle_bib = ("9F88070000820282010282028202018202820201820018281A000F424085010100005823526561647920746F"
                              "2067656E657261746520612033322D62797465207061796C6F6164850B020000585681010101820282020182"
                              "820107820300818182015840756D484ED764AEF06A35C53D6033B5311258EE21748B5FD53A53C8F55793D7A6"
                              "B021E0CEC4A5C461CA6C179649EC7BBFC1EA89639409B809086B820216EFCF7BFF");

    const char *bundle_bcb =
        ("9F88070000820282010282028202018202820201820018281A000F42408501010000582315585E19F60C0978EDE4105E529F9B0006C13"
         "C9804A9C75AB46D4ED46F1097CFA03967850C02010058508101020182028202018482014C5477656C7665313231323132820201820358"
         "1869C411276FECDDC4780DF42C8A2AF89296FABF34D7FAE7008204008181820150F6DC43C2EE046C7AE713F0531B2BCB48FF");

    string_t kek_str;
    string_init_set_str(kek_str, "000102030405060708090A0B0C0D0E0F");
    BSL_Data_t kek_data;
    BSL_Data_Init(&kek_data);
    TEST_ASSERT_EQUAL(BSL_TestUtils_DecodeBase16(&kek_data, kek_str), 0);
    string_clear(kek_str);

    string_t wrapped_key_str;
    string_init_set_str(wrapped_key_str, "1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5");
    BSL_Data_t wrapped_key_data;
    BSL_Data_Init(&wrapped_key_data);
    TEST_ASSERT_EQUAL(BSL_TestUtils_DecodeBase16(&wrapped_key_data, wrapped_key_str), 0);
    string_clear(wrapped_key_str);

    string_t iv_str;
    string_init_set_str(iv_str, "5477656c7665313231323132");
    BSL_Data_t iv_data;
    BSL_Data_Init(&iv_data);
    TEST_ASSERT_EQUAL(BSL_TestUtils_DecodeBase16(&iv_data, iv_str), 0);
    string_clear(iv_str);

    string_t result_data_str;
    if (bib)
    {
        // sign
        string_init_set_str(result_data_str, "756D484ED764AEF06A35C53D6033B5311258EE21748B5FD53A53C8F55793D7A6B021E0CEC"
                                             "4A5C461CA6C179649EC7BBFC1EA89639409B809086B820216EFCF7B");
    }
    else
    {
        // authtag
        string_init_set_str(result_data_str, "F6DC43C2EE046C7AE713F0531B2BCB48");
    }
    BSL_Data_t result_data;
    BSL_Data_Init(&result_data);
    TEST_ASSERT_EQUAL(BSL_TestUtils_DecodeBase16(&result_data, result_data_str), 0);
    string_clear(result_data_str);

    if (bib)
    {
        TEST_ASSERT_EQUAL(0, BSL_TestUtils_LoadBundleFromCBOR(&LocalTestCtx, bundle_bib));
    }
    else
    {
        TEST_ASSERT_EQUAL(0, BSL_TestUtils_LoadBundleFromCBOR(&LocalTestCtx, bundle_bcb));
    }
    mock_bpa_ctr_t *mock_bpa_ctr = &LocalTestCtx.mock_bpa_ctr;

    BSL_SecOutcome_t *sec_outcome = BSL_CALLOC(1, BSL_SecOutcome_Sizeof());
    BIBTestContext    bibcontext;
    BCBTestContext    bcbcontext;
    if (bib)
    {
        BSL_Crypto_AddRegistryKey("kek_wrap", kek_data.ptr, kek_data.len);
        BSL_SecParam_InitStr(&bibcontext.param_test_key, BSL_SECPARAM_TYPE_KEY_ID, "kek_wrap");
        BSL_SecParam_InitInt64(&bibcontext.use_key_wrap, BSL_SECPARAM_USE_KEY_WRAP, 1);
        BSL_SecParam_InitBytestr(&bibcontext.param_wrapped_key, RFC9173_BIB_PARAMID_WRAPPED_KEY, wrapped_key_data);
        BSL_SecParam_InitInt64(&bibcontext.param_scope_flags, RFC9173_BIB_PARAMID_INTEG_SCOPE_FLAG, 0);
        BSL_SecParam_InitInt64(&bibcontext.param_sha_variant, RFC9173_BIB_PARAMID_SHA_VARIANT, RFC9173_BIB_SHA_HMAC512);

        BSL_SecOper_Init(&bibcontext.sec_oper);
        BSL_SecOper_Populate(&bibcontext.sec_oper, 1, 1, 2, BSL_SECBLOCKTYPE_BIB, BSL_SECROLE_ACCEPTOR,
                             BSL_POLICYACTION_DROP_BLOCK);
        BSL_SecOper_AppendParam(&bibcontext.sec_oper, &bibcontext.param_sha_variant);
        BSL_SecOper_AppendParam(&bibcontext.sec_oper, &bibcontext.param_scope_flags);
        BSL_SecOper_AppendParam(&bibcontext.sec_oper, &bibcontext.param_test_key);
        BSL_SecOper_AppendParam(&bibcontext.sec_oper, &bibcontext.use_key_wrap);
        BSL_SecOper_AppendParam(&bibcontext.sec_oper, &bibcontext.param_wrapped_key);

        BSL_SecOutcome_Init(sec_outcome, &bibcontext.sec_oper, BSL_SecOutcome_Sizeof());

        int bib_exec_status =
            BSLX_BIB_Execute(&LocalTestCtx.bsl, &mock_bpa_ctr->bundle_ref, &bibcontext.sec_oper, sec_outcome);
        TEST_ASSERT_EQUAL(BSL_SUCCESS, bib_exec_status);
    }
    else
    {
        BSL_Crypto_SetRngGenerator(rfc3394_cek);

        BSL_Crypto_AddRegistryKey("kek_wrap", kek_data.ptr, kek_data.len);
        BSL_SecParam_InitStr(&bcbcontext.param_test_key_id, BSL_SECPARAM_TYPE_KEY_ID, "kek_wrap");
        BSL_SecParam_InitInt64(&bcbcontext.use_wrap_key, BSL_SECPARAM_USE_KEY_WRAP, 1);
        BSL_SecParam_InitBytestr(&bcbcontext.param_wrapped_key, RFC9173_BCB_SECPARAM_WRAPPEDKEY, wrapped_key_data);
        BSL_SecParam_InitBytestr(&bcbcontext.param_auth_tag, BSL_SECPARAM_TYPE_AUTH_TAG, result_data);
        BSL_SecParam_InitBytestr(&bcbcontext.param_init_vec, RFC9173_BCB_SECPARAM_IV, iv_data);
        BSL_SecParam_InitInt64(&bcbcontext.param_scope_flags, RFC9173_BCB_SECPARAM_AADSCOPE,
                               RFC9173_BCB_AADSCOPEFLAGID_INC_NONE);
        BSL_SecParam_InitInt64(&bcbcontext.param_aes_variant, RFC9173_BCB_SECPARAM_AESVARIANT,
                               RFC9173_BCB_AES_VARIANT_A128GCM);

        BSL_SecOper_Init(&bcbcontext.sec_oper);
        BSL_SecOper_Populate(&bcbcontext.sec_oper, 2, 1, 2, BSL_SECBLOCKTYPE_BCB, BSL_SECROLE_ACCEPTOR,
                             BSL_POLICYACTION_DROP_BLOCK);
        BSL_SecOper_AppendParam(&bcbcontext.sec_oper, &bcbcontext.param_aes_variant);
        BSL_SecOper_AppendParam(&bcbcontext.sec_oper, &bcbcontext.param_scope_flags);
        BSL_SecOper_AppendParam(&bcbcontext.sec_oper, &bcbcontext.param_test_key_id);
        BSL_SecOper_AppendParam(&bcbcontext.sec_oper, &bcbcontext.use_wrap_key);
        BSL_SecOper_AppendParam(&bcbcontext.sec_oper, &bcbcontext.param_wrapped_key);
        BSL_SecOper_AppendParam(&bcbcontext.sec_oper, &bcbcontext.param_auth_tag);
        BSL_SecOper_AppendParam(&bcbcontext.sec_oper, &bcbcontext.param_init_vec);

        BSL_SecOutcome_Init(sec_outcome, &bcbcontext.sec_oper, BSL_SecOutcome_Sizeof());

        int bcb_exec_status =
            BSLX_BCB_Execute(&LocalTestCtx.bsl, &mock_bpa_ctr->bundle_ref, &bcbcontext.sec_oper, sec_outcome);
        TEST_ASSERT_EQUAL(BSL_SUCCESS, bcb_exec_status);
    }

    uint8_t logstr[500];

    if (!bib)
    {
        string_t pt_str;
        string_init_set_str(pt_str, "526561647920746F2067656E657261746520612033322D62797465207061796C6F6164");
        BSL_Data_t pt_data;
        BSL_Data_Init(&pt_data);
        TEST_ASSERT_EQUAL(BSL_TestUtils_DecodeBase16(&pt_data, pt_str), 0);
        string_clear(pt_str);

        MockBPA_CanonicalBlock_t **target_ptr = MockBPA_BlockByNum_get(mock_bpa_ctr->bundle->blocks_num, 1);
        TEST_ASSERT_NOT_NULL(target_ptr);
        MockBPA_CanonicalBlock_t *target_block = *target_ptr;
        TEST_ASSERT_NOT_NULL(target_block);

        BSL_LOG_INFO("EXPECTED payload: %s", BSL_Log_DumpAsHexString(logstr, sizeof(logstr), pt_data.ptr, pt_data.len));
        BSL_LOG_INFO("ACTUAL payload:   %s",
                     BSL_Log_DumpAsHexString(logstr, sizeof(logstr), target_block->btsd, target_block->btsd_len));
        TEST_ASSERT_EQUAL_MEMORY(pt_data.ptr, target_block->btsd, pt_data.len);

        BSL_Data_Deinit(&pt_data);
    }

    BSL_SecOutcome_Deinit(sec_outcome);
    if (bib)
    {
        BSL_SecOper_Deinit(&bibcontext.sec_oper);
    }
    else
    {
        BSL_SecOper_Deinit(&bcbcontext.sec_oper);
    }

    BSL_Data_Deinit(&kek_data);
    BSL_Data_Deinit(&wrapped_key_data);
    BSL_Data_Deinit(&result_data);
    BSL_Data_Deinit(&iv_data);
    BSL_FREE(sec_outcome);
}

// /// @brief Purpose: Exercises BCB as a security acceptor
// void test_DefaultSecuritContext_RFC9173_A2_BCB_Acceptor(void) {}

// /// @brief Purpose: Exercises BCB as a security acceptor with cryptographic mismatch
// void test_DefaultSecuritContext_RFC9173_A2_BCB_Acceptor_Failure(void) {}
