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
 * @brief Specific low-level tests of the Default Security Context
 *
 * Notes:
 *  - These tests use constructs defined in the BSL to exercise each context.
 *  - It uses test inputs and vectors from RFC9173 Appendix A.
 *  - It does NOT use any of the "Plumbing" inside the BSL.
 *  - It only directly calls the interfaces exposed by the Default Security Context.
 */
#include <stdlib.h>
#include <stdio.h>
#include <unity.h>

#include <BPSecLib_Private.h>
#include <mock_bpa/MockBPA.h>
#include <CryptoInterface.h>

#include <backend/PublicInterfaceImpl.h>
#include <default_sc/DefaultSecContext.h>
#include <default_sc/DefaultSecContext_Private.h>

#include "DefaultScUtils.h"

static BSL_TestContext_t LocalTestCtx;

void suiteSetUp(void)
{
    TEST_ASSERT_EQUAL_INT(0, BSL_HostDescriptors_Set(MockBPA_Agent_Descriptors(NULL)));
    mock_bpa_LogOpen();
    mock_bpa_LogSetLeastSeverity(LOG_DEBUG);
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
    BSL_TestUtils_SetupDefaultSecurityContext(&LocalTestCtx.bsl);
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
        0, BSL_TestUtils_LoadBundleFromCBOR(&LocalTestCtx, RFC9173_TestVectors_AppendixA1.hex_bundle_original));
    mock_bpa_ctr_t *mock_bpa_ctr = &LocalTestCtx.mock_bpa_ctr;

    BIBTestContext bib_test_context;
    BIBTestContext_Init(&bib_test_context);
    BSL_TestUtils_InitBIB_AppendixA1(&bib_test_context, BSL_SECROLE_SOURCE, RFC9173_EXAMPLE_A1_KEY);

    BSL_SecOutcome_t *sec_outcome = BSL_calloc(1, BSL_SecOutcome_Sizeof());
    BSL_SecOutcome_Init(sec_outcome, &bib_test_context.sec_oper);

    /// Confirm running BIB as source executes without error
    int bib_exec_status =
        BSLX_BIB_Execute(&LocalTestCtx.bsl, &mock_bpa_ctr->bundle_ref, &bib_test_context.sec_oper, sec_outcome);
    TEST_ASSERT_EQUAL(BSL_SUCCESS, bib_exec_status);

    /// Confirm it produced only 1 result
    TEST_ASSERT_EQUAL(1, BSL_SecOutcome_CountResults(sec_outcome));
    const BSL_IdValPair_t *bib_result = BSL_SecOutcome_GetResultAtIndex(sec_outcome, 0);

    /// Confirm the context and result result is the right ID (Defined in RFC)
    TEST_ASSERT_EQUAL(RFC9173_BIB_RESULTID_HMAC, bib_result->id);

    /// Confirm the actual HMAC tag matches what is in the RFC
    BSL_Data_t mac_view;
    TEST_ASSERT_EQUAL(0, BSL_IdValPair_GetAsBytestr(bib_result, &mac_view));
    bool is_equal = BSL_TestUtils_IsB16StrEqualTo(RFC9173_TestVectors_AppendixA1.hex_hmac, mac_view);
    TEST_ASSERT_TRUE(is_equal);
    BSL_Data_Deinit(&mac_view);

    BSL_SecOutcome_Deinit(sec_outcome);
    BSL_free(sec_outcome);
    BIBTestContext_Deinit(&bib_test_context);
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
        0, BSL_TestUtils_LoadBundleFromCBOR(&LocalTestCtx, RFC9173_TestVectors_AppendixA1.hex_bundle_original));
    mock_bpa_ctr_t *mock_bpa_ctr = &LocalTestCtx.mock_bpa_ctr;

    BCBTestContext bcb_test_context;
    BCBTestContext_Init(&bcb_test_context);
    BSL_TestUtils_InitBCB_Appendix2(&bcb_test_context, BSL_SECROLE_SOURCE);

    BSL_SecOutcome_t *outcome = BSL_calloc(1, BSL_SecOutcome_Sizeof());
    BSL_SecOutcome_Init(outcome, &bcb_test_context.sec_oper);

    // Execute BCB as source, confirm result is 0 (success)
    int bcb_exec_result =
        BSLX_BCB_Execute(&LocalTestCtx.bsl, &mock_bpa_ctr->bundle_ref, &bcb_test_context.sec_oper, outcome);
    TEST_ASSERT_EQUAL(BSL_SUCCESS, bcb_exec_result);

    // Confirm the output produces one result (the AES-GCM auth code)
    TEST_ASSERT_EQUAL(1, BSL_SecOutcome_CountResults(outcome));
    const BSL_IdValPair_t *auth_tag_result = BSL_SecOutcome_GetResultAtIndex(outcome, 0);

    // Confirm that AUTHTAG result id is there
    TEST_ASSERT_EQUAL(RFC9173_BCB_RESULTID_AUTHTAG, auth_tag_result->id);

    {
        // Confirm expected vs actual auth tag byte length's match and they are equal
        BSL_Data_t view;
        TEST_ASSERT_EQUAL(0, BSL_IdValPair_GetAsBytestr(auth_tag_result, &view));
        TEST_ASSERT_EQUAL_size_t(sizeof(ApxA2_AuthTag), view.len);
        TEST_ASSERT_EQUAL_MEMORY(ApxA2_AuthTag, view.ptr, sizeof(ApxA2_AuthTag));
    }

    MockBPA_CanonicalBlock_t **target_ptr = MockBPA_BlockByNum_get(mock_bpa_ctr->bundle->blocks_num, 1);
    TEST_ASSERT_NOT_NULL(target_ptr);
    MockBPA_CanonicalBlock_t *target_block = *target_ptr;
    TEST_ASSERT_NOT_NULL(target_block);

    TEST_ASSERT_EQUAL_size_t(sizeof(ApxA2_Ciphertext), target_block->btsd_len);
    char logstr[500];
    BSL_LOG_INFO("EXPECTED payload: %s",
                 BSL_Log_DumpAsHexString(logstr, sizeof(logstr), ApxA2_Ciphertext, sizeof(ApxA2_Ciphertext)));
    BSL_LOG_INFO("ACTUAL payload:   %s",
                 BSL_Log_DumpAsHexString(logstr, sizeof(logstr), target_block->btsd, target_block->btsd_len));
    TEST_ASSERT_EQUAL_MEMORY(ApxA2_Ciphertext, target_block->btsd, sizeof(ApxA2_Ciphertext));

    BSL_SecOutcome_Deinit(outcome);
    BSL_free(outcome);
    BCBTestContext_Deinit(&bcb_test_context);
}

void test_RFC9173_AppendixA_Example2_BCB_Acceptor(void)
{
    TEST_ASSERT_EQUAL(0,
                      BSL_TestUtils_LoadBundleFromCBOR(&LocalTestCtx, RFC9173_TestVectors_AppendixA2.hex_bundle_bcb));
    mock_bpa_ctr_t *mock_bpa_ctr = &LocalTestCtx.mock_bpa_ctr;

    BCBTestContext bcb_test_context;
    BCBTestContext_Init(&bcb_test_context);
    BSL_TestUtils_InitBCB_Appendix2(&bcb_test_context, BSL_SECROLE_ACCEPTOR);

    BSL_SecOutcome_t *outcome = BSL_calloc(1, BSL_SecOutcome_Sizeof());
    BSL_SecOutcome_Init(outcome, &bcb_test_context.sec_oper);

    /// Confirm that BCB executes with SUCCESS
    int bcb_exec_result = BSL_ExecBCBVerifierAcceptor(BSLX_BCB_Execute, &LocalTestCtx.bsl, &mock_bpa_ctr->bundle_ref,
                                                      &bcb_test_context.sec_oper, outcome);
    TEST_ASSERT_EQUAL(BSL_SUCCESS, bcb_exec_result);

    /// Confirm that running as ACCEPTOR consumes result.
    size_t result_count = BSL_SecOutcome_CountResults(outcome);
    TEST_ASSERT_EQUAL(0, result_count);

    /// Confirm that the target block is decrypted correctly.
    MockBPA_CanonicalBlock_t **target_ptr = MockBPA_BlockByNum_get(mock_bpa_ctr->bundle->blocks_num, 1);
    TEST_ASSERT_NOT_NULL(target_ptr);
    MockBPA_CanonicalBlock_t *target_block = *target_ptr;
    TEST_ASSERT_NOT_NULL(target_block);

    TEST_ASSERT_EQUAL_size_t(sizeof(ApxA2_PayloadData), target_block->btsd_len);
    char logstr[500];
    BSL_LOG_INFO("EXPECTED payload: %s",
                 BSL_Log_DumpAsHexString(logstr, sizeof(logstr), ApxA2_PayloadData, sizeof(ApxA2_PayloadData)));
    BSL_LOG_INFO("ACTUAL payload:   %s",
                 BSL_Log_DumpAsHexString(logstr, sizeof(logstr), target_block->btsd, target_block->btsd_len));
    TEST_ASSERT_EQUAL_MEMORY(ApxA2_PayloadData, target_block->btsd, sizeof(ApxA2_PayloadData));

    BSL_SecOutcome_Deinit(outcome);
    BSL_free(outcome);
    BCBTestContext_Deinit(&bcb_test_context);
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
void test_sec_source_keywrap(bool wrap, bool bib)
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
        0, BSL_TestUtils_LoadBundleFromCBOR(&LocalTestCtx, RFC9173_TestVectors_AppendixA1.hex_bundle_original));
    mock_bpa_ctr_t *mock_bpa_ctr = &LocalTestCtx.mock_bpa_ctr;

    BSL_SecOutcome_t      *sec_outcome = BSL_calloc(1, BSL_SecOutcome_Sizeof());
    const BSL_IdValPair_t *result;
    BIBTestContext         bibcontext;
    BCBTestContext         bcbcontext;
    BIBTestContext_Init(&bibcontext);
    BCBTestContext_Init(&bcbcontext);
    if (bib)
    {
        if (wrap)
        {
            BSL_Data_t key_id = BSL_DATA_INIT_VIEW_CSTR("kek_wrap");
            BSL_Crypto_AddRegistryKey(&key_id, kek_data.ptr, kek_data.len);
            BSL_IdValPair_SetTextstr(&bibcontext.opt_test_key, BSLX_BIB_OPT_KEY_ID, "kek_wrap");
            BSL_IdValPair_SetInt64(&bibcontext.opt_use_key_wrap, BSLX_BIB_OPT_USE_KEY_WRAP, 1);
            BSL_Crypto_SetRngGenerator(rfc3394_cek);
        }
        else
        {
            BSL_Data_t key_id = BSL_DATA_INIT_VIEW_CSTR("cek_wrap");
            BSL_Crypto_AddRegistryKey(&key_id, cek_data.ptr, cek_data.len);
            BSL_IdValPair_SetTextstr(&bibcontext.opt_test_key, BSLX_BIB_OPT_KEY_ID, "cek_wrap");
            BSL_IdValPair_SetInt64(&bibcontext.opt_use_key_wrap, BSLX_BIB_OPT_USE_KEY_WRAP, 0);
        }
        BSL_IdValPair_SetInt64(&bibcontext.opt_scope_flags, BSLX_BIB_OPT_SCOPE, 0);
        BSL_IdValPair_SetInt64(&bibcontext.opt_sha_variant, BSLX_BIB_OPT_SHA_VARIANT, RFC9173_BIB_SHA_HMAC512);

        BSL_SecOper_Populate(&bibcontext.sec_oper, 1, 1, 2, BSL_SECBLOCKTYPE_BIB, BSL_SECROLE_SOURCE,
                             BSL_POLICYACTION_DROP_BLOCK);
        BSL_SecOper_AppendOption(&bibcontext.sec_oper, &bibcontext.opt_sha_variant);
        BSL_SecOper_AppendOption(&bibcontext.sec_oper, &bibcontext.opt_scope_flags);
        BSL_SecOper_AppendOption(&bibcontext.sec_oper, &bibcontext.opt_test_key);
        BSL_SecOper_AppendOption(&bibcontext.sec_oper, &bibcontext.opt_use_key_wrap);

        BSL_SecOutcome_Init(sec_outcome, &bibcontext.sec_oper);

        int bib_exec_status =
            BSLX_BIB_Execute(&LocalTestCtx.bsl, &mock_bpa_ctr->bundle_ref, &bibcontext.sec_oper, sec_outcome);
        TEST_ASSERT_EQUAL(BSL_SUCCESS, bib_exec_status);

        TEST_ASSERT_EQUAL(1, BSL_SecOutcome_CountResults(sec_outcome));
        result = BSL_SecOutcome_GetResultAtIndex(sec_outcome, 0);

        TEST_ASSERT_EQUAL(RFC9173_BIB_RESULTID_HMAC, result->id);
    }
    else
    {
        BSL_Crypto_SetRngGenerator(rfc3394_cek);
        if (wrap)
        {
            BSL_Crypto_AddRegistryKeyName("kek_wrap", kek_data.ptr, kek_data.len);
            BSL_IdValPair_SetTextstr(&bcbcontext.opt_test_key_id, BSLX_BCB_OPT_KEY_ID, "kek_wrap");
            BSL_IdValPair_SetInt64(&bcbcontext.opt_use_key_wrap, BSLX_BCB_OPT_USE_KEY_WRAP, 1);
        }
        else
        {
            BSL_Crypto_AddRegistryKeyName("cek_wrap", cek_data.ptr, cek_data.len);
            BSL_IdValPair_SetTextstr(&bcbcontext.opt_test_key_id, BSLX_BCB_OPT_KEY_ID, "cek_wrap");
            BSL_IdValPair_SetInt64(&bcbcontext.opt_use_key_wrap, BSLX_BCB_OPT_USE_KEY_WRAP, 0);
        }
        BSL_IdValPair_SetInt64(&bcbcontext.opt_scope_flags, BSLX_BCB_OPT_SCOPE, RFC9173_BCB_AADSCOPEFLAGID_INC_NONE);
        BSL_IdValPair_SetInt64(&bcbcontext.opt_aes_variant, BSLX_BCB_OPT_AES_VARIANT, RFC9173_BCB_AES_VARIANT_A128GCM);

        BSL_SecOper_Populate(&bcbcontext.sec_oper, 2, 1, 2, BSL_SECBLOCKTYPE_BCB, BSL_SECROLE_SOURCE,
                             BSL_POLICYACTION_DROP_BLOCK);
        BSL_SecOper_AppendOption(&bcbcontext.sec_oper, &bcbcontext.opt_aes_variant);
        BSL_SecOper_AppendOption(&bcbcontext.sec_oper, &bcbcontext.opt_scope_flags);
        BSL_SecOper_AppendOption(&bcbcontext.sec_oper, &bcbcontext.opt_test_key_id);
        BSL_SecOper_AppendOption(&bcbcontext.sec_oper, &bcbcontext.opt_use_key_wrap);

        BSL_SecOutcome_Init(sec_outcome, &bcbcontext.sec_oper);

        int bcb_exec_status =
            BSLX_BCB_Execute(&LocalTestCtx.bsl, &mock_bpa_ctr->bundle_ref, &bcbcontext.sec_oper, sec_outcome);
        TEST_ASSERT_EQUAL(BSL_SUCCESS, bcb_exec_status);

        TEST_ASSERT_EQUAL(1, BSL_SecOutcome_CountResults(sec_outcome));
        result = BSL_SecOutcome_GetResultAtIndex(sec_outcome, 0);

        TEST_ASSERT_EQUAL(RFC9173_BCB_RESULTID_AUTHTAG, result->id);
    }

    char logstr[500];
    if (wrap)
    {
        int got = 0;
        for (size_t i = 0; i < BSL_SecOutcome_CountParams(sec_outcome); i++)
        {
            const BSL_IdValPair_t *sec_param = BSL_SecOutcome_GetParamAt(sec_outcome, i);
            if (sec_param->id == ((bib) ? RFC9173_BIB_PARAMID_WRAPPED_KEY : RFC9173_BCB_SECPARAM_WRAPPEDKEY))
            {
                got++;
                BSL_LOG_INFO("GOT WRAPPED KEY PARAM:");
                BSL_LOG_INFO(
                    "EXPECTED wrapped key: %s",
                    BSL_Log_DumpAsHexString(logstr, sizeof(logstr), wrapped_key_data.ptr, wrapped_key_data.len));
                BSL_Data_t view;
                TEST_ASSERT_EQUAL_INT(0, BSL_IdValPair_GetAsBytestr(sec_param, &view));
                BSL_LOG_INFO("ACTUAL wrapped key:   %s",
                             BSL_Log_DumpAsHexString(logstr, sizeof(logstr), view.ptr, view.len));
                TEST_ASSERT_EQUAL(wrapped_key_data.len, view.len);
                TEST_ASSERT_EQUAL_MEMORY(wrapped_key_data.ptr, view.ptr, wrapped_key_data.len);
                BSL_Data_Deinit(&view);
            }
        }
        TEST_ASSERT_EQUAL(1, got);
    }

    {
        BSL_LOG_INFO("EXPECTED result: %s",
                     BSL_Log_DumpAsHexString(logstr, sizeof(logstr), result_data.ptr, result_data.len));

        BSL_Data_t view;
        TEST_ASSERT_EQUAL(0, BSL_IdValPair_GetAsBytestr(result, &view));
        BSL_LOG_INFO("ACTUAL result:   %s", BSL_Log_DumpAsHexString(logstr, sizeof(logstr), view.ptr, view.len));
        TEST_ASSERT_EQUAL_size_t(result_data.len, view.len);
        TEST_ASSERT_EQUAL_MEMORY(result_data.ptr, view.ptr, result_data.len);
    }

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

    BSL_Data_Deinit(&result_data);
    BSL_Data_Deinit(&cek_data);
    BSL_Data_Deinit(&kek_data);
    BSL_Data_Deinit(&wrapped_key_data);
    BSL_free(sec_outcome);
    BIBTestContext_Deinit(&bibcontext);
    BCBTestContext_Deinit(&bcbcontext);
}

TEST_MATRIX([ true, false ])
void test_sec_accept_keyunwrap(bool bib)
{
    // From RFC 9173 Appendix A.1.4 with the addition of a key wrap parameter with KEK from Appendix A.2.4
    const char *bundle_bib = "9F88070000820282010282028202018202820201820018281A000F4240850B0200"
                             "00587281010101820282020183820107820258188D1B3284D416049DA2E0F27135F2C"
                             "2B84345DEE9EC51E76E8203008181820158403BDC69B3A34A2B5D3A8554368BD1E808"
                             "F606219D2A10A846EAE3886AE4ECC83C4EE550FDFB1CC636B904E2F1A73E303DCD4B6"
                             "CCECE003E95E8164DCC89A156E185010100005823526561647920746F2067656E6572"
                             "61746520612033322D62797465207061796C6F6164FF";

    // From RFC 9173 Appendix A.2.4
    const char *bundle_bcb = "9f88070000820282010282028202018202820201820018281a000f4240850c0201"
                             "0058508101020182028202018482014c5477656c7665313231323132820201820358"
                             "1869c411276fecddc4780df42c8a2af89296fabf34d7fae7008204008181820150ef"
                             "a4b5ac0108e3816c5606479801bc04850101000058233a09c1e63fe23a7f66a59c73"
                             "03837241e070b02619fc59c5214a22f08cd70795e73e9aff";

    string_t kek_str;
    string_init_set_str(kek_str, "6162636465666768696a6b6c6d6e6f70");
    BSL_Data_t kek_data;
    BSL_Data_Init(&kek_data);
    TEST_ASSERT_EQUAL(BSL_TestUtils_DecodeBase16(&kek_data, kek_str), 0);
    string_clear(kek_str);

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

    BSL_SecOutcome_t *sec_outcome = BSL_calloc(1, BSL_SecOutcome_Sizeof());
    BIBTestContext    bibcontext;
    BCBTestContext    bcbcontext;
    BIBTestContext_Init(&bibcontext);
    BCBTestContext_Init(&bcbcontext);
    if (bib)
    {
        BSL_Crypto_AddRegistryKeyName("kek_wrap", kek_data.ptr, kek_data.len);
        BSL_IdValPair_SetTextstr(&bibcontext.opt_test_key, BSLX_BIB_OPT_KEY_ID, "kek_wrap");
        BSL_IdValPair_SetInt64(&bibcontext.opt_use_key_wrap, BSLX_BIB_OPT_USE_KEY_WRAP, 1);
        BSL_IdValPair_SetInt64(&bibcontext.opt_scope_flags, BSLX_BIB_OPT_SCOPE, 0);
        BSL_IdValPair_SetInt64(&bibcontext.opt_sha_variant, BSLX_BIB_OPT_SHA_VARIANT, RFC9173_BIB_SHA_HMAC512);

        BSL_SecOper_Populate(&bibcontext.sec_oper, 1, 1, 2, BSL_SECBLOCKTYPE_BIB, BSL_SECROLE_ACCEPTOR,
                             BSL_POLICYACTION_DROP_BLOCK);
        BSL_SecOper_AppendOption(&bibcontext.sec_oper, &bibcontext.opt_sha_variant);
        BSL_SecOper_AppendOption(&bibcontext.sec_oper, &bibcontext.opt_scope_flags);
        BSL_SecOper_AppendOption(&bibcontext.sec_oper, &bibcontext.opt_test_key);
        BSL_SecOper_AppendOption(&bibcontext.sec_oper, &bibcontext.opt_use_key_wrap);

        BSL_SecOutcome_Init(sec_outcome, &bibcontext.sec_oper);

        int bib_exec_status = BSL_ExecBIBVerifierAcceptor(BSLX_BIB_Execute, &LocalTestCtx.bsl,
                                                          &mock_bpa_ctr->bundle_ref, &bibcontext.sec_oper, sec_outcome);
        TEST_ASSERT_EQUAL(BSL_SUCCESS, bib_exec_status);
    }
    else
    {
        BSL_Crypto_SetRngGenerator(rfc3394_cek);

        BSL_Crypto_AddRegistryKeyName("kek_wrap", kek_data.ptr, kek_data.len);
        BSL_IdValPair_SetTextstr(&bcbcontext.opt_test_key_id, BSLX_BCB_OPT_KEY_ID, "kek_wrap");
        BSL_IdValPair_SetInt64(&bcbcontext.opt_use_key_wrap, BSLX_BCB_OPT_USE_KEY_WRAP, 1);
        BSL_IdValPair_SetInt64(&bcbcontext.opt_scope_flags, BSLX_BCB_OPT_SCOPE, RFC9173_BCB_AADSCOPEFLAGID_INC_NONE);
        BSL_IdValPair_SetInt64(&bcbcontext.opt_aes_variant, BSLX_BCB_OPT_AES_VARIANT, RFC9173_BCB_AES_VARIANT_A128GCM);

        BSL_SecOper_Populate(&bcbcontext.sec_oper, 2, 1, 2, BSL_SECBLOCKTYPE_BCB, BSL_SECROLE_ACCEPTOR,
                             BSL_POLICYACTION_DROP_BLOCK);
        BSL_SecOper_AppendOption(&bcbcontext.sec_oper, &bcbcontext.opt_aes_variant);
        BSL_SecOper_AppendOption(&bcbcontext.sec_oper, &bcbcontext.opt_scope_flags);
        BSL_SecOper_AppendOption(&bcbcontext.sec_oper, &bcbcontext.opt_test_key_id);
        BSL_SecOper_AppendOption(&bcbcontext.sec_oper, &bcbcontext.opt_use_key_wrap);

        BSL_SecOutcome_Init(sec_outcome, &bcbcontext.sec_oper);

        int bcb_exec_status = BSL_ExecBCBVerifierAcceptor(BSLX_BCB_Execute, &LocalTestCtx.bsl,
                                                          &mock_bpa_ctr->bundle_ref, &bcbcontext.sec_oper, sec_outcome);
        TEST_ASSERT_EQUAL(BSL_SUCCESS, bcb_exec_status);
    }

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

        {
            char logstr[2 * pt_data.len + 1];
            BSL_LOG_INFO("EXPECTED payload: %s",
                         BSL_Log_DumpAsHexString(logstr, sizeof(logstr), pt_data.ptr, pt_data.len));
        }
        {
            char logstr[2 * target_block->btsd_len + 1];
            BSL_LOG_INFO("ACTUAL payload:   %s",
                         BSL_Log_DumpAsHexString(logstr, sizeof(logstr), target_block->btsd, target_block->btsd_len));
        }
        TEST_ASSERT_EQUAL_MEMORY(pt_data.ptr, target_block->btsd, pt_data.len);

        BSL_Data_Deinit(&pt_data);
    }

    BSL_SecOutcome_Deinit(sec_outcome);
    BSL_Data_Deinit(&kek_data);
    BSL_Data_Deinit(&result_data);
    BSL_free(sec_outcome);
    BIBTestContext_Deinit(&bibcontext);
    BCBTestContext_Deinit(&bcbcontext);
}

// /// @brief Purpose: Exercises BCB as a security acceptor
// void test_DefaultSecuritContext_RFC9173_A2_BCB_Acceptor(void) {}

// /// @brief Purpose: Exercises BCB as a security acceptor with cryptographic mismatch
// void test_DefaultSecuritContext_RFC9173_A2_BCB_Acceptor_Failure(void) {}
