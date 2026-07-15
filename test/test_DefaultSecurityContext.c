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

static const char *ApxA2_AuthTag     = "efa4b5ac0108e3816c5606479801bc04";
static const char *ApxA2_Ciphertext  = "3a09c1e63fe23a7f66a59c7303837241e070b02619fc59c5214a22f08cd70795e73e9a";
static const char *ApxA2_PayloadData = "526561647920746f2067656e657261746520612033322d62797465207061796c6f6164";

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
 *  - Check the operation after the above function to confirm 1 result (the authentication code)
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

    /// Confirm running BIB as source executes without error
    int bib_exec_status = BSLX_BIB_Execute(&LocalTestCtx.bsl, &mock_bpa_ctr->bundle_ref, &bib_test_context.sec_oper);
    TEST_ASSERT_EQUAL(BSL_SUCCESS, bib_exec_status);

    /// Confirm it produced only 1 result
    TEST_ASSERT_EQUAL(1, BSL_SecOper_CountResults(&bib_test_context.sec_oper));
    const BSL_Variant_t *bib_result = BSL_SecOper_FindResult(&bib_test_context.sec_oper, RFC9173_BIB_RESULTID_HMAC);
    TEST_ASSERT_NOT_NULL(bib_result);

    /// Confirm the actual HMAC tag matches what is in the RFC
    BSL_Data_t mac_view;
    TEST_ASSERT_EQUAL(0, BSL_Variant_GetAsBytestr(bib_result, &mac_view));
    TEST_ASSERT_TRUE(BSL_TestUtils_IsB16StrEqualTo(RFC9173_TestVectors_AppendixA1.hex_hmac, mac_view));
    BSL_Data_Deinit(&mac_view);

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
 *  - Check the operation after the above function to confirm 1 result (the auth tag) is present
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

    // Execute BCB as source, confirm result is 0 (success)
    int bcb_exec_result = BSLX_BCB_Execute(&LocalTestCtx.bsl, &mock_bpa_ctr->bundle_ref, &bcb_test_context.sec_oper);
    TEST_ASSERT_EQUAL(BSL_SUCCESS, bcb_exec_result);

    // Confirm the output produces one result (the AES-GCM auth code)
    TEST_ASSERT_EQUAL(1, BSL_SecOper_CountResults(&bcb_test_context.sec_oper));
    const BSL_Variant_t *auth_tag_result = BSL_SecOper_FindResult(&bcb_test_context.sec_oper, RFC9173_BCB_RESULTID_AUTHTAG);
    TEST_ASSERT_NOT_NULL(auth_tag_result);

    {
        // Confirm expected vs actual auth tag byte length's match and they are equal
        BSL_Data_t view;
        TEST_ASSERT_EQUAL(0, BSL_Variant_GetAsBytestr(auth_tag_result, &view));
        TEST_ASSERT_TRUE(BSL_TestUtils_IsB16StrEqualTo(ApxA2_AuthTag, view));
        BSL_Data_Deinit(&view);
    }

    MockBPA_CanonicalBlock_t **target_ptr = MockBPA_BlockByNum_get(mock_bpa_ctr->bundle->blocks_num, 1);
    TEST_ASSERT_NOT_NULL(target_ptr);
    MockBPA_CanonicalBlock_t *target_block = *target_ptr;
    TEST_ASSERT_NOT_NULL(target_block);

    BSL_Data_t btsd_view = BSL_DATA_INIT_VIEW(target_block->btsd, target_block->btsd_len);
    TEST_ASSERT_TRUE(BSL_TestUtils_IsB16StrEqualTo(ApxA2_Ciphertext, btsd_view));
    BSL_Data_Deinit(&btsd_view);

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

    /// Confirm that BCB executes with SUCCESS
    int bcb_exec_result = BSL_ExecBCBVerifierAcceptor(BSLX_BCB_Execute, &LocalTestCtx.bsl, &mock_bpa_ctr->bundle_ref,
                                                      &bcb_test_context.sec_oper);
    TEST_ASSERT_EQUAL(BSL_SUCCESS, bcb_exec_result);

    /// Confirm that the target block is decrypted correctly.
    MockBPA_CanonicalBlock_t **target_ptr = MockBPA_BlockByNum_get(mock_bpa_ctr->bundle->blocks_num, 1);
    TEST_ASSERT_NOT_NULL(target_ptr);
    MockBPA_CanonicalBlock_t *target_block = *target_ptr;
    TEST_ASSERT_NOT_NULL(target_block);

    BSL_Data_t btsd_view = BSL_DATA_INIT_VIEW(target_block->btsd, target_block->btsd_len);
    TEST_ASSERT_TRUE(BSL_TestUtils_IsB16StrEqualTo(ApxA2_PayloadData, btsd_view));
    BSL_Data_Deinit(&btsd_view);

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
    BSL_Data_t cek_data;
    BSL_Data_Init(&cek_data);
    TEST_ASSERT_EQUAL(0, BSL_TestUtils_DecodeBase16_cstr(&cek_data, "00112233445566778899AABBCCDDEEFF"));

    BSL_Data_t kek_data;
    BSL_Data_Init(&kek_data);
    TEST_ASSERT_EQUAL(0, BSL_TestUtils_DecodeBase16_cstr(&kek_data, "000102030405060708090A0B0C0D0E0F"));

    const char *wrapped_key_hex = "1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5";

    const char *result_data_hex;
    if (bib)
    {
        // sign
        result_data_hex = "756D484ED764AEF06A35C53D6033B5311258EE21748B5FD53A53C8F55793D7A6B021E0CEC"
                          "4A5C461CA6C179649EC7BBFC1EA89639409B809086B820216EFCF7B";
    }
    else
    {
        // authtag
        result_data_hex = "F6DC43C2EE046C7AE713F0531B2BCB48";
    }

    TEST_ASSERT_EQUAL(
        0, BSL_TestUtils_LoadBundleFromCBOR(&LocalTestCtx, RFC9173_TestVectors_AppendixA1.hex_bundle_original));
    mock_bpa_ctr_t *mock_bpa_ctr = &LocalTestCtx.mock_bpa_ctr;

    const BSL_Variant_t *result;
    BIBTestContext         bibcontext;
    BCBTestContext         bcbcontext;
    BIBTestContext_Init(&bibcontext);
    BCBTestContext_Init(&bcbcontext);
    if (bib)
    {
        BSL_SecOper_Populate(&bibcontext.sec_oper, 1, 1, 2, BSL_SECBLOCKTYPE_BIB, BSL_SECROLE_SOURCE,
                             BSL_POLICYACTION_DROP_BLOCK);

        if (wrap)
        {
            TEST_ASSERT_EQUAL_INT(0, BSL_Crypto_AddRegistryKeyName("kek_wrap", kek_data.ptr, kek_data.len));
            BSL_Variant_SetTextstr(BSL_SecOper_AddOption(&bibcontext.sec_oper, BSLX_BIB_OPT_KEY_ID), "kek_wrap");
            BSL_Variant_SetInt64(BSL_SecOper_AddOption(&bibcontext.sec_oper, BSLX_BIB_OPT_USE_KEY_WRAP), 1);
            BSL_Crypto_SetRngGenerator(rfc3394_cek);
        }
        else
        {
            TEST_ASSERT_EQUAL_INT(0, BSL_Crypto_AddRegistryKeyName("cek_wrap", cek_data.ptr, cek_data.len));
            BSL_Variant_SetTextstr(BSL_SecOper_AddOption(&bibcontext.sec_oper, BSLX_BIB_OPT_KEY_ID), "cek_wrap");
            BSL_Variant_SetInt64(BSL_SecOper_AddOption(&bibcontext.sec_oper, BSLX_BIB_OPT_USE_KEY_WRAP), 0);
        }
        BSL_Variant_SetInt64(BSL_SecOper_AddOption(&bibcontext.sec_oper, BSLX_BIB_OPT_SCOPE), 0);
        BSL_Variant_SetInt64(BSL_SecOper_AddOption(&bibcontext.sec_oper, BSLX_BIB_OPT_SHA_VARIANT),
                             RFC9173_BIB_SHA_HMAC512);

        int bib_exec_status = BSLX_BIB_Execute(&LocalTestCtx.bsl, &mock_bpa_ctr->bundle_ref, &bibcontext.sec_oper);
        TEST_ASSERT_EQUAL(BSL_SUCCESS, bib_exec_status);

        TEST_ASSERT_EQUAL(1, BSL_SecOper_CountResults(&bibcontext.sec_oper));
        result = BSL_SecOper_FindResult(&bibcontext.sec_oper, RFC9173_BIB_RESULTID_HMAC);
        TEST_ASSERT_NOT_NULL(result);
    }
    else
    {
        BSL_Crypto_SetRngGenerator(rfc3394_cek);
        BSL_SecOper_Populate(&bcbcontext.sec_oper, 2, 1, 2, BSL_SECBLOCKTYPE_BCB, BSL_SECROLE_SOURCE,
                             BSL_POLICYACTION_DROP_BLOCK);
        if (wrap)
        {
            TEST_ASSERT_EQUAL_INT(0, BSL_Crypto_AddRegistryKeyName("kek_wrap", kek_data.ptr, kek_data.len));
            BSL_Variant_SetTextstr(BSL_SecOper_AddOption(&bcbcontext.sec_oper, BSLX_BCB_OPT_KEY_ID), "kek_wrap");
            BSL_Variant_SetInt64(BSL_SecOper_AddOption(&bcbcontext.sec_oper, BSLX_BCB_OPT_USE_KEY_WRAP), 1);
        }
        else
        {
            TEST_ASSERT_EQUAL_INT(0, BSL_Crypto_AddRegistryKeyName("cek_wrap", cek_data.ptr, cek_data.len));
            BSL_Variant_SetTextstr(BSL_SecOper_AddOption(&bcbcontext.sec_oper, BSLX_BCB_OPT_KEY_ID), "cek_wrap");
            BSL_Variant_SetInt64(BSL_SecOper_AddOption(&bcbcontext.sec_oper, BSLX_BCB_OPT_USE_KEY_WRAP), 0);
        }
        BSL_Variant_SetInt64(BSL_SecOper_AddOption(&bcbcontext.sec_oper, BSLX_BCB_OPT_SCOPE),
                             RFC9173_BCB_AADSCOPEFLAGID_INC_NONE);
        BSL_Variant_SetInt64(BSL_SecOper_AddOption(&bcbcontext.sec_oper, BSLX_BCB_OPT_AES_VARIANT),
                             RFC9173_BCB_AES_VARIANT_A128GCM);

        int bcb_exec_status = BSLX_BCB_Execute(&LocalTestCtx.bsl, &mock_bpa_ctr->bundle_ref, &bcbcontext.sec_oper);
        TEST_ASSERT_EQUAL(BSL_SUCCESS, bcb_exec_status);

        TEST_ASSERT_EQUAL(1, BSL_SecOper_CountResults(&bcbcontext.sec_oper));
        result = BSL_SecOper_FindResult(&bcbcontext.sec_oper, RFC9173_BCB_RESULTID_AUTHTAG);
        TEST_ASSERT_NOT_NULL(result);

        TEST_ASSERT_EQUAL(RFC9173_BCB_RESULTID_AUTHTAG, result->id);
    }

    if (wrap)
    {
        const BSL_Variant_t *sec_param;
        if (bib)
        {
            sec_param = BSL_SecOper_FindParam(&bibcontext.sec_oper, RFC9173_BIB_PARAMID_WRAPPED_KEY);
        }
        else
        {
            sec_param = BSL_SecOper_FindParam(&bcbcontext.sec_oper, RFC9173_BCB_SECPARAM_WRAPPEDKEY);
        }

        TEST_ASSERT_NOT_NULL(sec_param);
        BSL_Data_t view;
        TEST_ASSERT_EQUAL_INT(0, BSL_Variant_GetAsBytestr(sec_param, &view));
        TEST_ASSERT_TRUE(BSL_TestUtils_IsB16StrEqualTo(wrapped_key_hex, view));
        BSL_Data_Deinit(&view);
    }

    {
        BSL_Data_t view;
        TEST_ASSERT_EQUAL(0, BSL_Variant_GetAsBytestr(result, &view));
        TEST_ASSERT_TRUE(BSL_TestUtils_IsB16StrEqualTo(result_data_hex, view));
        BSL_Data_Deinit(&view);
    }

    if (!bib)
    {
        const char *pt_data_hex = "15585e19f60c0978ede4105e529f9b0006c13c9804a9c75ab46d4ed46f1097cfa03967";

        MockBPA_CanonicalBlock_t **target_ptr = MockBPA_BlockByNum_get(mock_bpa_ctr->bundle->blocks_num, 1);
        TEST_ASSERT_NOT_NULL(target_ptr);
        MockBPA_CanonicalBlock_t *target_block = *target_ptr;
        TEST_ASSERT_NOT_NULL(target_block);

        BSL_Data_t btsd_view = BSL_DATA_INIT_VIEW(target_block->btsd, target_block->btsd_len);
        TEST_ASSERT_TRUE(BSL_TestUtils_IsB16StrEqualTo(pt_data_hex, btsd_view));
        BSL_Data_Deinit(&btsd_view);
    }

    BSL_Data_Deinit(&cek_data);
    BSL_Data_Deinit(&kek_data);
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

    BSL_Data_t kek_data;
    BSL_Data_Init(&kek_data);
    TEST_ASSERT_EQUAL(BSL_TestUtils_DecodeBase16_cstr(&kek_data, "6162636465666768696a6b6c6d6e6f70"), 0);

    const char *result_data_str;
    if (bib)
    {
        // sign
        result_data_str = "756D484ED764AEF06A35C53D6033B5311258EE21748B5FD53A53C8F55793D7A6B021E0CEC"
                          "4A5C461CA6C179649EC7BBFC1EA89639409B809086B820216EFCF7B";
    }
    else
    {
        // authtag
        result_data_str = "F6DC43C2EE046C7AE713F0531B2BCB48";
    }
    BSL_Data_t result_data;
    BSL_Data_Init(&result_data);
    TEST_ASSERT_EQUAL(BSL_TestUtils_DecodeBase16_cstr(&result_data, result_data_str), 0);

    if (bib)
    {
        TEST_ASSERT_EQUAL(0, BSL_TestUtils_LoadBundleFromCBOR(&LocalTestCtx, bundle_bib));
    }
    else
    {
        TEST_ASSERT_EQUAL(0, BSL_TestUtils_LoadBundleFromCBOR(&LocalTestCtx, bundle_bcb));
    }
    mock_bpa_ctr_t *mock_bpa_ctr = &LocalTestCtx.mock_bpa_ctr;

    BIBTestContext bibcontext;
    BCBTestContext bcbcontext;
    BIBTestContext_Init(&bibcontext);
    BCBTestContext_Init(&bcbcontext);
    if (bib)
    {
        TEST_ASSERT_EQUAL_INT(0, BSL_Crypto_AddRegistryKeyName("kek_wrap", kek_data.ptr, kek_data.len));
        BSL_Variant_SetTextstr(&bibcontext.opt_test_key, BSLX_BIB_OPT_KEY_ID, "kek_wrap");
        BSL_Variant_SetInt64(&bibcontext.opt_use_key_wrap, BSLX_BIB_OPT_USE_KEY_WRAP, 1);
        BSL_Variant_SetInt64(&bibcontext.opt_scope_flags, BSLX_BIB_OPT_SCOPE, 0);
        BSL_Variant_SetInt64(&bibcontext.opt_sha_variant, BSLX_BIB_OPT_SHA_VARIANT, RFC9173_BIB_SHA_HMAC512);

        BSL_SecOper_Populate(&bibcontext.sec_oper, 1, 1, 2, BSL_SECBLOCKTYPE_BIB, BSL_SECROLE_ACCEPTOR,
                             BSL_POLICYACTION_DROP_BLOCK);
        BSL_SecOper_AddOption(&bibcontext.sec_oper, &bibcontext.opt_sha_variant);
        BSL_SecOper_AddOption(&bibcontext.sec_oper, &bibcontext.opt_scope_flags);
        BSL_SecOper_AddOption(&bibcontext.sec_oper, &bibcontext.opt_test_key);
        BSL_SecOper_AddOption(&bibcontext.sec_oper, &bibcontext.opt_use_key_wrap);

        int bib_exec_status = BSL_ExecBIBVerifierAcceptor(BSLX_BIB_Execute, &LocalTestCtx.bsl,
                                                          &mock_bpa_ctr->bundle_ref, &bibcontext.sec_oper);
        TEST_ASSERT_EQUAL(BSL_SUCCESS, bib_exec_status);
    }
    else
    {
        BSL_Crypto_SetRngGenerator(rfc3394_cek);

        TEST_ASSERT_EQUAL_INT(0, BSL_Crypto_AddRegistryKeyName("kek_wrap", kek_data.ptr, kek_data.len));
        BSL_Variant_SetTextstr(&bcbcontext.opt_test_key_id, BSLX_BCB_OPT_KEY_ID, "kek_wrap");
        BSL_Variant_SetInt64(&bcbcontext.opt_use_key_wrap, BSLX_BCB_OPT_USE_KEY_WRAP, 1);
        BSL_Variant_SetInt64(&bcbcontext.opt_scope_flags, BSLX_BCB_OPT_SCOPE, RFC9173_BCB_AADSCOPEFLAGID_INC_NONE);
        BSL_Variant_SetInt64(&bcbcontext.opt_aes_variant, BSLX_BCB_OPT_AES_VARIANT, RFC9173_BCB_AES_VARIANT_A128GCM);

        BSL_SecOper_Populate(&bcbcontext.sec_oper, 2, 1, 2, BSL_SECBLOCKTYPE_BCB, BSL_SECROLE_ACCEPTOR,
                             BSL_POLICYACTION_DROP_BLOCK);
        BSL_SecOper_AddOption(&bcbcontext.sec_oper, &bcbcontext.opt_aes_variant);
        BSL_SecOper_AddOption(&bcbcontext.sec_oper, &bcbcontext.opt_scope_flags);
        BSL_SecOper_AddOption(&bcbcontext.sec_oper, &bcbcontext.opt_test_key_id);
        BSL_SecOper_AddOption(&bcbcontext.sec_oper, &bcbcontext.opt_use_key_wrap);

        int bcb_exec_status = BSL_ExecBCBVerifierAcceptor(BSLX_BCB_Execute, &LocalTestCtx.bsl,
                                                          &mock_bpa_ctr->bundle_ref, &bcbcontext.sec_oper);
        TEST_ASSERT_EQUAL(BSL_SUCCESS, bcb_exec_status);
    }

    if (!bib)
    {
        const char *pt_data_hex = "526561647920746F2067656E657261746520612033322D62797465207061796C6F6164";

        MockBPA_CanonicalBlock_t **target_ptr = MockBPA_BlockByNum_get(mock_bpa_ctr->bundle->blocks_num, 1);
        TEST_ASSERT_NOT_NULL(target_ptr);
        MockBPA_CanonicalBlock_t *target_block = *target_ptr;
        TEST_ASSERT_NOT_NULL(target_block);

        BSL_Data_t btsd_view = BSL_DATA_INIT_VIEW(target_block->btsd, target_block->btsd_len);
        TEST_ASSERT_TRUE(BSL_TestUtils_IsB16StrEqualTo(pt_data_hex, btsd_view));
        BSL_Data_Deinit(&btsd_view);
    }

    BSL_Data_Deinit(&kek_data);
    BSL_Data_Deinit(&result_data);
    BIBTestContext_Deinit(&bibcontext);
    BCBTestContext_Deinit(&bcbcontext);
}

// /// @brief Purpose: Exercises BCB as a security acceptor
// void test_DefaultSecuritContext_RFC9173_A2_BCB_Acceptor(void) {}

// /// @brief Purpose: Exercises BCB as a security acceptor with cryptographic mismatch
// void test_DefaultSecuritContext_RFC9173_A2_BCB_Acceptor_Failure(void) {}
