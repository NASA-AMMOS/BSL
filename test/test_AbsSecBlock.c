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

void suiteSetUp(void)
{
    BSL_openlog();
    TEST_ASSERT_EQUAL_INT(0, BSL_HostDescriptors_Set(MockBPA_Agent_Descriptors(NULL)));
}

int suiteTearDown(int failures)
{
    BSL_HostDescriptors_Clear();
    BSL_closelog();
    return failures;
}

void TestASBDecodeEncodeClosure(uint8_t *asb_cbor, size_t asb_cbor_bytelen, uint64_t sample_target_block_num)
{
    BSL_Data_t asb_cbor_data;
    BSL_Data_InitView(&asb_cbor_data, asb_cbor_bytelen, asb_cbor);
    BSL_AbsSecBlock_t *asb = BSL_CALLOC(1, BSL_AbsSecBlock_Sizeof());
    BSL_AbsSecBlock_InitEmpty(asb);

    const int decode_result = BSL_AbsSecBlock_DecodeFromCBOR(asb, &asb_cbor_data);
    TEST_ASSERT_EQUAL(BSL_SUCCESS, decode_result);

    // Confirm its in a valid state
    TEST_ASSERT_TRUE(BSL_AbsSecBlock_IsConsistent(asb));

    // Confirm it contains an given sample block num
    TEST_ASSERT_TRUE(BSL_AbsSecBlock_ContainsTarget(asb, sample_target_block_num));

    // As a sanity check, make sure it does NOT contain insane values
    TEST_ASSERT_FALSE(BSL_AbsSecBlock_ContainsTarget(asb, 999999));

    // Confirm that when we encode it, we get the original.
    BSL_Data_t encoded_cbor;
    BSL_Data_InitBuffer(&encoded_cbor, asb_cbor_bytelen);

    const ssize_t encode_result = BSL_AbsSecBlock_EncodeToCBOR(asb, &encoded_cbor);
    TEST_ASSERT_GREATER_THAN(BSL_SUCCESS, encode_result);

    // Make sure the lengths match and then make sure the bytes match
    const size_t nbytes = (size_t)encode_result;
    TEST_ASSERT_EQUAL_size_t(asb_cbor_bytelen, nbytes);
    TEST_ASSERT_EQUAL_MEMORY(asb_cbor, encoded_cbor.ptr, asb_cbor_bytelen);

    BSL_Data_Deinit(&encoded_cbor);
    BSL_AbsSecBlock_Deinit(asb);
    BSL_FREE(asb);
}

// See: https://www.rfc-editor.org/rfc/rfc9173.html#name-abstract-security-block-2
// RFC9173 AppendixA Example1
TEST_CASE("810101018202820201828201078203008181820158403bdc69b3a34a2b5d3a8554368bd1e808f606219d2a10a846eae3886ae4ecc83c"
          "4ee550fdfb1cc636b904e2f1a73e303dcd4b6ccece003e95e8164dcc89a156e1",
          1)
// RFC9173 AppendixA Example2
TEST_CASE("8101020182028202018482014c5477656c76653132313231328202018203581869c411276fecddc4780df42c8a2af89296fabf34d7fa"
          "e7008204008181820150efa4b5ac0108e3816c5606479801bc04",
          1)
// RFC9173 AppendixA Example3 BIB
TEST_CASE("8200020101820282030082820105820300828182015820cac6ce8e4c5dae57988b757e49a6dd1431dc04763541b2845098265bc81724"
          "1b81820158203ed614c0d97f49b3633627779aa18a338d212bf3c92b97759d9739cd50725596",
          0)
// RFC9173 AppendixA Example3 BCB
TEST_CASE("8101020182028202018382014c5477656c76653132313231328202018204008181820150efa4b5ac0108e3816c5606479801bc04", 1)
// RFC9173 AppendixA Example4 BIB
TEST_CASE("81010101820282020182820106820307818182015830f75fe4c37f76f046165855bd5ff72fbfd4e3a64b4695c40e2b787da005ae819f"
          "0a2e30a2e8b325527de8aefb52e73d71",
          1)
// RFC9173 AppendixA Example4 BCB
TEST_CASE("820301020182028202018382014c5477656c76653132313231328202038204078281820150220ffc45c8a901999ecc60991dd78b2981"
          "820150d2c51cb2481792dae8b21d848cede99b",
          3)
void test_AbsSecBlock_loopback(const char *hexdata, uint64_t sample_target_block_num)
{
    BSL_Data_t in_data;
    BSL_Data_Init(&in_data);
    {
        string_t in_text;
        string_init_set_str(in_text, hexdata);
        TEST_ASSERT_EQUAL_INT_MESSAGE(0, BSL_TestUtils_DecodeBase16(&in_data, in_text),
                                      "BSL_TestUtils_DecodeBase16() failed");
        string_clear(in_text);
    }

    TestASBDecodeEncodeClosure(in_data.ptr, in_data.len, sample_target_block_num);

    BSL_Data_Deinit(&in_data);
}

TEST_CASE("438ed6208eb1c1ffb94d952175167df0902902064a2983910c4fb2340790bf420a7d1921d5bf7c4721e02ab87a93ab1e0b75cf62e494"
          "8727c8b5dae46ed2af05439b88029191")
// fuzzed input
TEST_CASE("8200020101820282030082820158203ed614c0d97f49b3633727779aa18a338d212bf3c92b9aa18a338d212bf3c996")
void test_AbsSecBlock_Decode_failure(const char *hexdata)
{
    BSL_Data_t in_data;
    BSL_Data_Init(&in_data);
    {
        string_t in_text;
        string_init_set_str(in_text, hexdata);
        TEST_ASSERT_EQUAL_INT_MESSAGE(0, BSL_TestUtils_DecodeBase16(&in_data, in_text),
                                      "BSL_TestUtils_DecodeBase16() failed");
        string_clear(in_text);
    }

    BSL_AbsSecBlock_t *asb = BSL_CALLOC(1, BSL_AbsSecBlock_Sizeof());
    BSL_AbsSecBlock_InitEmpty(asb);

    const int decode_result = BSL_AbsSecBlock_DecodeFromCBOR(asb, &in_data);
    TEST_ASSERT_EQUAL_INT(BSL_ERR_DECODING, decode_result);

    BSL_AbsSecBlock_Deinit(asb);
    BSL_FREE(asb);

    BSL_Data_Deinit(&in_data);
}
