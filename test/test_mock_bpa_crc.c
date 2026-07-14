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
#include <inttypes.h>
#include <unity.h>
#include "TestUtils.h"
#include <mock_bpa/crc.h>
#include <mock_bpa/log.h>

void suiteSetUp(void)
{
    mock_bpa_LogOpen();
}

int suiteTearDown(int failures)
{
    mock_bpa_LogClose();
    return failures;
}

TEST_CASE("", "0000")
TEST_CASE("313233343536373839", "906E") // from https://crcmod.sourceforge.net/crcmod.predefined.html
void test_mock_bpa_crc_crc16(const char *hexdata, const char *hexexpect)
{
    BSL_Data_t in_data;
    BSL_Data_Init(&in_data);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, BSL_TestUtils_DecodeBase16_cstr(&in_data, hexdata),
                                  "BSL_TestUtils_DecodeBase16_cstr() failed");

    BSL_Data_t expect_data;
    BSL_Data_Init(&expect_data);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, BSL_TestUtils_DecodeBase16_cstr(&expect_data, hexexpect),
                                  "BSL_TestUtils_DecodeBase16_cstr() failed");

    UsefulBufC buf = { .ptr = in_data.ptr, .len = in_data.len };

    uint8_t got[MOCK_BPA_CRC_CRC16_LEN];
    mock_bpa_crc_oneshot(got, buf, BSL_BUNDLECRCTYPE_16);

    TEST_ASSERT_EQUAL_size_t(MOCK_BPA_CRC_CRC16_LEN, expect_data.len);
    TEST_ASSERT_EQUAL_MEMORY(got, expect_data.ptr, expect_data.len);

    BSL_Data_Deinit(&expect_data);
    BSL_Data_Deinit(&in_data);
}

TEST_CASE("", "00000000")
TEST_CASE("313233343536373839", "E3069283") // from https://crcmod.sourceforge.net/crcmod.predefined.html
void test_mock_bpa_crc_crc32c(const char *hexdata, const char *hexexpect)
{
    BSL_Data_t in_data;
    BSL_Data_Init(&in_data);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, BSL_TestUtils_DecodeBase16_cstr(&in_data, hexdata),
                                  "BSL_TestUtils_DecodeBase16_cstr() failed");

    BSL_Data_t expect_data;
    BSL_Data_Init(&expect_data);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, BSL_TestUtils_DecodeBase16_cstr(&expect_data, hexexpect),
                                  "BSL_TestUtils_DecodeBase16_cstr() failed");

    UsefulBufC buf = { .ptr = in_data.ptr, .len = in_data.len };

    uint8_t got[MOCK_BPA_CRC_CRC32C_LEN];
    mock_bpa_crc_oneshot(got, buf, BSL_BUNDLECRCTYPE_32);

    TEST_ASSERT_EQUAL_size_t(MOCK_BPA_CRC_CRC32C_LEN, expect_data.len);
    TEST_ASSERT_EQUAL_MEMORY(got, expect_data.ptr, expect_data.len);

    BSL_Data_Deinit(&expect_data);
    BSL_Data_Deinit(&in_data);
}
