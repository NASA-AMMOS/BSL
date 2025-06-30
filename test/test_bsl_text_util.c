/*
 * Copyright (c) 2024 The Johns Hopkins University Applied Physics
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
 * Test the bsl_text_util.h interfaces.
 */
#include "bsl_mock_bpa.h"
#include <UtilHelpers.h>
#include <Logging.h>
#include <string.h>
#include <unity.h>

#define TEST_CASE(...)

void suiteSetUp(void)
{
    BSL_openlog();
    // avoid compiler helpfully eliding link of the bsl_mock_bpa
    assert(0 == bsl_mock_bpa_init());
}

int suiteTearDown(int failures)
{
    bsl_mock_bpa_deinit();
    BSL_closelog();
    return failures;
}

TEST_CASE("", NULL, 0)
TEST_CASE("00", "\x00", 1)
TEST_CASE("6869", "hi", 2)
void test_base16_decode_valid(const char *text, const char *expect, size_t expect_len)
{
    string_t in_text;
    string_init_set_str(in_text, text);
    BSL_Data_t out_data;
    BSL_Data_Init(&out_data);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, base16_decode(&out_data, in_text), "base16_decode() failed");

    if (expect)
    {
        BSL_Data_t expect_data;
        BSL_Data_InitView(&expect_data, expect_len, (BSL_DataPtr_t)expect);
        TEST_ASSERT_TRUE(out_data.owned);
        TEST_ASSERT_EQUAL_INT(expect_data.len, out_data.len);
        TEST_ASSERT_EQUAL_MEMORY(expect_data.ptr, out_data.ptr, out_data.len);
        BSL_Data_Deinit(&expect_data);
    }
    else
    {
        TEST_ASSERT_FALSE(out_data.owned);
        TEST_ASSERT_EQUAL_INT(0, out_data.len);
        TEST_ASSERT_NULL(out_data.ptr);
    }
    BSL_Data_Deinit(&out_data);
    string_clear(in_text);
}

TEST_CASE("1")
TEST_CASE("asd")
void test_base16_decode_invalid(const char *text)
{
    string_t in_text;
    string_init_set_str(in_text, text);
    BSL_Data_t out_data;
    BSL_Data_Init(&out_data);
    TEST_ASSERT_NOT_EQUAL_INT(0, base16_decode(&out_data, in_text));
    BSL_Data_Deinit(&out_data);
    string_clear(in_text);
}
