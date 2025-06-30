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
#include <HostBPA.h>
#include <bsl_mock_bpa.h>
#include <bsl_mock_bpa_eid.h>
#include <Logging.h>
#include <unity.h>

// allow parameterized cases
#define TEST_CASE(...)

void suiteSetUp(void)
{
    BSL_openlog();
    assert(0 == bsl_mock_bpa_init());
}

int suiteTearDown(int failures)
{
    bsl_mock_bpa_deinit();
    BSL_closelog();
    return failures;
}

void test_BSL_HostLabel_DecodeFromText_unique(void)
{
    // label conversion is stateful on the BPA
    BSL_HostLabel_t label_hi;
    TEST_ASSERT_EQUAL_INT(0, BSL_HostLabel_Init(&label_hi));
    TEST_ASSERT_EQUAL_INT(0, BSL_HostLabel_DecodeFromText(&label_hi, "hi"));

    BSL_HostLabel_t label_hello;
    TEST_ASSERT_EQUAL_INT(0, BSL_HostLabel_Init(&label_hello));
    TEST_ASSERT_EQUAL_INT(0, BSL_HostLabel_DecodeFromText(&label_hello, "hello"));

    BSL_HostLabel_t label_hi2;
    TEST_ASSERT_EQUAL_INT(0, BSL_HostLabel_Init(&label_hi2));
    TEST_ASSERT_EQUAL_INT(0, BSL_HostLabel_DecodeFromText(&label_hi2, "hi"));

    // handles act as proxy to equality comparison
    TEST_ASSERT_NOT_EQUAL(label_hi.handle, label_hello.handle);
    TEST_ASSERT_EQUAL(label_hi.handle, label_hi2.handle);

    BSL_HostLabel_Deinit(&label_hello);
    BSL_HostLabel_Deinit(&label_hi2);
    BSL_HostLabel_Deinit(&label_hi);
}

// only empty is invalid
TEST_CASE(NULL)
TEST_CASE("")
void test_BSL_HostLabel_DecodeFromText_invalid(const char *text)
{
    BSL_HostLabel_t label;
    TEST_ASSERT_EQUAL_INT(0, BSL_HostLabel_Init(&label));
    TEST_ASSERT_NOT_EQUAL_INT(0, BSL_HostLabel_DecodeFromText(&label, text));
    BSL_HostLabel_Deinit(&label);
}

TEST_CASE("hi")
TEST_CASE("hello")
void test_BSL_HostLabel_DecodeFromText_loopback(const char *text)
{
    // label conversion is stateful on the BPA
    BSL_HostLabel_t label;
    TEST_ASSERT_EQUAL_INT(0, BSL_HostLabel_Init(&label));

    TEST_ASSERT_EQUAL_INT(0, BSL_HostLabel_DecodeFromText(&label, text));
    TEST_ASSERT_NOT_NULL(label.handle);

    string_t out;
    string_init(out);
    TEST_ASSERT_EQUAL_INT(0, BSL_HostLabel_EncodeToText(out, &label));
    TEST_ASSERT_EQUAL_STRING(text, string_get_cstr(out));

    string_clear(out);
    BSL_HostLabel_Deinit(&label);
}
