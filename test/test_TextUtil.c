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
 * Test the TextUtil.h interfaces.
 */
#include <bsl/front/TextUtil.h>
#include <unity.h>
#include <string.h>

#define TEST_CASE(...)

TEST_CASE("", 0, false, "")
TEST_CASE("hi", 2, false, "6869")
void test_BSL_TextUtil_Base16_Encode(const char *data, size_t data_len, bool uppercase, const char *expect)
{
    BSL_Data_t in_data = BSL_DATA_INIT_VIEW(data, data_len);

    BSL_Data_t out_text;
    BSL_Data_Init(&out_text);
    TEST_ASSERT_EQUAL_INT(0, BSL_TextUtil_Base16_Encode(&out_text, &in_data, uppercase));

    TEST_ASSERT_EQUAL_STRING(expect, out_text.ptr);
    BSL_Data_Deinit(&out_text);
}

TEST_CASE("", NULL, 0)
TEST_CASE("00", "\x00", 1)
TEST_CASE("6869", "hi", 2)
void test_BSL_TextUtil_Base16_Decode_valid(const char *text, const char *expect, size_t expect_len)
{
    BSL_Data_t out_data;
    BSL_Data_Init(&out_data);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, BSL_TextUtil_Base16_Decode(&out_data, text, strlen(text)),
                                  "BSL_TextUtil_Base16_Decode() failed");

    TEST_ASSERT_EQUAL_INT(expect_len, out_data.len);
    if (expect)
    {
        TEST_ASSERT_EQUAL_MEMORY(expect, out_data.ptr, expect_len);
    }

    BSL_Data_Deinit(&out_data);
}

TEST_CASE("1")
TEST_CASE("asd")
void test_BSL_TextUtil_Base16_Decode_invalid(const char *text)
{
    BSL_Data_t out_data;
    BSL_Data_Init(&out_data);
    TEST_ASSERT_NOT_EQUAL_INT(0, BSL_TextUtil_Base16_Decode(&out_data, text, strlen(text)));
    BSL_Data_Deinit(&out_data);
}

// vectors from Section 10 of RFC 4648
TEST_CASE("", 0, false, true, "")
TEST_CASE("f", 1, false, true, "Zg==")
TEST_CASE("fo", 2, false, true, "Zm8=")
TEST_CASE("foo", 3, false, true, "Zm9v")
TEST_CASE("foob", 4, false, true, "Zm9vYg==")
TEST_CASE("fooba", 5, false, true, "Zm9vYmE=")
TEST_CASE("foobar", 6, false, true, "Zm9vYmFy")
// example from Section 9 of RFC 4648
TEST_CASE("\x14\xfb\x9c\x03\xd9\x7e", 6, false, true, "FPucA9l+")
// random cases to use last two characters of alphabet
TEST_CASE("\xc1\x04\xc4\xcf\xb7\x77\x0f\xf0\xbe\xba\xa2\xe9\x5f\xbc\x2c\x18", 16, false, true,
          "wQTEz7d3D/C+uqLpX7wsGA==")
TEST_CASE("\xc1\x04\xc4\xcf\xb7\x77\x0f\xf0\xbe\xba\xa2\xe9\x5f\xbc\x2c\x18", 16, false, false,
          "wQTEz7d3D/C+uqLpX7wsGA")
TEST_CASE("\xc1\x04\xc4\xcf\xb7\x77\x0f\xf0\xbe\xba\xa2\xe9\x5f\xbc\x2c\x18", 16, true, true,
          "wQTEz7d3D_C-uqLpX7wsGA==")
TEST_CASE("\xc1\x04\xc4\xcf\xb7\x77\x0f\xf0\xbe\xba\xa2\xe9\x5f\xbc\x2c\x18", 16, true, false, "wQTEz7d3D_C-uqLpX7wsGA")
void test_BSL_TextUtil_Base64_Encode(const char *data, size_t data_len, bool useurl, bool usepad, const char *expect)
{
    BSL_Data_t in_data = BSL_DATA_INIT_VIEW(data, data_len);

    BSL_Data_t out_text;
    BSL_Data_Init(&out_text);
    TEST_ASSERT_EQUAL_INT(0, BSL_TextUtil_Base64_Encode(&out_text, &in_data, useurl, usepad));

    TEST_ASSERT_EQUAL_STRING(expect, out_text.ptr);
    BSL_Data_Deinit(&out_text);
}

// vectors from Section 10 of RFC 4648
TEST_CASE("", NULL, 0)
TEST_CASE("Zg==", "f", 1)
TEST_CASE("Zm8=", "fo", 2)
TEST_CASE("Zm9v", "foo", 3)
TEST_CASE("Zm9vYg==", "foob", 4)
TEST_CASE("Zm9vYmE=", "fooba", 5)
TEST_CASE("Zm9vYmFy", "foobar", 6)
// removed padding
TEST_CASE("Zg", "f", 1)
TEST_CASE("Zm8", "fo", 2)
// excess padding is okay
TEST_CASE("Zm9vYmFy====", "foobar", 6)
TEST_CASE("====", NULL, 0)
// random cases to use last two characters of alphabet
TEST_CASE("wQTEz7d3D/C+uqLpX7wsGA==", "\xc1\x04\xc4\xcf\xb7\x77\x0f\xf0\xbe\xba\xa2\xe9\x5f\xbc\x2c\x18", 16)
TEST_CASE("wQTEz7d3D/C+uqLpX7wsGA", "\xc1\x04\xc4\xcf\xb7\x77\x0f\xf0\xbe\xba\xa2\xe9\x5f\xbc\x2c\x18", 16)
TEST_CASE("wQTEz7d3D_C-uqLpX7wsGA==", "\xc1\x04\xc4\xcf\xb7\x77\x0f\xf0\xbe\xba\xa2\xe9\x5f\xbc\x2c\x18", 16)
TEST_CASE("wQTEz7d3D_C-uqLpX7wsGA", "\xc1\x04\xc4\xcf\xb7\x77\x0f\xf0\xbe\xba\xa2\xe9\x5f\xbc\x2c\x18", 16)
void test_BSL_TextUtil_Base64_Decode_valid(const char *text, const char *expect, size_t expect_len)
{
    BSL_Data_t out_data;
    BSL_Data_Init(&out_data);
    TEST_ASSERT_EQUAL_INT(0, BSL_TextUtil_Base64_Decode(&out_data, text, strlen(text)));

    TEST_ASSERT_EQUAL_INT(expect_len, out_data.len);
    if (expect)
    {
        TEST_ASSERT_EQUAL_MEMORY(expect, out_data.ptr, expect_len);
    }
    BSL_Data_Deinit(&out_data);
}

TEST_CASE(".")
TEST_CASE("A.")
TEST_CASE("AB.")
TEST_CASE("ABC.")
void test_BSL_TextUtil_Base64_Decode_invalid(const char *text)
{
    BSL_Data_t out_data;
    BSL_Data_Init(&out_data);
    TEST_ASSERT_NOT_EQUAL_INT(0, BSL_TextUtil_Base64_Decode(&out_data, text, strlen(text)));
    BSL_Data_Deinit(&out_data);
}
