/*
 * Copyright (c) 2011-2025 The Johns Hopkins University Applied Physics
 * Laboratory LLC.
 *
 * This file is part of the Delay-Tolerant Networking Management
 * Architecture (DTNMA) Tools package.
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
 */
/** @file
 * Test the text_util.h interfaces.
 */
#include <mock_bpa/text_util.h>
#include <unity.h>
#include <string.h>

#define TEST_CASE(...)

TEST_CASE("", "", "")
TEST_CASE("hi", "", "hi")
TEST_CASE("h i", "", "h%20i")
TEST_CASE("h$i", "", "h%24i")
TEST_CASE("h$i", "$", "h$i")
void test_mock_bpa_uri_percent_encode_valid(const char *text, const char *safe, const char *expect)
{
    m_string_t in_text;
    m_string_init_set_cstr(in_text, text);

    m_string_t out_text;
    m_string_init(out_text);
    TEST_ASSERT_EQUAL_INT(0, mock_bpa_uri_percent_encode(out_text, in_text, safe));

    TEST_ASSERT_EQUAL_STRING(expect, m_string_get_cstr(out_text));

    m_string_clear(out_text);
    m_string_clear(in_text);
}

TEST_CASE("", "")
TEST_CASE("hi", "hi")
TEST_CASE("h%20i", "h i")
TEST_CASE("h%7ei", "h~i")
void test_mock_bpa_uri_percent_decode_valid(const char *text, const char *expect)
{
    m_string_t in_text;
    m_string_init_set_cstr(in_text, text);

    m_string_t out_text;
    m_string_init(out_text);
    TEST_ASSERT_EQUAL_INT(0, mock_bpa_uri_percent_decode(out_text, in_text));

    TEST_ASSERT_EQUAL_STRING(expect, m_string_get_cstr(out_text));

    m_string_clear(out_text);
    m_string_clear(in_text);
}

TEST_CASE("%")
TEST_CASE("%1")
void test_mock_bpa_uri_percent_decode_invalid(const char *text)
{
    m_string_t in_text;
    m_string_init_set_cstr(in_text, text);

    m_string_t out_text;
    m_string_init(out_text);
    TEST_ASSERT_NOT_EQUAL_INT(0, mock_bpa_uri_percent_decode(out_text, in_text));
    m_string_clear(out_text);
    m_string_clear(in_text);
}

TEST_CASE("", '"', "")
TEST_CASE("hi", '"', "hi")
TEST_CASE("h\"i", '"', "h\\\"i")
TEST_CASE("h'i", '"', "h'i")
TEST_CASE("h \b\f\n\r\ti", '\"', "h \\b\\f\\n\\r\\ti")
TEST_CASE("hi\u1234", '"', "hi\\u1234")
TEST_CASE("hi\U0001D11E", '"', "hi\\uD834\\uDD1E")
TEST_CASE("h'i", '\'', "h\\'i")
TEST_CASE("hi\u1234", '\'', "hi\\u1234")
void test_mock_bpa_slash_escape_valid(const char *text, const char quote, const char *expect)
{
    m_string_t in_text;
    m_string_init_set_cstr(in_text, text);

    m_string_t out_text;
    m_string_init(out_text);
    TEST_ASSERT_EQUAL_INT(0, mock_bpa_slash_escape(out_text, in_text, quote));

    if (expect)
    {
        TEST_ASSERT_EQUAL_STRING(expect, m_string_get_cstr(out_text));
    }
    else
    {
        TEST_ASSERT_EQUAL_INT(0, m_string_size(out_text));
    }
    m_string_clear(out_text);
    m_string_clear(in_text);
}

TEST_CASE("", NULL)
TEST_CASE("hi", "hi")
TEST_CASE("h\\'i", "h'i")
TEST_CASE("h\\\"i", "h\"i")
TEST_CASE("h \\b\\f\\n\\r\\ti", "h \b\f\n\r\ti")
TEST_CASE("hi\\u1234", "hi\u1234")
TEST_CASE("hi\\uD834\\uDD1E", "hi\U0001D11E")
void test_mock_bpa_slash_unescape_valid(const char *text, const char *expect)
{
    m_string_t in_text;
    m_string_init_set_cstr(in_text, text);

    m_string_t out_text;
    m_string_init(out_text);
    TEST_ASSERT_EQUAL_INT(0, mock_bpa_slash_unescape(out_text, in_text));

    if (expect)
    {
        TEST_ASSERT_EQUAL_STRING(expect, m_string_get_cstr(out_text));
    }
    else
    {
        TEST_ASSERT_EQUAL_INT(0, m_string_size(out_text));
    }
    m_string_clear(out_text);
    m_string_clear(in_text);
}

TEST_CASE("\\")
void test_mock_bpa_slash_unescape_invalid(const char *text)
{
    m_string_t in_text;
    m_string_init_set_cstr(in_text, text);

    m_string_t out_text;
    m_string_init(out_text);
    TEST_ASSERT_NOT_EQUAL_INT(0, mock_bpa_slash_unescape(out_text, in_text));
    m_string_clear(out_text);
    m_string_clear(in_text);
}

TEST_CASE("", 0, false, "")
TEST_CASE("hi", 2, false, "6869")
void test_mock_bpa_base16_encode(const char *data, size_t data_len, bool uppercase, const char *expect)
{
    m_bstring_t in_data;
    m_bstring_init(in_data);
    if (data_len)
    {
        m_bstring_push_back_bytes(in_data, data_len, data);
    }

    m_string_t out;
    m_string_init(out);
    TEST_ASSERT_EQUAL_INT(0, mock_bpa_base16_encode(out, in_data, uppercase));

    TEST_ASSERT_EQUAL_STRING(expect, m_string_get_cstr(out));
    m_string_clear(out);
    m_bstring_clear(in_data);
}

TEST_CASE("", NULL, 0)
TEST_CASE("00", "\x00", 1)
TEST_CASE("6869", "hi", 2)
void test_mock_bpa_base16_decode_valid(const char *text, const char *expect, size_t expect_len)
{
    m_string_t in_text;
    m_string_init_set_cstr(in_text, text);

    m_bstring_t out_data;
    m_bstring_init(out_data);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, mock_bpa_base16_decode(out_data, in_text), "mock_bpa_base16_decode() failed");

    TEST_ASSERT_EQUAL_INT(expect_len, m_bstring_size(out_data));
    if (expect)
    {
        TEST_ASSERT_EQUAL_MEMORY(expect, m_bstring_view(out_data, 0, expect_len), expect_len);
    }

    m_bstring_clear(out_data);
    m_string_clear(in_text);
}

TEST_CASE("1")
TEST_CASE("asd")
void test_mock_bpa_base16_decode_invalid(const char *text)
{
    m_string_t in_text;
    m_string_init_set_cstr(in_text, text);

    m_bstring_t out_data;
    m_bstring_init(out_data);
    TEST_ASSERT_NOT_EQUAL_INT(0, mock_bpa_base16_decode(out_data, in_text));

    m_bstring_clear(out_data);
    m_string_clear(in_text);
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
void test_mock_bpa_base64_encode(const char *data, size_t data_len, bool useurl, bool usepad, const char *expect)
{
    m_bstring_t in_data;
    m_bstring_init(in_data);
    if (data_len)
    {
        m_bstring_push_back_bytes(in_data, data_len, data);
    }

    m_string_t out;
    m_string_init(out);
    TEST_ASSERT_EQUAL_INT(0, mock_bpa_base64_encode(out, in_data, useurl, usepad));

    TEST_ASSERT_EQUAL_STRING(expect, m_string_get_cstr(out));
    m_string_clear(out);
    m_bstring_clear(in_data);
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
void test_mock_bpa_base64_decode_valid(const char *text, const char *expect, size_t expect_len)
{
    m_string_t in_text;
    m_string_init_set_cstr(in_text, text);

    m_bstring_t out_data;
    m_bstring_init(out_data);
    TEST_ASSERT_EQUAL_INT(0, mock_bpa_base64_decode(out_data, in_text));

    TEST_ASSERT_EQUAL_INT(expect_len, m_bstring_size(out_data));
    if (expect)
    {
        TEST_ASSERT_EQUAL_MEMORY(expect, m_bstring_view(out_data, 0, expect_len), expect_len);
    }
    m_bstring_clear(out_data);
    m_string_clear(in_text);
}

TEST_CASE(".")
TEST_CASE("A.")
TEST_CASE("AB.")
TEST_CASE("ABC.")
void test_mock_bpa_base64_decode_invalid(const char *text)
{
    m_string_t in_text;
    m_string_init_set_cstr(in_text, text);
    m_bstring_t out_data;
    m_bstring_init(out_data);
    TEST_ASSERT_NOT_EQUAL_INT(0, mock_bpa_base64_decode(out_data, in_text));
    m_bstring_clear(out_data);
    m_string_clear(in_text);
}
