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
#include <backend/DeprecatedLibContext.h>
#include <backend/DynBundleContext.h>
#include "Logging.h"
#include <TypeDefintions.h>
#include <bsl_mock_bpa.h>
#include <bsl_mock_bpa_decode.h>
#include <bsl_mock_bpa_encode.h>
#include <UtilHelpers.h>
#include <inttypes.h>
#include <unity.h>

// allow parameterized cases
#define TEST_CASE(...)

static BSL_LibCtx_t bsl;

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

void setUp(void)
{
    TEST_ASSERT_EQUAL(0, BSL_LibCtx_Init(&bsl));
}

void tearDown(void)
{
    TEST_ASSERT_EQUAL(0, BSL_LibCtx_Deinit(&bsl));
}

TEST_CASE("8202820102")                   // IPN scheme
TEST_CASE("821A00010000A203426869041819") // unknown scheme with complex data
void test_bsl_loopback_eid(const char *hexdata)
{
    string_t in_text;
    string_init_set_str(in_text, hexdata);
    BSL_Data_t in_data;
    BSL_Data_Init(&in_data);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, base16_decode(&in_data, in_text), "base16_decode() failed");

    BSL_HostEID_t eid;
    BSL_HostEID_Init(&eid);
    {
        QCBORDecodeContext decoder;
        QCBORDecode_Init(&decoder, (UsefulBufC) { in_data.ptr, in_data.len }, QCBOR_DECODE_MODE_NORMAL);
        TEST_ASSERT_EQUAL_INT_MESSAGE(0, bsl_mock_decode_eid(&decoder, &eid), "bsl_mock_decode_eid() failed");
        TEST_ASSERT_EQUAL_INT(QCBOR_SUCCESS, QCBORDecode_Finish(&decoder));
    }

    BSL_Data_t out_data;
    BSL_Data_Init(&out_data);
    {
        QCBOREncodeContext encoder;
        size_t             needlen;

        QCBOREncode_Init(&encoder, SizeCalculateUsefulBuf);
        TEST_ASSERT_EQUAL_INT_MESSAGE(0, bsl_mock_encode_eid(&encoder, &eid), "bsl_mock_encode_eid() failed");
        TEST_ASSERT_EQUAL_INT(QCBOR_SUCCESS, QCBOREncode_FinishGetSize(&encoder, &needlen));

        TEST_ASSERT_EQUAL_INT(0, BSL_Data_Resize(&out_data, needlen));
        QCBOREncode_Init(&encoder, (UsefulBuf) { out_data.ptr, out_data.len });
        TEST_ASSERT_EQUAL_INT_MESSAGE(0, bsl_mock_encode_eid(&encoder, &eid), "bsl_mock_encode_eid() failed");

        UsefulBufC out;
        TEST_ASSERT_EQUAL_INT(QCBOR_SUCCESS, QCBOREncode_Finish(&encoder, &out));
    }

    TEST_ASSERT_EQUAL_MEMORY(in_data.ptr, out_data.ptr, in_data.len);

    BSL_Data_Deinit(&out_data);
    BSL_HostEID_Deinit(&eid);
    BSL_Data_Deinit(&in_data);
    string_clear(in_text);
}

TEST_CASE("9f88070000820282030482028201028202820000821903e81903e900850a182d000043010203ff")
void test_bsl_loopback_bundle(const char *hexdata)
{
    string_t in_text;
    string_init_set_str(in_text, hexdata);
    BSL_Data_t in_data;
    BSL_Data_Init(&in_data);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, base16_decode(&in_data, in_text), "base16_decode() failed");

    BSL_BundleCtx_t bundle;
    BSL_BundleCtx_Init(&bundle, &bsl);
    {
        QCBORDecodeContext decoder;
        QCBORDecode_Init(&decoder, (UsefulBufC) { in_data.ptr, in_data.len }, QCBOR_DECODE_MODE_NORMAL);
        TEST_ASSERT_EQUAL_INT_MESSAGE(0, bsl_mock_decode_bundle(&decoder, &bundle), "bsl_mock_decode_bundle() failed");
        TEST_ASSERT_EQUAL_INT(QCBOR_SUCCESS, QCBORDecode_Finish(&decoder));
    }

    BSL_Data_t out_data;
    BSL_Data_Init(&out_data);
    {
        QCBOREncodeContext encoder;

        QCBOREncode_Init(&encoder, SizeCalculateUsefulBuf);
        TEST_ASSERT_EQUAL_INT_MESSAGE(0, bsl_mock_encode_bundle(&encoder, &bundle), "bsl_mock_encode_bundle() failed");
        size_t needlen;
        TEST_ASSERT_EQUAL_INT(QCBOR_SUCCESS, QCBOREncode_FinishGetSize(&encoder, &needlen));

        TEST_ASSERT_EQUAL_INT(0, BSL_Data_Resize(&out_data, needlen));
        QCBOREncode_Init(&encoder, (UsefulBuf) { out_data.ptr, out_data.len });
        TEST_ASSERT_EQUAL_INT_MESSAGE(0, bsl_mock_encode_bundle(&encoder, &bundle), "bsl_mock_encode_bundle() failed");

        UsefulBufC out;
        TEST_ASSERT_EQUAL_INT(QCBOR_SUCCESS, QCBOREncode_Finish(&encoder, &out));
    }

    TEST_ASSERT_EQUAL_MEMORY(in_data.ptr, out_data.ptr, in_data.len);

    BSL_Data_Deinit(&out_data);
    BSL_BundleCtx_Deinit(&bundle);
    BSL_Data_Deinit(&in_data);
    string_clear(in_text);
}
