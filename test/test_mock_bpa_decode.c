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
#include "backend/DeprecatedLibContext.h"
#include "backend/DynBundleContext.h"
#include "Logging.h"
#include <TypeDefintions.h>
#include <bsl_mock_bpa.h>
#include <bsl_mock_bpa_decode.h>
#include <UtilHelpers.h>
#include <unity.h>

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

void test_qcbor_decode_without_head(void)
{
    string_t in_text;
    string_init_set_str(in_text, "58"); // not a full head
    BSL_Data_t in_data;
    BSL_Data_Init(&in_data);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, base16_decode(&in_data, in_text), "base16_decode() failed");

    QCBORDecodeContext decoder;
    QCBORDecode_Init(&decoder, (UsefulBufC) { in_data.ptr, in_data.len }, QCBOR_DECODE_MODE_NORMAL);
    QCBORItem item;
    TEST_ASSERT_EQUAL_INT_MESSAGE(QCBOR_ERR_HIT_END, QCBORDecode_GetNext(&decoder, &item),
                                  "QCBORDecode_VGetNext() failed");
    TEST_ASSERT_EQUAL_INT(QCBOR_TYPE_NONE, item.uDataType);
    TEST_ASSERT_EQUAL_INT(1, QCBORDecode_Tell(&decoder));
    TEST_ASSERT_EQUAL_INT(QCBOR_SUCCESS, QCBORDecode_Finish(&decoder));

    BSL_Data_Deinit(&in_data);
    string_clear(in_text);
}

void test_qcbor_decode_only_head(void)
{
    string_t in_text;
    string_init_set_str(in_text, "586C"); // just a full head
    BSL_Data_t in_data;
    BSL_Data_Init(&in_data);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, base16_decode(&in_data, in_text), "base16_decode() failed");

    QCBORDecodeContext decoder;
    QCBORDecode_Init(&decoder, (UsefulBufC) { in_data.ptr, in_data.len }, QCBOR_DECODE_MODE_NORMAL);
    QCBORItem item;
    TEST_ASSERT_EQUAL_INT_MESSAGE(QCBOR_ERR_HIT_END, QCBORDecode_GetNext(&decoder, &item),
                                  "QCBORDecode_VGetNext() failed");
    TEST_ASSERT_EQUAL_INT(QCBOR_TYPE_NONE, item.uDataType);
    TEST_ASSERT_EQUAL_INT(2, QCBORDecode_Tell(&decoder));
    TEST_ASSERT_EQUAL_INT(QCBOR_SUCCESS, QCBORDecode_Finish(&decoder));

    BSL_Data_Deinit(&in_data);
    string_clear(in_text);
}

void test_qcbor_decode_with_head(void)
{
    string_t in_text;
    string_init_set_str(in_text, "586C616263646566"); // front of a bstr value
    BSL_Data_t in_data;
    BSL_Data_Init(&in_data);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, base16_decode(&in_data, in_text), "base16_decode() failed");

    QCBORDecodeContext decoder;
    QCBORDecode_Init(&decoder, (UsefulBufC) { in_data.ptr, in_data.len }, QCBOR_DECODE_MODE_NORMAL);
    QCBORItem item;
    TEST_ASSERT_EQUAL_INT_MESSAGE(QCBOR_ERR_HIT_END, QCBORDecode_GetNext(&decoder, &item),
                                  "QCBORDecode_VGetNext() failed");
    TEST_ASSERT_EQUAL_INT(QCBOR_TYPE_NONE, item.uDataType);
    TEST_ASSERT_EQUAL_INT(2, QCBORDecode_Tell(&decoder));
    TEST_ASSERT_EQUAL_INT(QCBOR_ERR_EXTRA_BYTES, QCBORDecode_Finish(&decoder));

    BSL_Data_Deinit(&in_data);
    string_clear(in_text);
}
