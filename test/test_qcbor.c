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
#include <m-string.h>
#include <qcbor/qcbor_spiffy_decode.h>
#include <BPSecLib_Public.h>
#include "TestUtils.h"

void test_qcbor_decode_without_head(void)
{
    const char *in_hex = "58"; // not a full head
    BSL_Data_t  in_data;
    BSL_Data_Init(&in_data);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, BSL_TestUtils_DecodeBase16_cstr(&in_data, in_hex),
                                  "BSL_TestUtils_DecodeBase16_cstr() failed");

    QCBORDecodeContext decoder;
    QCBORDecode_Init(&decoder, (UsefulBufC) { in_data.ptr, in_data.len }, QCBOR_DECODE_MODE_NORMAL);
    QCBORItem item;
    TEST_ASSERT_EQUAL_INT_MESSAGE(QCBOR_ERR_HIT_END, QCBORDecode_GetNext(&decoder, &item),
                                  "QCBORDecode_GetNext() failed");
    TEST_ASSERT_EQUAL_INT(QCBOR_TYPE_NONE, item.uDataType);
    TEST_ASSERT_EQUAL_INT(1, QCBORDecode_Tell(&decoder));
    TEST_ASSERT_EQUAL_INT(QCBOR_SUCCESS, QCBORDecode_Finish(&decoder));

    BSL_Data_Deinit(&in_data);
}

void test_qcbor_decode_only_head(void)
{
    const char *in_hex = "586C"; // just a full head
    BSL_Data_t  in_data;
    BSL_Data_Init(&in_data);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, BSL_TestUtils_DecodeBase16_cstr(&in_data, in_hex),
                                  "BSL_TestUtils_DecodeBase16_cstr() failed");

    QCBORDecodeContext decoder;
    QCBORDecode_Init(&decoder, (UsefulBufC) { in_data.ptr, in_data.len }, QCBOR_DECODE_MODE_NORMAL);
    QCBORItem item;
    TEST_ASSERT_EQUAL_INT_MESSAGE(QCBOR_ERR_HIT_END, QCBORDecode_GetNext(&decoder, &item),
                                  "QCBORDecode_GetNext() failed");
    TEST_ASSERT_EQUAL_INT(QCBOR_TYPE_NONE, item.uDataType);
    TEST_ASSERT_EQUAL_INT(2, QCBORDecode_Tell(&decoder));
    TEST_ASSERT_EQUAL_INT(QCBOR_SUCCESS, QCBORDecode_Finish(&decoder));

    BSL_Data_Deinit(&in_data);
}

void test_qcbor_decode_with_head(void)
{
    const char *in_hex = "586C616263646566"; // front of a bstr value
    BSL_Data_t  in_data;
    BSL_Data_Init(&in_data);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, BSL_TestUtils_DecodeBase16_cstr(&in_data, in_hex),
                                  "BSL_TestUtils_DecodeBase16_cstr() failed");

    QCBORDecodeContext decoder;
    QCBORDecode_Init(&decoder, (UsefulBufC) { in_data.ptr, in_data.len }, QCBOR_DECODE_MODE_NORMAL);
    QCBORItem item;
    TEST_ASSERT_EQUAL_INT_MESSAGE(QCBOR_ERR_HIT_END, QCBORDecode_GetNext(&decoder, &item),
                                  "QCBORDecode_GetNext() failed");
    TEST_ASSERT_EQUAL_INT(QCBOR_TYPE_NONE, item.uDataType);
    TEST_ASSERT_EQUAL_INT(2, QCBORDecode_Tell(&decoder));
    TEST_ASSERT_EQUAL_INT(QCBOR_ERR_EXTRA_BYTES, QCBORDecode_Finish(&decoder));

    BSL_Data_Deinit(&in_data);
}

void test_qcbor_decode_map_sequential(void)
{
    const char *in_hex = "a201020304";
    BSL_Data_t  in_data;
    BSL_Data_Init(&in_data);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, BSL_TestUtils_DecodeBase16_cstr(&in_data, in_hex),
                                  "BSL_TestUtils_DecodeBase16_cstr() failed");

    QCBORDecodeContext decoder;
    QCBORDecode_Init(&decoder, (UsefulBufC) { in_data.ptr, in_data.len }, QCBOR_DECODE_MODE_NORMAL);
    QCBORItem item;
    QCBORDecode_EnterMap(&decoder, &item);
    TEST_ASSERT_EQUAL_INT(QCBOR_SUCCESS, QCBORDecode_GetError(&decoder));
    TEST_ASSERT_EQUAL_INT(QCBOR_TYPE_MAP, item.uDataType);
    TEST_ASSERT_EQUAL_INT(1, QCBORDecode_Tell(&decoder));

    TEST_ASSERT_EQUAL_INT(QCBOR_SUCCESS, QCBORDecode_PeekNext(&decoder, &item));

    TEST_ASSERT_EQUAL_INT(QCBOR_SUCCESS, QCBORDecode_GetNext(&decoder, &item));
    TEST_ASSERT_EQUAL_INT(QCBOR_TYPE_INT64, item.uLabelType);
    TEST_ASSERT_EQUAL_INT(1, item.label.int64);
    TEST_ASSERT_EQUAL_INT(QCBOR_TYPE_INT64, item.uDataType);
    TEST_ASSERT_EQUAL_INT(2, item.val.int64);
    TEST_ASSERT_EQUAL_INT(3, QCBORDecode_Tell(&decoder));

    TEST_ASSERT_EQUAL_INT(QCBOR_SUCCESS, QCBORDecode_PeekNext(&decoder, &item));
    TEST_ASSERT_EQUAL_INT(QCBOR_SUCCESS, QCBORDecode_GetNext(&decoder, &item));
    TEST_ASSERT_EQUAL_INT(QCBOR_TYPE_INT64, item.uLabelType);
    TEST_ASSERT_EQUAL_INT(3, item.label.int64);
    TEST_ASSERT_EQUAL_INT(QCBOR_TYPE_INT64, item.uDataType);
    TEST_ASSERT_EQUAL_INT(4, item.val.int64);
    TEST_ASSERT_EQUAL_INT(5, QCBORDecode_Tell(&decoder));

    TEST_ASSERT_EQUAL_INT(QCBOR_ERR_NO_MORE_ITEMS, QCBORDecode_PeekNext(&decoder, &item));

    QCBORDecode_ExitMap(&decoder);
    TEST_ASSERT_EQUAL_INT(QCBOR_SUCCESS, QCBORDecode_Finish(&decoder));

    BSL_Data_Deinit(&in_data);
}

void test_qcbor_decode_array_nested(void)
{
    const char *in_hex = "9F820102FF"; // [_ [1,2]]
    BSL_Data_t  in_data;
    BSL_Data_Init(&in_data);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, BSL_TestUtils_DecodeBase16_cstr(&in_data, in_hex),
                                  "BSL_TestUtils_DecodeBase16_cstr() failed");

    QCBORDecodeContext decoder;
    QCBORDecode_Init(&decoder, (UsefulBufC) { in_data.ptr, in_data.len }, QCBOR_DECODE_MODE_NORMAL);
    QCBORItem item;

    // outer array
    QCBORDecode_EnterArray(&decoder, &item);
    TEST_ASSERT_EQUAL_INT_MESSAGE(QCBOR_SUCCESS, QCBORDecode_GetError(&decoder), "QCBORDecode_EnterArray() failed");
    TEST_ASSERT_EQUAL_INT(QCBOR_TYPE_ARRAY, item.uDataType);
    TEST_ASSERT_EQUAL_INT(UINT16_MAX, item.val.uCount);
    TEST_ASSERT_EQUAL_INT(1, QCBORDecode_Tell(&decoder));

    // inner array
    QCBORDecode_EnterArray(&decoder, &item);
    TEST_ASSERT_EQUAL_INT_MESSAGE(QCBOR_SUCCESS, QCBORDecode_GetError(&decoder), "QCBORDecode_EnterArray() failed");
    TEST_ASSERT_EQUAL_INT(QCBOR_TYPE_ARRAY, item.uDataType);
    TEST_ASSERT_EQUAL_INT(2, item.val.uCount);
    TEST_ASSERT_EQUAL_INT(2, QCBORDecode_Tell(&decoder));

    int64_t dummy;
    QCBORDecode_GetInt64(&decoder, &dummy);
    TEST_ASSERT_EQUAL_INT_MESSAGE(QCBOR_SUCCESS, QCBORDecode_GetError(&decoder), "QCBORDecode_GetInt64() failed");

    QCBORDecode_GetInt64(&decoder, &dummy);
    TEST_ASSERT_EQUAL_INT_MESSAGE(QCBOR_SUCCESS, QCBORDecode_GetError(&decoder), "QCBORDecode_GetInt64() failed");
    TEST_ASSERT_EQUAL_INT(4, QCBORDecode_Tell(&decoder));

    // exit inner
    QCBORDecode_ExitArray(&decoder);
    TEST_ASSERT_EQUAL_INT_MESSAGE(QCBOR_SUCCESS, QCBORDecode_GetError(&decoder), "QCBORDecode_ExitArray() failed");
    TEST_ASSERT_EQUAL_INT(5, QCBORDecode_Tell(&decoder)); // QCBOR issue

    // exit outer
    QCBORDecode_ExitArray(&decoder);
    TEST_ASSERT_EQUAL_INT_MESSAGE(QCBOR_SUCCESS, QCBORDecode_GetError(&decoder), "QCBORDecode_ExitArray() failed");
    TEST_ASSERT_EQUAL_INT(5, QCBORDecode_Tell(&decoder));

    TEST_ASSERT_EQUAL_INT(QCBOR_SUCCESS, QCBORDecode_Finish(&decoder));

    BSL_Data_Deinit(&in_data);
}
