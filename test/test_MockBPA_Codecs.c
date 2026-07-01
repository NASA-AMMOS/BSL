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

#include <BPSecLib_Private.h>
#include <mock_bpa/log.h>
#include <mock_bpa/agent.h>
#include <mock_bpa/decode.h>
#include <mock_bpa/encode.h>

#include "DefaultScUtils.h"

static BSL_LibCtx_t bsl;

void suiteSetUp(void)
{
    TEST_ASSERT_EQUAL_INT(0, BSL_HostDescriptors_Set(MockBPA_Agent_Descriptors(NULL)));
    mock_bpa_LogOpen();
}

int suiteTearDown(int failures)
{
    mock_bpa_LogClose();
    BSL_HostDescriptors_Clear();
    return failures;
}

void setUp(void)
{
    TEST_ASSERT_EQUAL(0, BSL_API_InitLib(&bsl));
}

void tearDown(void)
{
    int deinit_code = BSL_API_DeinitLib(&bsl);
    TEST_ASSERT_EQUAL(0, deinit_code);
}

TEST_CASE("", NULL, 0)
TEST_CASE("00", "\x00", 1)
TEST_CASE("6869", "hi", 2)
void test_BSL_TestUtils_DecodeBase16_valid(const char *text, const char *expect, size_t expect_len)
{
    string_t in_text;
    string_init_set_str(in_text, text);
    BSL_Data_t out_data;
    BSL_Data_Init(&out_data);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, BSL_TestUtils_DecodeBase16(&out_data, in_text),
                                  "BSL_TestUtils_DecodeBase16() failed");

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
void test_DecodeBase16(const char *text)
{
    string_t in_text;
    string_init_set_str(in_text, text);
    BSL_Data_t out_data;
    BSL_Data_Init(&out_data);
    TEST_ASSERT_NOT_EQUAL_INT(0, BSL_TestUtils_DecodeBase16(&out_data, in_text));
    BSL_Data_Deinit(&out_data);
    string_clear(in_text);
}

TEST_CASE(BSL_BUNDLECRCTYPE_NONE, "88070000820282030482028201028202820000821903e81903e900")
TEST_CASE(BSL_BUNDLECRCTYPE_16, "89070001820282030482028201028202820000821903e81903e9004274FF")
TEST_CASE(BSL_BUNDLECRCTYPE_32, "89070002820282030482028201028202820000821903e81903e90044D64C9E29")
void test_bsl_mock_encode_primary(uint64_t crc_type, const char *expecthex)
{
    MockBPA_PrimaryBlock_t prim_blk_info = { .version       = 7,
                                             .flags         = 0,
                                             .crc_type      = crc_type,
                                             .dest_eid      = BSL_HOSTEID_INIT_INVALID,
                                             .src_node_id   = BSL_HOSTEID_INIT_INVALID,
                                             .report_to_eid = BSL_HOSTEID_INIT_INVALID,
                                             .timestamp     = { .bundle_creation_time = 1000, .seq_num = 1001 },
                                             .lifetime      = 0 };
    BSL_HostEID_Init(&(prim_blk_info.src_node_id));
    TEST_ASSERT_EQUAL_INT(0, BSL_HostEID_DecodeFromText(&(prim_blk_info.src_node_id), "ipn:1.2"));
    BSL_HostEID_Init(&(prim_blk_info.dest_eid));
    TEST_ASSERT_EQUAL_INT(0, BSL_HostEID_DecodeFromText(&(prim_blk_info.dest_eid), "ipn:3.4"));
    BSL_HostEID_Init(&(prim_blk_info.report_to_eid));
    TEST_ASSERT_EQUAL_INT(0, BSL_HostEID_DecodeFromText(&(prim_blk_info.report_to_eid), "ipn:0.0"));

    BSL_Data_t encoded;
    BSL_Data_Init(&encoded);
    TEST_ASSERT_EQUAL_INT(
        BSL_SUCCESS, BSL_CBOR_Encode_Twopass(&encoded, (BSL_CBOR_Encode_f)&bsl_mock_encode_primary, &prim_blk_info));

    TEST_ASSERT_TRUE(BSL_TestUtils_IsB16StrEqualTo(expecthex, encoded));
    BSL_Data_Deinit(&encoded);

    BSL_HostEID_Deinit(&(prim_blk_info.src_node_id));
    BSL_HostEID_Deinit(&(prim_blk_info.dest_eid));
    BSL_HostEID_Deinit(&(prim_blk_info.report_to_eid));
}

TEST_CASE(BSL_BUNDLECRCTYPE_NONE, "850a182d000043010203")
void test_bsl_mock_encode_canonical(uint64_t crc_type, const char *expecthex)
{
    static const uint8_t dummy_btsd[] = { 0x01, 0x02, 0x03 };
    static const size_t  dummy_size   = sizeof(dummy_btsd) / sizeof(uint8_t);

    MockBPA_CanonicalBlock_t blk = { 0 };
    blk.blk_type                 = 10;
    blk.blk_num                  = 45;
    blk.flags                    = 0;
    blk.crc_type                 = crc_type;
    blk.btsd                     = BSL_malloc(dummy_size);
    blk.btsd_len                 = dummy_size;
    memcpy(blk.btsd, dummy_btsd, dummy_size);

    BSL_Data_t encoded;
    BSL_Data_Init(&encoded);
    TEST_ASSERT_EQUAL_INT(BSL_SUCCESS,
                          BSL_CBOR_Encode_Twopass(&encoded, (BSL_CBOR_Encode_f)&bsl_mock_encode_canonical, &blk));

    TEST_ASSERT_TRUE(BSL_TestUtils_IsB16StrEqualTo(expecthex, encoded));
    BSL_Data_Deinit(&encoded);

    BSL_free(blk.btsd);
}

void test_bsl_mock_encode_bundle(void)
{
    MockBPA_Bundle_t bundle;
    MockBPA_Bundle_Init(&bundle);

    {
        MockBPA_PrimaryBlock_t *prim = &bundle.primary_block;
        prim->version                = 7;
        TEST_ASSERT_EQUAL_INT(0, BSL_HostEID_DecodeFromText(&(prim->src_node_id), "ipn:1.2"));
        TEST_ASSERT_EQUAL_INT(0, BSL_HostEID_DecodeFromText(&(prim->dest_eid), "ipn:3.4"));
        TEST_ASSERT_EQUAL_INT(0, BSL_HostEID_DecodeFromText(&(prim->report_to_eid), "ipn:0.0"));
        prim->timestamp.bundle_creation_time = 1000;
        prim->timestamp.seq_num              = 1001;
    }

    static const uint8_t dummy_btsd[] = { 0x01, 0x02, 0x03 };
    static const size_t  dummy_size   = sizeof(dummy_btsd) / sizeof(uint8_t);
    {
        MockBPA_CanonicalBlock_t *blk = MockBPA_BlockList_push_front_new(bundle.blocks);
        blk->blk_type                 = 10;
        blk->blk_num                  = 45;
        blk->flags                    = 0;
        blk->crc_type                 = 0;
        blk->btsd                     = BSL_calloc(1, dummy_size);
        blk->btsd_len                 = dummy_size;
        memcpy(blk->btsd, dummy_btsd, dummy_size);
    }

    BSL_Data_t encoded;
    BSL_Data_Init(&encoded);
    TEST_ASSERT_EQUAL_INT(BSL_SUCCESS,
                          BSL_CBOR_Encode_Twopass(&encoded, (BSL_CBOR_Encode_f)&bsl_mock_encode_bundle, &bundle));

    static const char *expecthex = "9f88070000820282030482028201028202820000821903e81903e900850a182d000043010203ff";
    TEST_ASSERT_TRUE(BSL_TestUtils_IsB16StrEqualTo(expecthex, encoded));
    BSL_Data_Deinit(&encoded);

    MockBPA_Bundle_Deinit(&bundle);
}

TEST_CASE("8202820102")                   // IPN scheme
TEST_CASE("821A00010000A203426869041819") // unknown scheme with complex data
void test_bsl_loopback_eid(const char *hexdata)
{
    string_t in_text;
    string_init_set_str(in_text, hexdata);
    BSL_Data_t in_data;
    BSL_Data_Init(&in_data);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, BSL_TestUtils_DecodeBase16(&in_data, in_text),
                                  "BSL_TestUtils_DecodeBase16() failed");

    BSL_HostEID_t eid;
    BSL_HostEID_Init(&eid);
    TEST_ASSERT_NOT_NULL(eid.handle);
    {
        QCBORDecodeContext decoder;
        QCBORDecode_Init(&decoder, (UsefulBufC) { in_data.ptr, in_data.len }, QCBOR_DECODE_MODE_NORMAL);
        TEST_ASSERT_EQUAL_INT_MESSAGE(0, bsl_mock_decode_eid_from_ctx(&decoder, &eid), "bsl_mock_decode_eid() failed");
        TEST_ASSERT_EQUAL_INT(QCBOR_SUCCESS, QCBORDecode_Finish(&decoder));
    }

    BSL_Data_t out_data;
    BSL_Data_Init(&out_data);
    {
        QCBOREncodeContext encoder;
        size_t             needlen;

        QCBOREncode_Init(&encoder, SizeCalculateUsefulBuf);
        TEST_ASSERT_EQUAL_INT_MESSAGE(0, bsl_mock_encode_eid_from_ctx(&encoder, &eid), "bsl_mock_encode_eid() failed");
        TEST_ASSERT_EQUAL_INT(QCBOR_SUCCESS, QCBOREncode_FinishGetSize(&encoder, &needlen));

        TEST_ASSERT_EQUAL_INT(0, BSL_Data_Resize(&out_data, needlen));
        QCBOREncode_Init(&encoder, (UsefulBuf) { out_data.ptr, out_data.len });
        TEST_ASSERT_EQUAL_INT_MESSAGE(0, bsl_mock_encode_eid_from_ctx(&encoder, &eid), "bsl_mock_encode_eid() failed");

        UsefulBufC out;
        TEST_ASSERT_EQUAL_INT(QCBOR_SUCCESS, QCBOREncode_Finish(&encoder, &out));
    }

    TEST_ASSERT_EQUAL_MEMORY(in_data.ptr, out_data.ptr, in_data.len);

    BSL_Data_Deinit(&out_data);
    BSL_HostEID_Deinit(&eid);
    BSL_Data_Deinit(&in_data);
    string_clear(in_text);
}

TEST_CASE("9f88070000820282030482028201028202820000821903e81903e900850101000043010203ff")
// sample input from BPSec COSE draft
TEST_CASE("9f890700028201692f2f6473742f7376638201692f2f7372632f7376638201662f2f7372632f821b000000bd51281400001a000f4240"
          "4482a081c98601010002466568656c6c6f444ec359d2ff")
void test_bsl_loopback_bundle(const char *hexdata)
{
    BSL_Data_t in_data;
    BSL_Data_Init(&in_data);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, BSL_TestUtils_DecodeBase16_cstr(&in_data, hexdata),
                                  "BSL_TestUtils_DecodeBase16_cstr() failed");

    MockBPA_Bundle_t bundle;
    MockBPA_Bundle_Init(&bundle);
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

    TEST_ASSERT_TRUE(BSL_TestUtils_IsB16StrEqualTo(hexdata, out_data));

    MockBPA_Bundle_Deinit(&bundle);
    BSL_Data_Deinit(&out_data);
    BSL_Data_Deinit(&in_data);
}
