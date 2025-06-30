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
#include <bsl_mock_bpa_encode.h>
#include <UtilHelpers.h>
#include <unity.h>

// allow parameterized cases
#define TEST_CASE(...)

static void printencoded(const uint8_t *pEncoded, size_t nLen)
{
    BSL_Data_t in;
    BSL_Data_InitView(&in, nLen, (BSL_DataPtr_t)pEncoded);
    string_t out;
    string_init(out);
    base16_encode(out, &in, false);
    TEST_MESSAGE(string_get_cstr(out));
    string_clear(out);
    BSL_Data_Deinit(&in);
}

static BSL_LibCtx_t bsl;
/// Output storage safely cleaned up
static UsefulBuf buf;
/// Encoder shared among tests
static QCBOREncodeContext encoder;

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

    buf.len = 10000;
    buf.ptr = BSL_MALLOC(buf.len);
    TEST_ASSERT_NOT_NULL(buf.ptr);
    QCBOREncode_Init(&encoder, buf);
}

void tearDown(void)
{
    if (buf.ptr)
    {
        BSL_FREE(buf.ptr);
    }
    buf = NULLUsefulBuf;

    TEST_ASSERT_EQUAL(0, BSL_LibCtx_Deinit(&bsl));
}

TEST_CASE(BSL_BUNDLECRCTYPE_NONE, "88070000820282030482028201028202820000821903e81903e900")
TEST_CASE(BSL_BUNDLECRCTYPE_16,
          "89070001820282030482028201028202820000821903e81903e9004204D2") // FIXME placeholder CRC value
TEST_CASE(BSL_BUNDLECRCTYPE_32, "89070002820282030482028201028202820000821903e81903e900440012D687")
void test_bsl_mock_encode_primary(uint64_t crc_type, const char *expecthex)
{
    string_t expect_text;
    string_init_set_str(expect_text, expecthex);
    BSL_Data_t expect_data;
    BSL_Data_Init(&expect_data);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, base16_decode(&expect_data, expect_text), "base16_decode() failed");

    BSL_BundlePrimaryBlock_t prim_blk_info = { .version       = 7,
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

    TEST_ASSERT_EQUAL_INT(0, bsl_mock_encode_primary(&encoder, &prim_blk_info));

    UsefulBufC encoded;
    QCBORError err = QCBOREncode_Finish(&encoder, &encoded);
    TEST_ASSERT_EQUAL_INT(QCBOR_SUCCESS, err);

    printencoded(encoded.ptr, encoded.len);
    TEST_ASSERT_EQUAL_INT(expect_data.len, encoded.len);
    TEST_ASSERT_EQUAL_MEMORY(expect_data.ptr, encoded.ptr, expect_data.len);

    BSL_BundlePrimaryBlock_Deinit(&prim_blk_info);
    BSL_Data_Deinit(&expect_data);
    string_clear(expect_text);
}

TEST_CASE(BSL_BUNDLECRCTYPE_NONE, "850a182d000043010203")
void test_bsl_mock_encode_canonical(uint64_t crc_type, const char *expecthex)
{
    string_t expect_text;
    string_init_set_str(expect_text, expecthex);
    BSL_Data_t expect_data;
    BSL_Data_Init(&expect_data);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, base16_decode(&expect_data, expect_text), "base16_decode() failed");

    static const uint8_t dummy_btsd[] = { 0x01, 0x02, 0x03 };
    static const size_t  dummy_size   = sizeof(dummy_btsd) / sizeof(uint8_t);

    BSL_BundleBlock_t blk;
    BSL_BundleBlock_Init(&blk);
    blk.blk_type = 10;
    blk.blk_num  = 45;
    blk.flags    = 0;
    blk.crc_type = crc_type;
    BSL_Data_InitView(&blk.btsd, dummy_size, (BSL_DataPtr_t)dummy_btsd);

    TEST_ASSERT_EQUAL_INT(0, bsl_mock_encode_canonical(&encoder, &blk));

    UsefulBufC encoded;
    QCBORError err = QCBOREncode_Finish(&encoder, &encoded);
    TEST_ASSERT_EQUAL_INT(QCBOR_SUCCESS, err);

    printencoded(encoded.ptr, encoded.len);
    TEST_ASSERT_EQUAL_INT(expect_data.len, encoded.len);
    TEST_ASSERT_EQUAL_MEMORY(expect_data.ptr, encoded.ptr, expect_data.len);

    BSL_BundleBlock_Deinit(&blk);
    BSL_Data_Deinit(&expect_data);
    string_clear(expect_text);
}

void test_bsl_mock_encode_bundle(void)
{
    BSL_BundleCtx_t bundle;
    BSL_BundleCtx_Init(&bundle, &bsl);

    {
        BSL_BundlePrimaryBlock_t *prim = BSL_BundleCtx_GetPrimaryBlock(&bundle);

        TEST_ASSERT_EQUAL_INT(0, BSL_HostEID_DecodeFromText(&(prim->src_node_id), "ipn:1.2"));
        TEST_ASSERT_EQUAL_INT(0, BSL_HostEID_DecodeFromText(&(prim->dest_eid), "ipn:3.4"));
        TEST_ASSERT_EQUAL_INT(0, BSL_HostEID_DecodeFromText(&(prim->report_to_eid), "ipn:0.0"));
        prim->timestamp.bundle_creation_time = 1000;
        prim->timestamp.seq_num              = 1001;
    }

    static const uint8_t dummy_btsd[] = { 0x01, 0x02, 0x03 };
    static const size_t  dummy_size   = sizeof(dummy_btsd) / sizeof(uint8_t);
    {
        BSL_BundleBlock_t blk;
        BSL_BundleBlock_Init(&blk);
        blk.blk_type = 10;
        blk.blk_num  = 45;
        blk.flags    = 0;
        blk.crc_type = 0;
        BSL_Data_InitView(&blk.btsd, dummy_size, (BSL_DataPtr_t)dummy_btsd);
        BSL_BundleCtx_AddBlock(&bundle, blk);
    }

    TEST_ASSERT_EQUAL_INT(0, bsl_mock_encode_bundle(&encoder, &bundle));

    UsefulBufC encoded;
    QCBORError err = QCBOREncode_Finish(&encoder, &encoded);
    TEST_ASSERT_EQUAL_INT(QCBOR_SUCCESS, err);

    printencoded(encoded.ptr, encoded.len);

    static const uint8_t expected[] = {
        0x9f, 0x88, 0x07, 0x00, 0x00, 0x82, 0x02, 0x82, 0x03, 0x04, 0x82, 0x02, 0x82,
        0x01, 0x02, 0x82, 0x02, 0x82, 0x00, 0x00, 0x82, 0x19, 0x03, 0xe8, 0x19, 0x03,
        0xe9, 0x00, 0x85, 0x0a, 0x18, 0x2d, 0x00, 0x00, 0x43, 0x01, 0x02, 0x03, 0xff,
    };
    TEST_ASSERT_EQUAL_MEMORY(expected, encoded.ptr, sizeof(expected));

    BSL_BundleCtx_Deinit(&bundle);
}
