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
#include <bsl_mock_bpa.h>
#include <backend/DynBundleContext.h>
#include <Logging.h>
#include <unity.h>

static BSL_LibCtx_t    bsl;
static BSL_BundleCtx_t bundle;

static const uint8_t dummy_btsd[] = { 0x01, 0x02, 0x03 };
static const size_t  dummy_size   = sizeof(dummy_btsd) / sizeof(uint8_t);

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
    TEST_ASSERT_EQUAL(0, BSL_BundleCtx_Init(&bundle, &bsl));
}

void tearDown(void)
{
    BSL_BundleCtx_Deinit(&bundle);
    TEST_ASSERT_EQUAL(0, BSL_LibCtx_Deinit(&bsl));
}

static BSL_BundleBlock_t add_dummy_block(uint64_t blk_type, uint64_t blk_num, const uint8_t *btsd_buf,
                                         const size_t btsd_size)
{
    BSL_BundleBlock_t info = {
        .blk_type = blk_type,
        .blk_num  = blk_num,
        .flags    = 0x34,
        .crc_type = 1,
    };
    BSL_Data_InitView(&info.btsd, btsd_size, (BSL_DataPtr_t)btsd_buf);
    TEST_ASSERT_EQUAL(0, BSL_BundleCtx_AddBlock(&bundle, info));

    return info;
}

void test_BSL_BundleCtx_GetPrimaryBlock(void)
{
    // The bundle starts off with a primary block
    BSL_BundlePrimaryBlock_t *prim = BSL_BundleCtx_GetPrimaryBlock(&bundle);
    TEST_ASSERT_NOT_NULL(prim);
    TEST_ASSERT_EQUAL(7, prim->version);
    TEST_ASSERT_EQUAL(0, prim->timestamp.bundle_creation_time);
    TEST_ASSERT_EQUAL(0, prim->timestamp.seq_num);
}

void test_bundle_ctx_one_block(void)
{
    TEST_ASSERT_NOT_EQUAL(0, BSL_BundleContext_GetBlockMetadata(&bundle, 2, NULL, NULL, NULL, NULL));

    add_dummy_block(10, 2, dummy_btsd, dummy_size);
    TEST_ASSERT_EQUAL(0, BSL_BundleContext_GetBlockMetadata(&bundle, 2, NULL, NULL, NULL, NULL));
}

void test_bundle_ctx_get_meta(void)
{
    BSL_BundleBlock_t info = add_dummy_block(10, 2, dummy_btsd, dummy_size);

    uint64_t   got_type;
    uint64_t   got_flags;
    uint64_t   got_crc_type;
    BSL_Data_t got_btsd;
    TEST_ASSERT_EQUAL(0,
                      BSL_BundleContext_GetBlockMetadata(&bundle, 2, &got_type, &got_flags, &got_crc_type, &got_btsd));
    TEST_ASSERT_EQUAL(info.blk_type, got_type);
    TEST_ASSERT_EQUAL(info.flags, got_flags);
    TEST_ASSERT_EQUAL(info.crc_type, got_crc_type);
    TEST_ASSERT_EQUAL(info.btsd.len, got_btsd.len);
    TEST_ASSERT_EQUAL(info.btsd.ptr, got_btsd.ptr);
}

void test_bundle_ctx_btsd_read_parts(void)
{
    BSL_BundleBlock_t info = add_dummy_block(10, 2, dummy_btsd, dummy_size);

    BSL_SeqReader_t *reader = NULL;
    TEST_ASSERT_EQUAL(0, BSL_BundleCtx_ReadBTSD(&bundle, 2, &reader));
    TEST_ASSERT_NOT_NULL(reader);

    uint8_t got_buffer[2] = { 0x00 };
    size_t  got_size      = sizeof(got_buffer);
    TEST_ASSERT_EQUAL(2, got_size);

    // first read is full
    TEST_ASSERT_EQUAL(0, BSL_SeqReader_Get(reader, got_buffer, &got_size));
    TEST_ASSERT_EQUAL(2, got_size);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(info.btsd.ptr, got_buffer, got_size);

    // next read is partial
    TEST_ASSERT_EQUAL(0, BSL_SeqReader_Get(reader, got_buffer, &got_size));
    TEST_ASSERT_EQUAL(1, got_size);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(info.btsd.ptr + 2, got_buffer, got_size);

    // last read gets nothing
    TEST_ASSERT_EQUAL(0, BSL_SeqReader_Get(reader, got_buffer, &got_size));
    TEST_ASSERT_EQUAL(0, got_size);

    TEST_ASSERT_EQUAL(0, BSL_SeqReader_Deinit(reader));
}

void test_bundle_ctx_btsd_read_whole(void)
{
    BSL_BundleBlock_t info = add_dummy_block(10, 2, dummy_btsd, dummy_size);

    BSL_SeqReader_t *reader = NULL;
    TEST_ASSERT_EQUAL(0, BSL_BundleCtx_ReadBTSD(&bundle, 2, &reader));
    TEST_ASSERT_NOT_NULL(reader);

    uint8_t got_buffer[128] = { 0x00 };
    size_t  got_size        = sizeof(got_buffer);
    TEST_ASSERT_EQUAL(128, got_size);

    // first read is all
    TEST_ASSERT_EQUAL(0, BSL_SeqReader_Get(reader, got_buffer, &got_size));
    TEST_ASSERT_EQUAL(3, got_size);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(info.btsd.ptr, got_buffer, got_size);

    // last read gets nothing
    TEST_ASSERT_EQUAL(0, BSL_SeqReader_Get(reader, got_buffer, &got_size));
    TEST_ASSERT_EQUAL(0, got_size);

    TEST_ASSERT_EQUAL(0, BSL_SeqReader_Deinit(reader));
}

void test_bundle_ctx_btsd_write_parts(void)
{
    add_dummy_block(10, 2, dummy_btsd, dummy_size);

    BSL_SeqWriter_t *writer = NULL;
    TEST_ASSERT_EQUAL(0, BSL_BundleCtx_WriteBTSD(&bundle, 2, &writer));
    TEST_ASSERT_NOT_NULL(writer);

    {
        const uint8_t put_buffer[] = { 0x03, 0x04, 0x05 };
        size_t        put_size     = sizeof(put_buffer);
        TEST_ASSERT_EQUAL(3, put_size);
        TEST_ASSERT_EQUAL(0, BSL_SeqWriter_Put(writer, put_buffer, &put_size));
        TEST_ASSERT_EQUAL(3, put_size);
    }
    {
        const uint8_t put_buffer[] = { 0x06, 0x07, 0x08 };
        size_t        put_size     = sizeof(put_buffer);
        TEST_ASSERT_EQUAL(3, put_size);
        TEST_ASSERT_EQUAL(0, BSL_SeqWriter_Put(writer, put_buffer, &put_size));
        TEST_ASSERT_EQUAL(3, put_size);
    }
    TEST_ASSERT_EQUAL(0, BSL_SeqWriter_Deinit(writer));

    const BSL_BundleBlock_t *info = BSL_BundleCtx_GetBlockById(&bundle, 2);
    TEST_ASSERT_TRUE(info->btsd.owned);
    TEST_ASSERT_NOT_NULL(info->btsd.ptr);
    {
        const uint8_t expect[] = { 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
        TEST_ASSERT_EQUAL(sizeof(expect), info->btsd.len);
        TEST_ASSERT_EQUAL_UINT8_ARRAY(info->btsd.ptr, expect, info->btsd.len);
    }
}

void test_bundle_ctx_btsd_write_whole(void)
{
    add_dummy_block(10, 2, dummy_btsd, dummy_size);

    BSL_SeqWriter_t *writer = NULL;
    TEST_ASSERT_EQUAL(0, BSL_BundleCtx_WriteBTSD(&bundle, 2, &writer));
    TEST_ASSERT_NOT_NULL(writer);

    {
        const uint8_t put_buffer[] = { 0x03, 0x04, 0x05 };
        size_t        put_size     = sizeof(put_buffer);
        TEST_ASSERT_EQUAL(3, put_size);

        TEST_ASSERT_EQUAL(0, BSL_SeqWriter_Put(writer, put_buffer, &put_size));
        TEST_ASSERT_EQUAL(3, put_size);
    }
    TEST_ASSERT_EQUAL(0, BSL_SeqWriter_Deinit(writer));

    const BSL_BundleBlock_t *info = BSL_BundleCtx_GetBlockById(&bundle, 2);
    TEST_ASSERT_TRUE(info->btsd.owned);
    TEST_ASSERT_NOT_NULL(info->btsd.ptr);
    {
        const uint8_t expect[] = { 0x03, 0x04, 0x05 };
        TEST_ASSERT_EQUAL(sizeof(expect), info->btsd.len);
        TEST_ASSERT_EQUAL_UINT8_ARRAY(info->btsd.ptr, expect, info->btsd.len);
    }
}

void test_bundle_ctx_one_bib(void)
{
    TEST_ASSERT_NOT_EQUAL(0, BSL_BundleContext_GetBlockMetadata(&bundle, 2, NULL, NULL, NULL, NULL));

    add_dummy_block(BSL_BLOCK_TYPE_PAYLOAD, 1, dummy_btsd, dummy_size);
    TEST_ASSERT_EQUAL(0, BSL_BundleContext_GetBlockMetadata(&bundle, 1, NULL, NULL, NULL, NULL));

    // encoded from example in Section A.1.3.2 of RFC 9173
    // [1],1,1,[2,[2, 1]],[[1, 7], [3, 0]], [[[1,
    // h'3BDC69B3A34A2B5D3A8554368BD1E808F606219D2A10A846EAE3886AE4ECC83C4EE550FDFB1CC636B904E2F1A73E303DCD4B6CCECE003E95E8164DCC89A156E1']]]
    // Pipe through: diag2cbor.rb | xxd -i
    static const uint8_t asb_buf[] = { 0x81, 0x01, 0x01, 0x01, 0x82, 0x02, 0x82, 0x02, 0x01, 0x82, 0x82, 0x01, 0x07,
                                       0x82, 0x03, 0x00, 0x81, 0x81, 0x82, 0x01, 0x58, 0x40, 0x3b, 0xdc, 0x69, 0xb3,
                                       0xa3, 0x4a, 0x2b, 0x5d, 0x3a, 0x85, 0x54, 0x36, 0x8b, 0xd1, 0xe8, 0x08, 0xf6,
                                       0x06, 0x21, 0x9d, 0x2a, 0x10, 0xa8, 0x46, 0xea, 0xe3, 0x88, 0x6a, 0xe4, 0xec,
                                       0xc8, 0x3c, 0x4e, 0xe5, 0x50, 0xfd, 0xfb, 0x1c, 0xc6, 0x36, 0xb9, 0x04, 0xe2,
                                       0xf1, 0xa7, 0x3e, 0x30, 0x3d, 0xcd, 0x4b, 0x6c, 0xce, 0xce, 0x00, 0x3e, 0x95,
                                       0xe8, 0x16, 0x4d, 0xcc, 0x89, 0xa1, 0x56, 0xe1 };
    static const size_t  asb_size  = sizeof(asb_buf) / sizeof(uint8_t);
    add_dummy_block(BSL_BLOCK_TYPE_BIB, 3, asb_buf, asb_size);
}
