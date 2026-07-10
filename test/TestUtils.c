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
#undef NDEBUG // force assertions
#include <assert.h>

#include <m-string.h>

#include <BPSecLib_Private.h>
#include <CryptoInterface.h>
#include <mock_bpa/MockBPA.h>

#include <backend/IdValPair.h>
#include <backend/SecurityActionSet.h>
#include <backend/UtilDefs_SeqReadWrite.h>
#include <backend/TextUtil.h>
#include <policy_provider/SamplePolicyProvider.h>

#include "TestUtils.h"

int BSL_TestContext_Init(BSL_TestContext_t *ctx)
{
    memset(ctx, 0, sizeof(BSL_TestContext_t));
    if (BSL_SUCCESS != BSL_API_InitLib(&ctx->bsl))
    {
        return 1;
    }
    mock_bpa_ctr_init(&ctx->mock_bpa_ctr);
    return BSL_SUCCESS;
}

int BSL_TestContext_Deinit(BSL_TestContext_t *ctx)
{
    mock_bpa_ctr_deinit(&ctx->mock_bpa_ctr);
    if (BSL_SUCCESS != BSL_API_DeinitLib(&ctx->bsl))
    {
        return 1;
    }
    memset(ctx, 0, sizeof(BSL_TestContext_t));
    return BSL_SUCCESS;
}

bool BSL_TestUtils_IsB16StrEqualTo(const char *expected_hex, BSL_Data_t encoded_val)
{
    BSL_Data_t in_data;
    BSL_Data_Init(&in_data);
    in_data.owned = 1;
    if (BSL_TestUtils_DecodeBase16_cstr(&in_data, expected_hex) != 0)
    {
        BSL_LOG_CRIT("Could not base16-decode sequence");
        BSL_Data_Deinit(&in_data);
        return false;
    }

    BSL_TestUtils_PrintHexToBuffer("expected str: ", in_data.ptr, in_data.len);
    BSL_TestUtils_PrintHexToBuffer("actual str  : ", encoded_val.ptr, encoded_val.len);

    bool match = BSL_Data_Cmp(&encoded_val, &in_data) == 0;
    if (!match)
    {
        BSL_LOG_CRIT("Mismatch in content");
    }
    BSL_Data_Deinit(&in_data);
    return match;
}

void BSL_TestUtils_PrintHexToBuffer(const char *message, uint8_t *buff, size_t bufflen)
{
    BSL_Data_t val     = BSL_DATA_INIT_VIEW(buff, bufflen);
    BSL_Data_t hex_str = BSL_DATA_INIT_NULL;
    BSLB_TextUtil_Base16_Encode(&hex_str, &val, false);
    BSL_LOG_INFO("%s%s", message, hex_str.ptr);
    BSL_Data_Deinit(&hex_str);
}

int BSL_TestUtils_LoadBundleFromCBOR(BSL_TestContext_t *test_ctx, const char *cborhex)
{
    assert(test_ctx != NULL);
    assert(cborhex != NULL);

    int res = BSL_TestUtils_DecodeBase16_cstr(&test_ctx->mock_bpa_ctr.encoded, cborhex);
    if (res != 0)
    {
        BSL_LOG_ERR("Failed to decode base16 text from: %s", cborhex);
        return -1;
    }

    MockBPA_Bundle_t *bundle = test_ctx->mock_bpa_ctr.bundle_ref.data;
    assert(bundle != NULL);

    res = mock_bpa_ctr_decode(&(test_ctx->mock_bpa_ctr));
    if (res)
    {
        return res;
    }

    // additional test checks
    assert(bundle->primary_block.version == 7);
    assert(bundle->primary_block.lifetime > 0);
    assert(bundle->primary_block.flags <= 64);
    assert(bundle->primary_block.crc_type <= 4);
    assert(MockBPA_BlockList_size(bundle->blocks) > 0);
    assert(MockBPA_BlockByNum_size(bundle->blocks_num) > 0);
    return 0;
}

int BSL_TestUtils_EncodeBundleToCBOR(BSL_TestContext_t *test_ctx)
{
    assert(test_ctx != NULL);

    mock_bpa_ctr_sort_blocks(&test_ctx->mock_bpa_ctr);
    int res = mock_bpa_ctr_encode(&test_ctx->mock_bpa_ctr);
    return res;
}

BSL_HostEIDPattern_t BSL_TestUtils_GetEidPatternFromText(const char *text)
{
    BSL_HostEIDPattern_t pat;
    BSL_HostEIDPattern_Init(&pat);
    assert(0 == BSL_HostEIDPattern_DecodeFromText(&pat, text));
    return pat;
}

int BSL_TestUtils_DecodeBase16_cstr(BSL_Data_t *output, const char *input)
{
    return BSLB_TextUtil_Base16_Decode(output, input, strlen(input));
}

int BSL_TestUtils_ModifyEIDs(BSL_BundleRef_t *input_bundle, const char *src_eid, const char *dest_eid,
                             const char *report_to_eid)
{
    BSL_PrimaryBlock_t primary_block;
    BSL_PrimaryBlock_Init(&primary_block);
    BSL_BundleCtx_GetBundleMetadata(input_bundle, &primary_block);
    int res = 0;
    if (src_eid)
    {
        res |= (!!mock_bpa_eid_from_text((BSL_HostEID_t *)(primary_block.field_src_node_id), src_eid, NULL));
    }
    if (dest_eid)
    {
        res |= (!!mock_bpa_eid_from_text((BSL_HostEID_t *)(primary_block.field_dest_eid), dest_eid, NULL) << 1);
    }
    if (report_to_eid)
    {
        res |=
            (!!mock_bpa_eid_from_text((BSL_HostEID_t *)(primary_block.field_report_to_eid), report_to_eid, NULL) << 2);
    }
    BSL_PrimaryBlock_deinit(&primary_block);

    return res;
}

/// Internal state for reader and writer
struct BSL_TestUtils_Flat_Data_s
{
    /// Pointer to external buffer pointer
    void **origbuf;
    /// Pointer to external size
    size_t *origsize;

    /// Pointer to the head of the buffer
    char *ptr;
    /// Working size of the buffer
    size_t size;
    /// File opened for the buffer
    FILE *file;
};

static int BSL_TestUtils_ReadBTSD_Read(void *user_data, void *buf, size_t *bufsize)
{
    struct BSL_TestUtils_Flat_Data_s *obj = user_data;
    if (!obj || !obj->file)
    {
        return -1;
    }

    const size_t got = fread(buf, 1, *bufsize, obj->file);
    *bufsize         = got;
    return 0;
}

static void BSL_TestUtils_ReadBTSD_Deinit(void *user_data)
{
    struct BSL_TestUtils_Flat_Data_s *obj = user_data;
    if (!obj || !obj->file)
    {
        return;
    }

    fclose(obj->file);
    // buffer is external data, no cleanup
    BSL_free(obj);
}

BSL_SeqReader_t *BSL_TestUtils_FlatReader(const void *buf, size_t bufsize)
{
    struct BSL_TestUtils_Flat_Data_s *obj = BSL_calloc(1, sizeof(struct BSL_TestUtils_Flat_Data_s));
    ASSERT_PROPERTY(obj);
    obj->origbuf  = NULL;
    obj->origsize = NULL;
    obj->ptr      = (void *)buf;
    obj->size     = bufsize;
    obj->file     = fmemopen(obj->ptr, obj->size, "rb");

    BSL_SeqReader_t *reader = BSL_malloc(sizeof(BSL_SeqReader_t));
    ASSERT_PROPERTY(reader);
    reader->user_data = obj;
    reader->read      = BSL_TestUtils_ReadBTSD_Read;
    reader->deinit    = BSL_TestUtils_ReadBTSD_Deinit;

    return reader;
}

static int BSL_TestUtils_WriteBTSD_Write(void *user_data, const void *buf, size_t size)
{
    struct BSL_TestUtils_Flat_Data_s *obj = user_data;
    if (!obj || !obj->file)
    {
        return -1;
    }

    const size_t got = fwrite(buf, 1, size, obj->file);
    if (got < size)
    {
        return BSL_ERR_FAILURE;
    }
    return BSL_SUCCESS;
}

static void BSL_TestUtils_WriteBTSD_Deinit(void *user_data, bool success)
{
    struct BSL_TestUtils_Flat_Data_s *obj = user_data;
    if (!obj || !obj->file)
    {
        return;
    }

    fclose(obj->file);

    if (success)
    {
        // now write-back the result
        if (obj->origbuf)
        {
            *obj->origbuf = obj->ptr;
        }
        if (obj->origsize)
        {
            *obj->origsize = obj->size;
        }
    }
    else
    {
        BSL_free(obj->ptr);
    }

    BSL_free(obj);
}

BSL_SeqWriter_t *BSL_TestUtils_FlatWriter(void **buf, size_t *bufsize)
{
    struct BSL_TestUtils_Flat_Data_s *obj = BSL_calloc(1, sizeof(struct BSL_TestUtils_Flat_Data_s));
    ASSERT_PROPERTY(obj);
    // double-buffer for this write
    obj->origbuf  = buf;
    obj->origsize = bufsize;
    obj->ptr      = NULL;
    obj->size     = 0;
    obj->file     = open_memstream(&obj->ptr, &obj->size);

    BSL_SeqWriter_t *writer = BSL_malloc(sizeof(BSL_SeqWriter_t));
    ASSERT_PROPERTY(writer);
    writer->user_data = obj;
    writer->write     = BSL_TestUtils_WriteBTSD_Write;
    writer->deinit    = BSL_TestUtils_WriteBTSD_Deinit;

    return writer;
}
