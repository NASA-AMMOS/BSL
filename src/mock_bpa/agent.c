/*
 * Copyright (c) 2025 The Johns Hopkins University Applied Physics
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
 * Definitions for Agent initialization.
 * @ingroup mock_bpa
 */
#include <BPSecLib_Public.h>
#include <BPSecLib_Private.h>
#include <backend/UtilDefs_SeqReadWrite.h>
#include <assert.h>
#include "agent.h"
#include "eid.h"
#include "eidpat.h"
#include "encode.h"
#include "decode.h"

int MockBPA_Bundle_Init(MockBPA_Bundle_t *bundle)
{
    ASSERT_ARG_NONNULL(bundle);
    memset(bundle, 0, sizeof(*bundle));

    bundle->retain = true;

    MockBPA_BlockList_init(bundle->blocks);
    MockBPA_BlockByNum_init(bundle->blocks_num);

    return 0;
}

int MockBPA_Bundle_Deinit(MockBPA_Bundle_t *bundle)
{
    ASSERT_ARG_NONNULL(bundle);
    BSL_HostEID_Deinit(&bundle->primary_block.src_node_id);
    BSL_HostEID_Deinit(&bundle->primary_block.dest_eid);
    BSL_HostEID_Deinit(&bundle->primary_block.report_to_eid);
    BSL_Data_Deinit(&bundle->primary_block.encoded);

    MockBPA_BlockByNum_clear(bundle->blocks_num);

    MockBPA_BlockList_it_t bit;
    for (MockBPA_BlockList_it(bit, bundle->blocks); !MockBPA_BlockList_end_p(bit); MockBPA_BlockList_next(bit))
    {
        MockBPA_CanonicalBlock_t *blk = MockBPA_BlockList_ref(bit);
        BSL_LOG_DEBUG("freeing block number %" PRIu64, blk->blk_num);
        BSL_FREE(blk->btsd);
    }
    MockBPA_BlockList_clear(bundle->blocks);

    memset(bundle, 0, sizeof(*bundle));
    return 0;
}

int MockBPA_GetBundleMetadata(const BSL_BundleRef_t *bundle_ref, BSL_PrimaryBlock_t *result_primary_block)
{
    if (!bundle_ref || !result_primary_block || !bundle_ref->data)
    {
        return -1;
    }

    MockBPA_Bundle_t *bundle = bundle_ref->data;
    memset(result_primary_block, 0, sizeof(*result_primary_block));
    result_primary_block->field_version              = bundle->primary_block.version;
    result_primary_block->field_flags                = bundle->primary_block.flags;
    result_primary_block->field_crc_type             = bundle->primary_block.crc_type;
    result_primary_block->field_dest_eid             = bundle->primary_block.dest_eid;
    result_primary_block->field_src_node_id          = bundle->primary_block.src_node_id;
    result_primary_block->field_report_to_eid        = bundle->primary_block.report_to_eid;
    result_primary_block->field_bundle_creation_time = bundle->primary_block.timestamp.bundle_creation_time;
    result_primary_block->field_seq_num              = bundle->primary_block.timestamp.seq_num;
    result_primary_block->field_lifetime             = bundle->primary_block.lifetime;
    result_primary_block->field_frag_offset          = bundle->primary_block.frag_offset;
    result_primary_block->field_adu_length           = bundle->primary_block.adu_length;

    BSL_Data_InitView(&result_primary_block->encoded, bundle->primary_block.encoded.len,
                      bundle->primary_block.encoded.ptr);

    result_primary_block->block_count = MockBPA_BlockList_size(bundle->blocks);

    result_primary_block->block_numbers = BSL_CALLOC(result_primary_block->block_count, sizeof(uint64_t));
    if (!result_primary_block->block_numbers)
    {
        return -2;
    }
    size_t                 ix = 0;
    MockBPA_BlockList_it_t bit;
    for (MockBPA_BlockList_it(bit, bundle->blocks); !MockBPA_BlockList_end_p(bit); MockBPA_BlockList_next(bit))
    {
        const MockBPA_CanonicalBlock_t *blk       = MockBPA_BlockList_cref(bit);
        result_primary_block->block_numbers[ix++] = blk->blk_num;
    }

    return 0;
}

int MockBPA_GetBlockMetadata(const BSL_BundleRef_t *bundle_ref, uint64_t block_num,
                             BSL_CanonicalBlock_t *result_canonical_block)
{
    if (!bundle_ref || !result_canonical_block || !bundle_ref->data)
    {
        return -1;
    }

    memset(result_canonical_block, 0, sizeof(*result_canonical_block));

    const MockBPA_Bundle_t *bundle = bundle_ref->data;

    MockBPA_CanonicalBlock_t **found_ptr = MockBPA_BlockByNum_get(bundle->blocks_num, block_num);
    if (found_ptr == NULL)
    {
        return -3;
    }
    const MockBPA_CanonicalBlock_t *found_block = *found_ptr;

    result_canonical_block->block_num = found_block->blk_num;
    result_canonical_block->flags     = found_block->flags;
    result_canonical_block->crc_type  = found_block->crc_type;
    result_canonical_block->type_code = found_block->blk_type;
    result_canonical_block->btsd_len  = found_block->btsd_len;
    return 0;
}

int MockBPA_ReallocBTSD(BSL_BundleRef_t *bundle_ref, uint64_t block_num, size_t bytesize)
{
    if (!bundle_ref || !bundle_ref->data || block_num == 0 || bytesize == 0)
    {
        return -1;
    }

    MockBPA_Bundle_t *bundle = bundle_ref->data;

    MockBPA_CanonicalBlock_t **found_ptr = MockBPA_BlockByNum_get(bundle->blocks_num, block_num);
    if (found_ptr == NULL)
    {
        return -3;
    }
    MockBPA_CanonicalBlock_t *found_block = *found_ptr;

    if (found_block->btsd == NULL)
    {
        found_block->btsd     = BSL_CALLOC(1, bytesize);
        found_block->btsd_len = bytesize;
    }
    else
    {
        found_block->btsd     = BSL_REALLOC(found_block->btsd, bytesize);
        found_block->btsd_len = bytesize;
    }

    // Return -9 if malloc/realloc faile. Return 0 for success.
    return (found_block->btsd == NULL) ? -9 : 0;
}

/// Internal state for reader and writer
struct MockBPA_BTSD_Data_s
{
    /// Block which must have a longer lifetime than the reader/writer
    MockBPA_CanonicalBlock_t *block;

    /// Pointer to the head of the buffer
    char *ptr;
    /// Working size of the buffer
    size_t size;
    /// File opened for the buffer
    FILE *file;
};

static int MockBPA_ReadBTSD_Read(void *user_data, void *buf, size_t *bufsize)
{
    struct MockBPA_BTSD_Data_s *obj = user_data;
    ASSERT_ARG_NONNULL(obj);
    CHK_ARG_NONNULL(buf);
    CHK_ARG_NONNULL(bufsize);
    ASSERT_PRECONDITION(obj->file);

    const size_t got = fread(buf, 1, *bufsize, obj->file);
    BSL_LOG_DEBUG("reading up to %zd bytes, got %zd", *bufsize, got);
    *bufsize = got;
    return 0;
}

static void MockBPA_ReadBTSD_Deinit(void *user_data)
{
    struct MockBPA_BTSD_Data_s *obj = user_data;
    ASSERT_ARG_NONNULL(obj);
    ASSERT_PRECONDITION(obj->file);

    fclose(obj->file);
    // buffer is external data, no cleanup
    BSL_FREE(obj);
}

static struct BSL_SeqReader_s *MockBPA_ReadBTSD(const BSL_BundleRef_t *bundle_ref, uint64_t block_num)
{
    MockBPA_Bundle_t          *bundle    = bundle_ref->data;
    MockBPA_CanonicalBlock_t **found_ptr = MockBPA_BlockByNum_get(bundle->blocks_num, block_num);
    if (found_ptr == NULL)
    {
        return NULL;
    }
    MockBPA_CanonicalBlock_t *found_block = *found_ptr;

    struct MockBPA_BTSD_Data_s *obj = BSL_CALLOC(1, sizeof(struct MockBPA_BTSD_Data_s));
    if (!obj)
    {
        return NULL;
    }
    obj->block = found_block;
    obj->ptr   = found_block->btsd;
    obj->size  = found_block->btsd_len;
    obj->file  = fmemopen(obj->ptr, obj->size, "rb");

    BSL_SeqReader_t *reader = BSL_CALLOC(1, sizeof(BSL_SeqReader_t));
    if (!reader)
    {
        BSL_FREE(obj);
        return NULL;
    }
    reader->user_data = obj;
    reader->read      = MockBPA_ReadBTSD_Read;
    reader->deinit    = MockBPA_ReadBTSD_Deinit;

    return reader;
}

static int MockBPA_WriteBTSD_Write(void *user_data, const void *buf, size_t size)
{
    struct MockBPA_BTSD_Data_s *obj = user_data;
    ASSERT_ARG_NONNULL(obj);
    CHK_ARG_NONNULL(buf);
    ASSERT_PRECONDITION(obj->file);

    const size_t got = fwrite(buf, 1, size, obj->file);
    BSL_LOG_DEBUG("writing up to %zd bytes, got %zd", size, got);
    if (got < size)
    {
        return BSL_ERR_FAILURE;
    }
    return BSL_SUCCESS;
}

static void MockBPA_WriteBTSD_Deinit(void *user_data)
{
    struct MockBPA_BTSD_Data_s *obj = user_data;
    ASSERT_ARG_NONNULL(obj);
    ASSERT_PRECONDITION(obj->file);

    fclose(obj->file);
    BSL_LOG_DEBUG("closed with size %zu", obj->size);

    // now write-back the BTSD
    BSL_FREE(obj->block->btsd);
    obj->block->btsd     = obj->ptr;
    obj->block->btsd_len = obj->size;

    BSL_FREE(obj);
}

static struct BSL_SeqWriter_s *MockBPA_WriteBTSD(BSL_BundleRef_t *bundle_ref, uint64_t block_num, size_t total_size)
{
    MockBPA_Bundle_t          *bundle    = bundle_ref->data;
    MockBPA_CanonicalBlock_t **found_ptr = MockBPA_BlockByNum_get(bundle->blocks_num, block_num);
    if (found_ptr == NULL)
    {
        return NULL;
    }
    MockBPA_CanonicalBlock_t *found_block = *found_ptr;

    struct MockBPA_BTSD_Data_s *obj = BSL_CALLOC(1, sizeof(struct MockBPA_BTSD_Data_s));
    if (!obj)
    {
        return NULL;
    }
    // double-buffer for this write
    obj->block = found_block;
    obj->ptr   = BSL_MALLOC(total_size);
    obj->size  = total_size;
    obj->file  = open_memstream(&obj->ptr, &obj->size);

    BSL_SeqWriter_t *writer = BSL_CALLOC(1, sizeof(BSL_SeqWriter_t));
    if (!writer)
    {
        BSL_FREE(obj->ptr);
        BSL_FREE(obj);
        return NULL;
    }
    writer->user_data = obj;
    writer->write     = MockBPA_WriteBTSD_Write;
    writer->deinit    = MockBPA_WriteBTSD_Deinit;

    return writer;
}

int MockBPA_CreateBlock(BSL_BundleRef_t *bundle_ref, uint64_t block_type_code, uint64_t *result_block_num)
{
    if (!bundle_ref || !bundle_ref->data || !result_block_num)
    {
        return -1;
    }

    *result_block_num        = 0;
    MockBPA_Bundle_t *bundle = bundle_ref->data;

    uint64_t               max_id = 0;
    MockBPA_BlockList_it_t bit;
    for (MockBPA_BlockList_it(bit, bundle->blocks); !MockBPA_BlockList_end_p(bit); MockBPA_BlockList_next(bit))
    {
        const MockBPA_CanonicalBlock_t *blk = MockBPA_BlockList_cref(bit);
        max_id                              = blk->blk_num >= max_id ? blk->blk_num : max_id;
    }
    if (max_id < 1)
    {
        // should have at least a payload already
        return -2;
    }

    MockBPA_CanonicalBlock_t *new_block = MockBPA_BlockList_push_back_new(bundle->blocks);
    memset(new_block, 0, sizeof(*new_block));
    new_block->blk_num  = max_id + 1;
    new_block->blk_type = block_type_code;
    new_block->crc_type = 0;
    new_block->flags    = block_type_code == 12 ? 1 : 0; // BCB should have a flag of 1
    new_block->btsd     = NULL;
    new_block->btsd_len = 0;

    MockBPA_BlockByNum_set_at(bundle->blocks_num, new_block->blk_num, new_block);

    *result_block_num = new_block->blk_num;
    return 0;
}

int MockBPA_RemoveBlock(BSL_BundleRef_t *bundle_ref, uint64_t block_num)
{
    if (!bundle_ref || !bundle_ref->data)
    {
        return -1;
    }

    MockBPA_Bundle_t         *bundle      = bundle_ref->data;
    MockBPA_CanonicalBlock_t *found_block = NULL;

    MockBPA_BlockList_it_t bit;
    for (MockBPA_BlockList_it(bit, bundle->blocks); !MockBPA_BlockList_end_p(bit); MockBPA_BlockList_next(bit))
    {
        MockBPA_CanonicalBlock_t *blk = MockBPA_BlockList_ref(bit);

        if (blk->blk_num == block_num)
        {
            // stop with @c bit on the block
            found_block = blk;
            break;
        }
    }
    if (found_block == NULL)
    {
        return -2;
    }

    // Deinit and clear the target block for removal
    BSL_FREE(found_block->btsd);

    MockBPA_BlockByNum_erase(bundle->blocks_num, block_num);
    MockBPA_BlockList_remove(bundle->blocks, bit);

    return 0;
}

int MockBPA_DeleteBundle(BSL_BundleRef_t *bundle_ref)
{
    if (!bundle_ref || !bundle_ref->data)
    {
        return -1;
    }

    MockBPA_Bundle_t *bundle = bundle_ref->data;

    // Mark the bundle for deletion
    bundle->retain = false;

    return 0;
}

int bsl_mock_bpa_agent_init(void)
{
    uint8_t *state = BSL_MALLOC(999);

    BSL_HostDescriptors_t bpa = {
        .user_data = state,
        // New-style callbacks
        .get_host_eid_fn       = MockBPA_GetEid,
        .bundle_metadata_fn    = MockBPA_GetBundleMetadata,
        .block_metadata_fn     = MockBPA_GetBlockMetadata,
        .block_create_fn       = MockBPA_CreateBlock,
        .block_remove_fn       = MockBPA_RemoveBlock,
        .bundle_delete_fn      = MockBPA_DeleteBundle,
        .block_realloc_btsd_fn = MockBPA_ReallocBTSD,
        .block_read_btsd_fn    = MockBPA_ReadBTSD,
        .block_write_btsd_fn   = MockBPA_WriteBTSD,

        // Old-style callbacks
        .eid_init      = MockBPA_EID_Init,
        .eid_deinit    = MockBPA_EID_Deinit,
        .eid_to_cbor   = (int (*)(void *, const BSL_HostEID_t *))bsl_mock_encode_eid,
        .eid_from_cbor = (int (*)(void *, BSL_HostEID_t *))bsl_mock_decode_eid,
        .eid_from_text = mock_bpa_eid_from_text,
        // .eid_to_text      = mock_bpa_eid_to_text,
        .eidpat_init      = mock_bpa_eidpat_init,
        .eidpat_deinit    = mock_bpa_eidpat_deinit,
        .eidpat_from_text = mock_bpa_eidpat_from_text,
        .eidpat_match     = mock_bpa_eidpat_match,
    };
    return BSL_HostDescriptors_Set(bpa);
}

void bsl_mock_bpa_agent_deinit(void)
{
    BSL_HostDescriptors_t bpa;
    BSL_HostDescriptors_Get(&bpa);
    if (bpa.user_data != NULL)
    {
        BSL_FREE(bpa.user_data);
    }

    BSL_HostDescriptors_t nullbpa = { 0 };
    BSL_HostDescriptors_Set(nullbpa);
}
