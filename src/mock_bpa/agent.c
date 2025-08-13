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
#include <assert.h>
#include "agent.h"
#include "eid.h"
#include "eidpat.h"
#include "encode.h"
#include "decode.h"

int MockBPA_Bundle_Deinit(MockBPA_Bundle_t *bundle)
{
    assert(bundle != NULL);
    BSL_HostEID_Deinit(&bundle->primary_block.src_node_id);
    BSL_HostEID_Deinit(&bundle->primary_block.dest_eid);
    BSL_HostEID_Deinit(&bundle->primary_block.report_to_eid);
    for (size_t i = 0; i < bundle->block_count; i++)
    {
        free(bundle->blocks[i].btsd);
        memset(&bundle->blocks[i], 0, sizeof(bundle->blocks[i]));
    }
    if (bundle->primary_block.cbor)
    {
        free(bundle->primary_block.cbor);
    }
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
    result_primary_block->block_count                = bundle->block_count;
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
    result_primary_block->cbor                       = bundle->primary_block.cbor;
    result_primary_block->cbor_len                   = bundle->primary_block.cbor_len;

    return 0;
}

int MockBPA_GetBlockNums(const BSL_BundleRef_t *bundle_ref, size_t block_id_array_capacity,
                         uint64_t *block_id_array_result, size_t *result_count)
{
    if (!bundle_ref || !bundle_ref->data || block_id_array_capacity == 0 || !block_id_array_result || !result_count)
    {
        return -1;
    }

    *result_count            = 0;
    MockBPA_Bundle_t *bundle = bundle_ref->data;
    for (size_t i = 0; i < bundle->block_count; i++)
    {
        if (i >= block_id_array_capacity)
        {
            BSL_LOG_ERR("MOCKBPA_GETBLOCKNUMS: Result array too small");
            return -2;
        }

        block_id_array_result[i] = bundle->blocks[i].blk_num;
    }
    *result_count = bundle->block_count;
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

    MockBPA_Bundle_t         *bundle      = bundle_ref->data;
    MockBPA_CanonicalBlock_t *found_block = NULL;
    for (size_t i = 0; i < bundle->block_count; i++)
    {
        if (bundle->blocks[i].blk_num == block_num)
        {
            found_block = &bundle->blocks[i];
        }
    }

    if (found_block == NULL)
    {
        return -3;
    }

    result_canonical_block->block_num = found_block->blk_num;
    result_canonical_block->flags     = found_block->flags;
    result_canonical_block->crc       = found_block->crc_type;
    result_canonical_block->type_code = found_block->blk_type;
    result_canonical_block->btsd      = found_block->btsd;
    result_canonical_block->btsd_len  = found_block->btsd_len;
    return 0;
}

int MockBPA_ReallocBTSD(BSL_BundleRef_t *bundle_ref, uint64_t block_num, size_t bytesize)
{
    if (!bundle_ref || !bundle_ref->data || block_num == 0 || bytesize == 0)
    {
        return -1;
    }

    MockBPA_Bundle_t         *bundle      = bundle_ref->data;
    MockBPA_CanonicalBlock_t *found_block = NULL;
    for (size_t found_index = 0; found_index < bundle->block_count; found_index++)
    {
        if (bundle->blocks[found_index].blk_num == block_num)
        {
            found_block = &bundle->blocks[found_index];
        }
    }

    if (found_block == NULL)
    {
        return -2;
    }

    if (found_block->btsd == NULL)
    {
        found_block->btsd     = calloc(1, bytesize);
        found_block->btsd_len = bytesize;
    }
    else
    {
        found_block->btsd     = realloc(found_block->btsd, bytesize);
        found_block->btsd_len = bytesize;
    }

    // Return -9 if malloc/realloc faile. Return 0 for success.
    return (found_block->btsd == NULL) ? -9 : 0;
}

int MockBPA_CreateBlock(BSL_BundleRef_t *bundle_ref, uint64_t block_type_code, uint64_t *result_block_num)
{
    if (!bundle_ref || !bundle_ref->data || !result_block_num)
    {
        return -1;
    }

    *result_block_num        = 0;
    MockBPA_Bundle_t *bundle = bundle_ref->data;
    if (bundle->block_count >= MockBPA_BUNDLE_MAXBLOCKS)
    {
        return -2;
    }

    uint64_t max_id = 0;
    for (size_t i = 0; i < bundle->block_count; i++)
    {
        max_id = bundle->blocks[i].blk_num >= max_id ? bundle->blocks[i].blk_num : max_id;
    }

    MockBPA_CanonicalBlock_t *new_block = &bundle->blocks[bundle->block_count++];
    memset(new_block, 0, sizeof(*new_block));
    new_block->blk_num  = max_id + 1;
    new_block->blk_type = block_type_code;
    new_block->crc_type = 0;
    new_block->flags    = block_type_code == 12 ? 1 : 0; // BCB should have a flag of 1
    new_block->btsd     = NULL;
    new_block->btsd_len = 0;
    *result_block_num   = new_block->blk_num;
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
    size_t                    found_index = 0;
    for (found_index = 0; found_index < bundle->block_count; found_index++)
    {
        if (bundle->blocks[found_index].blk_num == block_num)
        {
            found_block = &bundle->blocks[found_index];
            break;
        }
    }

    if (found_block == NULL)
    {
        return -2;
    }

    // Deinit and clear the target block for removal
    if (found_block->btsd != NULL)
    {
        free(found_block->btsd);
    }
    memset(found_block, 0, sizeof(*found_block));

    if (bundle->block_count > 1)
    {
        for (size_t dst_index = found_index; dst_index < bundle->block_count - 1; dst_index++)
        {
            printf("Shifting block[%lu] (id=%lu, type=%lu) left", dst_index + 1, bundle->blocks[dst_index + 1].blk_num,
                   bundle->blocks[dst_index + 1].blk_type);
            memcpy(&bundle->blocks[dst_index], &bundle->blocks[dst_index + 1], sizeof(MockBPA_CanonicalBlock_t));
            memset(&bundle->blocks[dst_index + 1], 0, sizeof(MockBPA_CanonicalBlock_t));
        }
    }

    bundle->block_count--;
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
        .bundle_get_block_ids  = MockBPA_GetBlockNums,
        .block_create_fn       = MockBPA_CreateBlock,
        .block_remove_fn       = MockBPA_RemoveBlock,
        .bundle_delete_fn      = MockBPA_DeleteBundle,
        .block_realloc_btsd_fn = MockBPA_ReallocBTSD,

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
