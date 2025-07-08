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
/** @file
 * @ingroup backend_dyn
 * Implementation of the dynamic backend bundle context.
 */

#include <m-list.h>
#include <m-i-list.h>
#include <qcbor/qcbor_encode.h>
#include <qcbor/qcbor_spiffy_decode.h>

#include <HostBPA.h>
#include <Logging.h>
#include <TypeDefintions.h>

#include "DynBundleContext.h"
#include "DynSeqReadWrite.h"

void BSL_BundleBlock_Init(BSL_BundleBlock_t *obj)
{
    memset(obj, 0, sizeof(BSL_BundleBlock_t));
    BSL_Data_Init(&(obj->btsd));
}

void BSL_BundleBlock_InitMove(BSL_BundleBlock_t *obj, BSL_BundleBlock_t *src)
{
    *obj = *src;
    memset(src, 0, sizeof(BSL_BundleBlock_t));
}

void BSL_BundleBlock_Deinit(BSL_BundleBlock_t *obj)
{
    BSL_Data_Deinit(&(obj->btsd));

    if (obj->abs_sec_blk)
    {
        BSL_AbsSecBlock_Deinit(obj->abs_sec_blk);
        free(obj->abs_sec_blk);
    }
    memset(obj, 0, sizeof(BSL_BundleBlock_t));
}

int BSL_BundleCtx_Init(BSL_BundleCtx_t *bundle, BSL_LibCtx_t *parent)
{
    bundle->parent = parent;

    BSL_BundleBlockList_init(bundle->blks);
    BSL_BundleBlockIdMap_init(bundle->blk_num);
    BSL_BundleBlockTypeMap_init(bundle->blk_type);

    BSL_BundlePrimaryBlock_Init(&bundle->prim_blk);
    return 0;
}

void BSL_BundleCtx_Deinit(BSL_BundleCtx_t *bundle)
{
    BSL_BundlePrimaryBlock_Deinit(&bundle->prim_blk);

    // release each block data
    BSL_BundleBlockTypeMap_clear(bundle->blk_type);
    BSL_BundleBlockIdMap_clear(bundle->blk_num);
    BSL_BundleBlockList_clear(bundle->blks);

    bundle->parent = NULL;
}

BSL_LibCtx_t *BSL_BundleCtx_GetParentLib(BSL_BundleCtx_t *bundle)
{
    return bundle->parent;
}

const BSL_LibCtx_t *BSL_BundleCtx_CGetParentLib(const BSL_BundleCtx_t *bundle)
{
    return bundle->parent;
}

const BSL_BundleBlock_t *BSL_BundleCtx_CGetPayloadBlock(const BSL_BundleCtx_t *bundle)
{
    const BSL_BundleBlock_t *target_block = NULL;
    for
        M_EACH(blk, bundle->blks, ILIST_OPLIST(BSL_BundleBlockList))
        {
            if (blk->blk_type == BSL_BLOCK_TYPE_PAYLOAD)
            {
                target_block = blk;
                break;
            }
        }
    return target_block;
}

int BSL_BundleCtx_CreateBlock(BSL_BundleCtx_t *bundle, uint64_t block_type)
{
    BSL_BundleBlock_t new_block;
    BSL_BundleBlock_Init(&new_block);
    new_block.blk_type = block_type;
    // TODO - this should change to get the max of any block ID, and then add one to it.
    new_block.blk_num  = BSL_BundleBlockList_size(bundle->blks) + 1;
    new_block.crc_type = 0;
    new_block.flags    = 0;
    if (BSL_BundleCtx_AddBlock((BSL_BundleCtx_t *)bundle, new_block) != 0)
    {
        BSL_LOG_ERR("Could not add block to bundle");
        return -1;
    }

    return (int)new_block.blk_num;
}

BSL_BundlePrimaryBlock_t *BSL_BundleCtx_GetPrimaryBlock(BSL_BundleCtx_t *bundle)
{
    return &(bundle->prim_blk);
}

const BSL_BundlePrimaryBlock_t *BSL_BundleCtx_CGetPrimaryBlock(const BSL_BundleCtx_t *bundle)
{
    return &(bundle->prim_blk);
}

BSL_HostEID_t BSL_BundleCtx_GetSrcEID(const BSL_BundleCtx_t *self)
{
    assert(self != NULL);
    return self->prim_blk.src_node_id;
}

BSL_HostEID_t BSL_BundleCtx_GetDstEID(const BSL_BundleCtx_t *self)
{
    assert(self != NULL);
    return self->prim_blk.dest_eid;
}

int BSL_BundleContext_GetBlockMetadata(const BSL_BundleCtx_t *bundle, uint64_t blk_num, uint64_t *blk_type,
                                       uint64_t *flags, uint64_t *crc_type, BSL_Data_t *btsd)
{
    assertNonNull(bundle);
    const size_t             blk_list_len = BSL_BundleBlockList_size(bundle->blks);
    const BSL_BundleBlock_t *found;
    const BSL_BundleBlock_t *info = NULL;

    size_t i;
    for (i = 0; i < blk_list_len; i++)
    {
        found = BSL_BundleBlockList_cget(bundle->blks, i);
        if (found != NULL && (found->blk_num == blk_num))
        {
            info = found;
            break;
        }
    }

    if (!info)
    {
        // BSL_LOG_WARNING("Block #%lu missing in bundle", blk_num);
        return -1;
    }

    if (blk_type)
    {
        *blk_type = info->blk_type;
    }
    if (flags)
    {
        *flags = info->flags;
    }
    if (crc_type)
    {
        *crc_type = info->crc_type;
    }
    if (btsd)
    {
        BSL_Data_InitView(btsd, info->btsd.len, info->btsd.ptr);
        // *btsd = info->btsd;
    }
    return 0;
}

size_t BSL_BundleCtx_GetNumBlocks(const BSL_BundleCtx_t *bundle)
{
    assert(bundle != NULL);
    return BSL_BundleBlockList_size(bundle->blks);
}

const BSL_BundleBlock_t *BSL_BundleCtx_CGetBlockAtIndex(const BSL_BundleCtx_t *bundle, uint64_t index)
{
    assert(bundle != NULL);
    return BSL_BundleBlockList_cget(bundle->blks, index);
}

// TODO - Should bundle here be const?
int BSL_BundleCtx_ReadBTSD(BSL_BundleCtx_t *bundle, uint64_t blk_num, BSL_SeqReader_t **reader)
{
    if (!bundle || !reader)
    {
        return 1;
    }
    BSL_BundleBlock_t *const *found = BSL_BundleBlockIdMap_cget(bundle->blk_num, blk_num);
    if (!found)
    {
        return 2;
    }
    BSL_BundleBlock_t *info = *found;

    *reader = &(info->reader);
    if (BSL_SeqReader_InitFlat(*reader, info->btsd.ptr, info->btsd.len))
    {
        return 3;
    }
    return 0;
}

int BSL_BundleCtx_WriteBTSD(BSL_BundleCtx_t *bundle, uint64_t blk_num, BSL_SeqWriter_t **writer)
{
    if (!bundle || !writer)
    {
        return 1;
    }
    BSL_BundleBlock_t *const *found = BSL_BundleBlockIdMap_cget(bundle->blk_num, blk_num);
    if (!found)
    {
        return 2;
    }
    BSL_BundleBlock_t *info = *found;

    *writer = &(info->writer);
    BSL_Data_Deinit(&(info->btsd));
    if (BSL_SeqWriter_InitFlat(*writer, (uint8_t **)&(info->btsd.ptr), &(info->btsd.len)))
    {
        return 3;
    }
    info->btsd.owned = true;
    return 0;
}

int BSL_BundleCtx_AddBlock(BSL_BundleCtx_t *bundle, BSL_BundleBlock_t info)
{
    BSL_BundleBlock_t *item = BSL_BundleBlockList_push_new(bundle->blks);

    // actual parameter copy
    *item = info;

    BSL_BundleBlockIdMap_set_at(bundle->blk_num, item->blk_num, item);
    BSL_BundleBlockTypeMap_set_at(bundle->blk_type, item->blk_type, item);

    // special indexing for security blocks
    if ((item->blk_type == BSL_BLOCK_TYPE_BIB) || (item->blk_type == BSL_BLOCK_TYPE_BCB))
    {
        item->abs_sec_blk = BSL_MALLOC(sizeof(*item->abs_sec_blk));
        /// FIXME(bvb) this is a shim for now
        BSL_HostEID_t sec_source;
        BSL_HostEID_Init(&sec_source);
        BSL_Host_GetSecSrcEID(&sec_source);
        /// FIXME(bvb) work on consistency check with context ID isn't known.
        BSL_AbsSecBlock_Init(item->abs_sec_blk, 999, sec_source);
    }

    return 0;
}

int BSL_BundleCtx_RemoveBlock(BSL_BundleCtx_t *bundle, uint64_t blk_num)
{
    assert(bundle != NULL);

    if (blk_num == 0)
    {
        BSL_LOG_ERR("Cannot remove primary block");
        return -1;
    }

    if (BSL_BundleBlockList_size(bundle->blks) == 0)
    {
        BSL_LOG_ERR("Cannot remove block from empty list");
        return -1;
    }

    BSL_BundleBlockList_it_t *blk_iter_ptr = NULL;
    BSL_BundleBlockList_it_t  blk_iter;
    for (BSL_BundleBlockList_it(blk_iter, bundle->blks); !BSL_BundleBlockList_end_p(blk_iter);
         BSL_BundleBlockList_next(blk_iter))
    {
        if (BSL_BundleBlockList_cref(blk_iter)->blk_num == blk_num)
        {
            blk_iter_ptr = &blk_iter;
            break;
        }
    }

    if (blk_iter_ptr == NULL)
    {
        BSL_LOG_ERR("Cannot find target block #%lu", blk_num);
        return -1;
    }
    BSL_BundleBlockList_remove((struct BSL_BundleBlockList_s **)bundle->blks, *blk_iter_ptr);
    return 0;
}

const BSL_BundleBlock_t *BSL_BundleCtx_GetBlockById(BSL_BundleCtx_t *bundle, uint64_t blk_num)
{
    const BSL_BundleBlock_t *target_block = NULL;
    for
        M_EACH(blk, bundle->blks, ILIST_OPLIST(BSL_BundleBlockList))
        {
            if (blk->blk_num == blk_num)
            {
                target_block = blk;
                break;
            }
        }
    return target_block;
}

void BSL_BundlePrimaryBlock_Init(BSL_BundlePrimaryBlock_t *blk)
{
    CHKVOID(blk);
    memset(blk, 0, sizeof(BSL_BundlePrimaryBlock_t));
    blk->version = 7,

    BSL_HostEID_Init(&(blk->dest_eid));
    BSL_HostEID_Init(&(blk->src_node_id));
    BSL_HostEID_Init(&(blk->report_to_eid));
}

int BSL_BundlePrimaryBlock_Init_move(BSL_BundlePrimaryBlock_t *dest, BSL_BundlePrimaryBlock_t *src)
{
    CHKERR1(dest);
    CHKERR1(src);

    // ownership transfers with contained pointers
    *dest = *src;
    memset(src, 0, sizeof(BSL_BundlePrimaryBlock_t));
    return 0;
}

void BSL_BundlePrimaryBlock_Deinit(BSL_BundlePrimaryBlock_t *blk)
{
    CHKVOID(blk);

    BSL_HostEID_Deinit(&(blk->dest_eid));
    BSL_HostEID_Deinit(&(blk->src_node_id));
    BSL_HostEID_Deinit(&(blk->report_to_eid));

    memset(blk, 0, sizeof(BSL_BundlePrimaryBlock_t));
}
