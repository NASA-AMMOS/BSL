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
 * Private interface for the dynamic backend bundle context.
 */
#ifndef BSL_BUNDLE_DYN_H_
#define BSL_BUNDLE_DYN_H_

#include <BundleContext.h>
#include <DataContainers.h>
#include <HostBPA.h>
#include <AbsSecBlock.h>
#include "DynSeqReadWrite.h"

#include <m-bptree.h>
#include <m-dict.h>
#include <m-shared.h>
#include <qcbor/qcbor_encode.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Metadata and contiguous BTSD for a block from BPv7 @cite rfc9171.
 */
struct BSL_BundleBlock_s
{
    /// The block type code
    uint64_t blk_type;
    /// Unique block number, non-zero
    uint64_t blk_num;
    /// Block processing flags
    uint64_t flags;
    /// CRC type code
    uint64_t crc_type;

    /// View on or copy of the BTSD
    BSL_Data_t btsd;

    /// Singleton reader object
    BSL_SeqReader_t reader;
    /// Singleton reader object
    BSL_SeqWriter_t writer;

    /// @brief New ABS struct, used here temporarily for smoothing integration into existing code.
    BSL_AbsSecBlock_t *abs_sec_blk;
};

/** Match M*LIB signature for INIT.
 *
 * @param[out] obj The object to initialize.
 */
void BSL_BundleBlock_Init(BSL_BundleBlock_t *obj);

/** Match M*LIB signature for INIT_MOVE.
 *
 * @param[out] obj The object to initialize.
 * @param[in,out] src The object to move from.
 */
void BSL_BundleBlock_InitMove(BSL_BundleBlock_t *obj, BSL_BundleBlock_t *src);

/** Match M*LIB signature for SET.
 *
 * @param[out] obj The object to initialize.
 * @param[in] src The object to copy from.
 */
void BSL_BundleBlock_Set(BSL_BundleBlock_t *obj, const BSL_BundleBlock_t *src);

/** Match M*LIB signature for CLEAR.
 *
 * @param[out] obj The object to deinitialize.
 */
void BSL_BundleBlock_Deinit(BSL_BundleBlock_t *obj);

/// NOLINTBEGIN

/// OPLIST for BSL_BundleBlock_t
#define M_OPL_BSL_BundleBlock_t()                                                                                    \
    (INIT(API_2(BSL_BundleBlock_Init)), INIT_MOVE(API_6(BSL_BundleBlock_InitMove)), SET(API_6(BSL_BundleBlock_Set)), \
     CLEAR(API_2(BSL_BundleBlock_Deinit)))

/// @cond Doxygen_Suppress
/// Stable list of info structs
LIST_DEF(BSL_BundleBlockList, BSL_BundleBlock_t)
/// Map from unique block number to info
BPTREE_DEF2(BSL_BundleBlockIdMap, 4, uint64_t, M_BASIC_OPLIST, BSL_BundleBlock_t *, M_PTR_OPLIST)
/// Map from block type code to multiple info
BPTREE_MULTI_DEF2(BSL_BundleBlockTypeMap, 4, uint64_t, M_BASIC_OPLIST, BSL_BundleBlock_t *, M_PTR_OPLIST)
/// @endcond

/// NOLINTEND

/** Concrete definition of bundle context.
 */
struct BSL_BundleCtx_s
{
    /// Parent library context
    BSL_LibCtx_t *parent;
    /// Primary block content
    BSL_BundlePrimaryBlock_t prim_blk;
    /// Original list of block structs
    BSL_BundleBlockList_t blks;
    /// map from block number to pointer into #blks
    BSL_BundleBlockIdMap_t blk_num;
    /// multi-map from block type to pointer into #blks
    BSL_BundleBlockTypeMap_t blk_type;
};

/** Access the primary block for editing.
 * @param[in] bundle The bundle to get primary block from
 * @return Non-null pointer to the primary block data.
 * Ownership is kept by the bundle.
 */
BSL_BundlePrimaryBlock_t *BSL_BundleCtx_GetPrimaryBlock(BSL_BundleCtx_t *bundle);

/** Add block info to this bundle.
 *
 * @param bundle The bundle to add to.
 * @param info The block info to add.
 * @return Zero if successful.
 */
int BSL_BundleCtx_AddBlock(BSL_BundleCtx_t *bundle, BSL_BundleBlock_t info);

/**
 * Remove a bundle from this block indexed by block number.
 *
 * @param bundle The bundle to remove from
 * @param blk_num The block number to remove
 */
int BSL_BundleCtx_RemoveBlock(BSL_BundleCtx_t *bundle, uint64_t blk_num);

/** Lookup a specific block struct.
 *
 * @param bundle The bundle to add to.
 * @param blk_num The block number to search for.
 * @return The block info found, or a NULL pointer.
 */
const BSL_BundleBlock_t *BSL_BundleCtx_GetBlockById(BSL_BundleCtx_t *bundle, uint64_t blk_num);

#ifdef __cplusplus
} // extern C
#endif

#endif // BSL_BUNDLE_DYN_H_
