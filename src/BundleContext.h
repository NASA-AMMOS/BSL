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
 * Abstract interface for a bundle context.
 * @ingroup frontend
 */
#ifndef BSL_BUNDLE_CTX_H_
#define BSL_BUNDLE_CTX_H_

#include <stdint.h>

#include "HostBPA.h"
#include "DataContainers.h"
#include "LibContext.h"
#include "SeqReadWrite.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Block types using IANA-assigned code points from @cite iana:bundle.
 */
typedef enum
{
    /// @brief Primary block ID (a special case)
    BSL_BLOCK_TYPE_PRIMARY = 0,
    /// Payload block
    BSL_BLOCK_TYPE_PAYLOAD = 1,
    /// Block Integrity @cite iana:bundle
    BSL_BLOCK_TYPE_BIB = 11,
    /// Block Confidentiality @cite iana:bundle
    BSL_BLOCK_TYPE_BCB = 12,
} BSL_BundleBlockTypeCode_e;

/** Flags of the Abstract Security Block @cite rfc9172.
 */
typedef enum
{
    /// Flag set when parameters are present
    BSL_ASB_FLAG_PARAMS = 1
} BSL_BundleASBFlag_e;

/** Creation Timestamp
 *  Defined in Section 4.2.7 of RFC 9171 @cite rfc9171
 */
typedef struct BSL_BundleTimestamp_s
{
    /// Creation timestamp DTN creation time
    uint64_t bundle_creation_time;
    /// Creation timestamp sequence number
    uint64_t seq_num;
} BSL_BundleTimestamp_t;

/** Bundle processing control flags.
 * Defined in Section 4.2.3 of RFC 9171 @cite rfc9171.
 */
typedef enum
{
    /// Set if this bundle is a fragment
    BSL_BUNDLE_IS_FRAGMENT = 0x0001,
    // Others TBD
} BSL_BundleCtrlFlag_e;

/** Block CRC types.
 * Defined in Section 4.2.1 of RFC 9171 @cite rfc9171.
 */
typedef enum
{
    /// No CRC value
    BSL_BUNDLECRCTYPE_NONE = 0,
    /// CRC-16
    BSL_BUNDLECRCTYPE_16 = 1,
    /// CRC-32C
    BSL_BUNDLECRCTYPE_32 = 2,
} BSL_BundleCRCType_e;

/** Primary block struct.
 *  Defined in Section 4.3.1 of RFC 9171 @cite rfc9171.
 */
typedef struct
{
    /// Bundle Protocol Version
    uint64_t version;
    /** Bundle Processing Control Flags.
     * These should be a logical combination of ::BSL_BundleCtrlFlag_e values.
     */
    uint64_t flags;
    /** CRC Type.
     * This should be one of the ::BSL_BundleCRCType_e values.
     */
    uint64_t crc_type;
    /// EID of destination
    BSL_HostEID_t dest_eid;
    /// EID of source node
    BSL_HostEID_t src_node_id;
    /// EID for status reports
    BSL_HostEID_t report_to_eid;
    /// Creation timestamp
    BSL_BundleTimestamp_t timestamp;
    /// Lifetime field
    uint64_t lifetime;
    /// Optional iff control flags indicate bundle is a fragment
    uint64_t frag_offset;
    /// Optional iff control flags indicate bundle is a fragment
    uint64_t adu_length;
} BSL_BundlePrimaryBlock_t;

/**
 * Initialize primary block info struct.
 * The default state has version 7 and all other fields zero.
 *
 * @param[out] blk primary block info struct
 */
void BSL_BundlePrimaryBlock_Init(BSL_BundlePrimaryBlock_t *blk);

/**
 * Initialize primary block info struct
 * @todo Possibly move, this may be MLib specific.
 * @param[out] dest pointer to primary block to be initialized and set
 * @param[in,out] src primary block info struct to be moved from
 * @return 0 if successful
 */
int BSL_BundlePrimaryBlock_Init_move(BSL_BundlePrimaryBlock_t *dest, BSL_BundlePrimaryBlock_t *src);

/**
 * Deinitialize primary block info struct
 * @param[in,out] blk The primary block info.
 */
void BSL_BundlePrimaryBlock_Deinit(BSL_BundlePrimaryBlock_t *blk);

/** Forward declaration for the Bundle Context.
 * This struct is used as the context for all single-bundle data accesses.
 */
typedef struct BSL_BundleCtx_s BSL_BundleCtx_t;

/** Forward declaration for a Bundle Block
 * 
 */
typedef struct BSL_BundleBlock_s BSL_BundleBlock_t;

/** Initialize resources for a bundle context.
 * @param[in,out] bundle The context struct.
 * @param parent The library context to work under.
 * @return Zero if successful.
 */
int BSL_BundleCtx_Init(BSL_BundleCtx_t *bundle, BSL_LibCtx_t *parent);

/** Release resources from a bundle context.
 * @param[in,out] bundle The context struct.
 */
void BSL_BundleCtx_Deinit(BSL_BundleCtx_t *bundle);

/** Get the library context to which a bundle context is bound.
 * @param[in] bundle The bundle context to get for.
 * @return The associated library context, which is never NULL.
 */
BSL_LibCtx_t *BSL_BundleCtx_GetParentLib(BSL_BundleCtx_t *bundle);

/** @overload
 *
 * @param[in] bundle The bundle context to get for.
 * @return The associated library context, which is never NULL.
 */
const BSL_LibCtx_t *BSL_BundleCtx_CGetParentLib(const BSL_BundleCtx_t *bundle);

/** Access the primary block struct.
 * @param[in] bundle The bundle to get primary block from
 * @return Non-null pointer to the primary block data.
 * Ownership is kept by the bundle.
 */
const BSL_BundlePrimaryBlock_t *BSL_BundleCtx_CGetPrimaryBlock(const BSL_BundleCtx_t *bundle);

/** Get the payload block struct
 * @param[in] bundle The bundle to get payload block from
 * @return Possibly null pointer to the payload block data
 */
const BSL_BundleBlock_t *BSL_BundleCtx_CGetPayloadBlock(const BSL_BundleCtx_t *bundle);


/** Indicate to host we want a new block of the given type in the bundle.
 * 
 * @note block_type must be >= 2. We cannot create new payload or primary blocks.
 * 
 * @param[in,out] bundle The bundle to create a block for
 * @param[in] block_type Block type that must be greater than 1.
 * 
 * @returns The block number of the newly-created block. Negative on error.
 */
int BSL_BundleCtx_CreateBlock(BSL_BundleCtx_t *bundle, uint64_t block_type);

/** Return the host-specific security source EID
 * 
 * @param self This bundle
 */
BSL_HostEID_t BSL_BundleCtx_GetSrcEID(const BSL_BundleCtx_t *self);

/** Return host-specific destination EID
 * 
 * @param self This bundle.
 */
BSL_HostEID_t BSL_BundleCtx_GetDstEID(const BSL_BundleCtx_t *self);

/** Get block metadata from a bundle.
 *
 * @param bundle The bundle to query.
 * @param blk_num The block number to look up.
 * @param[out] blk_type Pointer to the type code of the block, if found.
 * @param[out] flags Pointer to the flags of the block, if found.
 * @param[out] crc_type Pointer to the CRC type of the block, if found.
 * @param[out] btsd Pointer to the size of the BTSD for the block, if found.
 * @return Zero if successful.
 */
int BSL_BundleContext_GetBlockMetadata(const BSL_BundleCtx_t *bundle, uint64_t blk_num, uint64_t *blk_type,
                                       uint64_t *flags, uint64_t *crc_type, BSL_Data_t *btsd);

/** Returns the number of non-primary blocks in the bundle.
 * 
 * @param bundle This bundle
 * @return Number of canonical blocks in bundle (including payload).
 */
size_t BSL_BundleCtx_GetNumBlocks(const BSL_BundleCtx_t *bundle);

/** Returns the bundle block at the given INDEX (NOT block id)
 * 
 * @param bundle This bundle.
 * @param index Block list INDEX
 * @return Block at the given index, NULL if not present.
 */
const BSL_BundleBlock_t *BSL_BundleCtx_CGetBlockAtIndex(const BSL_BundleCtx_t *bundle, uint64_t index);

/** Initialize a new BTSD reader.
 *
 * @param bundle The bundle to query.
 * @param blk_num The block number to look up.
 * @param[out] reader The initialized reader object, which must have
 * BSL_SeqReader_Deinit() called on it after using it.
 * @return Zero if successful.
 */
int BSL_BundleCtx_ReadBTSD(BSL_BundleCtx_t *bundle, uint64_t blk_num, BSL_SeqReader_t **reader);

/** Initialize a new BTSD writer.
 *
 * @param bundle The bundle to query.
 * @param blk_num The block number to look up.
 * @param[out] writer The initialized reader object, which must have
 * BSL_SeqWriter_Deinit() called on it after using it.
 * @return Zero if successful.
 */
int BSL_BundleCtx_WriteBTSD(BSL_BundleCtx_t *bundle, uint64_t blk_num, BSL_SeqWriter_t **writer);


#ifdef __cplusplus
} // extern C
#endif

#endif // BSL_BUNDLE_CTX_H_
