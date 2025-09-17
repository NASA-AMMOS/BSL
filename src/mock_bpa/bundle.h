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
 * Declarations for Bundle storage.
 * @ingroup mock_bpa
 */
#ifndef MOCK_BPA_BUNDLE_H_
#define MOCK_BPA_BUNDLE_H_

#include "eid.h"

#include <m-deque.h>
#include <m-bptree.h>

#ifdef __cplusplus
extern "C" {
#endif

/// Timestamp according to Section 4.2.7 of RFC 9171 @cite rfc9171
typedef struct
{
    uint64_t bundle_creation_time;
    uint64_t seq_num;
} MockBPA_CreationTimestamp_t;

/** Structure of the primary block according to
 * Section 4.3.1 of RFC 9171 @cite rfc9171.
 */
typedef struct
{
    uint64_t                    version;
    uint64_t                    flags;
    uint64_t                    crc_type;
    BSL_HostEID_t               dest_eid;
    BSL_HostEID_t               src_node_id;
    BSL_HostEID_t               report_to_eid;
    MockBPA_CreationTimestamp_t timestamp;
    uint64_t                    lifetime;
    uint64_t                    frag_offset;
    uint64_t                    adu_length;

    /// Encoded form owned by this struct
    BSL_Data_t encoded;
} MockBPA_PrimaryBlock_t;

/** Structure of each canonical block according to
 * Section 4.3.2 of RFC 9171 @cite rfc9171.
 */
typedef struct
{
    uint64_t blk_type;
    uint64_t blk_num;
    uint64_t flags;
    uint64_t crc_type;

    /// Pointer to memory managed by the BPA
    void *btsd;
    /// Known length of the #btsd
    size_t btsd_len;
} MockBPA_CanonicalBlock_t;

/** @struct MockBPA_BlockList_t
 * An ordered list of ::MockBPA_CanonicalBlock_t storage
 * with fast size access.
 * BTSD is not managed by this list, but by the BPA itself.
 */
/** @struct MockBPA_BlockByNum_t
 * A lookup from unique block number to ::MockBPA_CanonicalBlock_t pointer.
 */
/// @cond Doxygen_Suppress
// GCOV_EXCL_START
M_DEQUE_DEF(MockBPA_BlockList, MockBPA_CanonicalBlock_t, M_POD_OPLIST)
M_BPTREE_DEF2(MockBPA_BlockByNum, 4, uint64_t, M_BASIC_OPLIST, MockBPA_CanonicalBlock_t *, M_PTR_OPLIST)
// GCOV_EXCL_STOP
/// @endcond

typedef struct MockBPA_Bundle_s
{
    uint64_t               id;
    bool                   retain;
    MockBPA_PrimaryBlock_t primary_block;

    /// Storage for blocks in this bundle
    MockBPA_BlockList_t blocks;
    /// Lookup table by block number
    MockBPA_BlockByNum_t blocks_num;

} MockBPA_Bundle_t;

/** Initialize an empty not-really-valid bundle.
 * @param[out] bundle The struct.
 */
int MockBPA_Bundle_Init(MockBPA_Bundle_t *bundle);

/** Deinitialize any bundle storage.
 * This includes freeing any BTSD.
 * @param[out] bundle The struct.
 */
int MockBPA_Bundle_Deinit(MockBPA_Bundle_t *bundle);

#ifdef __cplusplus
} // extern C
#endif

#endif /* MOCK_BPA_BUNDLE_H_ */
