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
 * Declarations for Agent initialization.
 * @ingroup mock_bpa
 */
#ifndef BSL_MOCK_BPA_H_
#define BSL_MOCK_BPA_H_

#include <BPSecLib_Public.h>
#include <BPSecLib_Private.h>

#include <m-deque.h>
#include <m-dict.h>
#include <m-string.h>

#include <inttypes.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct MockBPA_BundleTimestamp_s
{
    uint64_t bundle_creation_time;
    uint64_t seq_num;
} MockBPA_BundleTimestamp_t;

typedef struct MockBPA_PrimaryBlock_s
{
    uint64_t                  version;
    uint64_t                  flags;
    uint64_t                  crc_type;
    BSL_HostEID_t             dest_eid;
    BSL_HostEID_t             src_node_id;
    BSL_HostEID_t             report_to_eid;
    MockBPA_BundleTimestamp_t timestamp;
    uint64_t                  lifetime;
    uint64_t                  frag_offset;
    uint64_t                  adu_length;

    /// Encoded form owned by this struct
    BSL_Data_t encoded;
} MockBPA_PrimaryBlock_t;

typedef struct MockBPA_CanonicalBlock_s
{
    uint64_t blk_type;
    uint64_t blk_num;
    uint64_t flags;
    uint64_t crc_type;
    void    *btsd;
    size_t   btsd_len;
} MockBPA_CanonicalBlock_t;

#define MockBPA_BUNDLE_MAXBLOCKS (10)
typedef struct MockBPA_Bundle_s
{
    uint64_t                 id;
    bool                     retain;
    MockBPA_PrimaryBlock_t   primary_block;
    MockBPA_CanonicalBlock_t blocks[MockBPA_BUNDLE_MAXBLOCKS];
    size_t                   block_count;
} MockBPA_Bundle_t;

int MockBPA_Bundle_Deinit(MockBPA_Bundle_t *bundle_ref);

int MockBPA_GetBundleMetadata(const BSL_BundleRef_t *bundle_ref, BSL_PrimaryBlock_t *result_primary_block);
int MockBPA_GetBlockNums(const BSL_BundleRef_t *bundle_ref, size_t block_id_array_capacity,
                         uint64_t *block_id_array_result, size_t *result_count);
int MockBPA_GetBlockMetadata(const BSL_BundleRef_t *bundle_ref, uint64_t block_num,
                             BSL_CanonicalBlock_t *result_canonical_block);
int MockBPA_ReallocBTSD(BSL_BundleRef_t *bundle_ref, uint64_t block_num, size_t bytesize);
int MockBPA_CreateBlock(BSL_BundleRef_t *bundle_ref, uint64_t block_type_code, uint64_t *result_block_num);
int MockBPA_RemoveBlock(BSL_BundleRef_t *bundle_ref, uint64_t block_num);
int MockBPA_DeleteBundle(BSL_BundleRef_t *bundle_ref);

/** Register this mock BPA for the current process.
 * @return Zero if successful.
 */
int bsl_mock_bpa_agent_init(void);

/** Clean up the mock BPA for the current process.
 */
void bsl_mock_bpa_agent_deinit(void);

#ifdef __cplusplus
} // extern C
#endif

#endif // BSL_MOCK_BPA_H_
