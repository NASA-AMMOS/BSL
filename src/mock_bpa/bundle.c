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
#include "bundle.h"

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
