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
