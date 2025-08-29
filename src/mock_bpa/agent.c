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
#include <security_context/DefaultSecContext.h>
#include <policy_provider/SamplePolicyProvider.h>
#include <assert.h>
#include <errno.h>
#include <poll.h>
#include "agent.h"
#include "eid.h"
#include "eidpat.h"
#include "encode.h"
#include "decode.h"
#include "policy_config.h"
#include "policy_registry.h"

static int MockBPA_GetEid(void *user_data, BSL_HostEID_t *result_eid)
{
    const char *local_ipn = getenv("BSL_TEST_LOCAL_IPN_EID");

    int x = mock_bpa_eid_from_text(result_eid, local_ipn, user_data);

    return (0 == x) ? 0 : -1;
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
    BSL_LOG_DEBUG("closed block %p with size %zu", obj->block, obj->size);

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
    BSL_LOG_DEBUG("opened block %p for size %zu", found_block, total_size);

    struct MockBPA_BTSD_Data_s *obj = BSL_CALLOC(1, sizeof(struct MockBPA_BTSD_Data_s));
    if (!obj)
    {
        return NULL;
    }
    // double-buffer for this write
    obj->block = found_block;
    obj->ptr   = NULL;
    obj->size  = 0;
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

BSL_HostDescriptors_t MockBPA_Agent_Descriptors(MockBPA_Agent_t *agent)
{
    BSL_HostDescriptors_t bpa = {
        .user_data = agent,
        // New-style callbacks
        .get_sec_src_eid_fn    = MockBPA_GetEid,
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
    return bpa;
}

int MockBPA_Agent_Init(MockBPA_Agent_t *agent)
{
    int retval = 0;

    atomic_init(&agent->stop_state, false);

    MockBPA_data_queue_init(agent->over_rx, MOCKBPA_DATA_QUEUE_SIZE);
    MockBPA_data_queue_init(agent->over_tx, MOCKBPA_DATA_QUEUE_SIZE);
    MockBPA_data_queue_init(agent->under_rx, MOCKBPA_DATA_QUEUE_SIZE);
    MockBPA_data_queue_init(agent->under_tx, MOCKBPA_DATA_QUEUE_SIZE);
    MockBPA_data_queue_init(agent->deliver, MOCKBPA_DATA_QUEUE_SIZE);
    MockBPA_data_queue_init(agent->forward, MOCKBPA_DATA_QUEUE_SIZE);
    {
        // event socket for waking the I/O thread
        int fds[2];
        if (pipe(fds) != 0)
        {
            return 3;
        }
        agent->tx_notify_r = fds[0];
        agent->tx_notify_w = fds[1];
    }

    // All BSL contexts get the same config
    BSL_LibCtx_t **bsls[] = {
        &agent->bsl_appin,
        &agent->bsl_appout,
        &agent->bsl_clin,
        &agent->bsl_clout,
    };
    for (size_t ix = 0; (ix < 4) && !retval; ++ix)
    {
        *bsls[ix]         = BSL_CALLOC(1, BSL_LibCtx_Sizeof());
        BSL_LibCtx_t *bsl = *bsls[ix];

        if (BSL_API_InitLib(bsl))
        {
            BSL_LOG_ERR("Failed to initialize BSL");
            retval = 2;
        }

        BSL_SecCtxDesc_t bib_sec_desc;
        bib_sec_desc.execute  = BSLX_BIB_Execute;
        bib_sec_desc.validate = BSLX_BIB_Validate;
        ASSERT_PROPERTY(0 == BSL_API_RegisterSecurityContext(bsl, 1, bib_sec_desc));

        BSL_SecCtxDesc_t bcb_sec_desc;
        bcb_sec_desc.execute  = BSLX_BCB_Execute;
        bcb_sec_desc.validate = BSLX_BCB_Validate;
        ASSERT_PROPERTY(0 == BSL_API_RegisterSecurityContext(bsl, 2, bcb_sec_desc));
    }
    // TODO find a better way to deal with this
    {
        agent->policy_appin               = BSL_CALLOC(1, sizeof(BSLP_PolicyProvider_t));
        BSL_PolicyDesc_t policy_callbacks = (BSL_PolicyDesc_t) { .deinit_fn   = BSLP_Deinit,
                                                                 .query_fn    = BSLP_QueryPolicy,
                                                                 .finalize_fn = BSLP_FinalizePolicy,
                                                                 .user_data   = agent->policy_appin };
        ASSERT_PROPERTY(BSL_SUCCESS == BSL_API_RegisterPolicyProvider(agent->bsl_appin, 1, policy_callbacks));
    }
    {
        agent->policy_appout              = BSL_CALLOC(1, sizeof(BSLP_PolicyProvider_t));
        BSL_PolicyDesc_t policy_callbacks = (BSL_PolicyDesc_t) { .deinit_fn   = BSLP_Deinit,
                                                                 .query_fn    = BSLP_QueryPolicy,
                                                                 .finalize_fn = BSLP_FinalizePolicy,
                                                                 .user_data   = agent->policy_appout };
        ASSERT_PROPERTY(BSL_SUCCESS == BSL_API_RegisterPolicyProvider(agent->bsl_appout, 1, policy_callbacks));
    }
    {
        agent->policy_clin                = BSL_CALLOC(1, sizeof(BSLP_PolicyProvider_t));
        BSL_PolicyDesc_t policy_callbacks = (BSL_PolicyDesc_t) { .deinit_fn   = BSLP_Deinit,
                                                                 .query_fn    = BSLP_QueryPolicy,
                                                                 .finalize_fn = BSLP_FinalizePolicy,
                                                                 .user_data   = agent->policy_clin };
        ASSERT_PROPERTY(BSL_SUCCESS == BSL_API_RegisterPolicyProvider(agent->bsl_clin, 1, policy_callbacks));
    }
    {
        agent->policy_clout               = BSL_CALLOC(1, sizeof(BSLP_PolicyProvider_t));
        BSL_PolicyDesc_t policy_callbacks = (BSL_PolicyDesc_t) { .deinit_fn   = BSLP_Deinit,
                                                                 .query_fn    = BSLP_QueryPolicy,
                                                                 .finalize_fn = BSLP_FinalizePolicy,
                                                                 .user_data   = agent->policy_clout };
        ASSERT_PROPERTY(BSL_SUCCESS == BSL_API_RegisterPolicyProvider(agent->bsl_clout, 1, policy_callbacks));
    }

    pthread_mutex_init(&agent->tlm_mutex, NULL);

    agent->over_addr.sin_family   = 0;
    agent->app_addr.sin_family    = 0;
    agent->under_addr.sin_family  = 0;
    agent->router_addr.sin_family = 0;

    return retval;
}

void MockBPA_Agent_Deinit(MockBPA_Agent_t *agent)
{
    pthread_mutex_destroy(&agent->tlm_mutex);

    // All BSL contexts get the same config
    BSL_LibCtx_t **bsls[] = {
        &agent->bsl_appin,
        &agent->bsl_appout,
        &agent->bsl_clin,
        &agent->bsl_clout,
    };
    for (size_t ix = 0; ix < 4; ++ix)
    {
        if (BSL_API_DeinitLib(*bsls[ix]))
        {
            BSL_LOG_ERR("Failed BSL_API_DeinitLib");
        }
        BSL_FREE(*bsls[ix]);
        *bsls[ix] = NULL;
    }

    close(agent->tx_notify_r);
    close(agent->tx_notify_w);

    MockBPA_data_queue_clear(agent->over_rx);
    MockBPA_data_queue_clear(agent->over_tx);
    MockBPA_data_queue_clear(agent->under_rx);
    MockBPA_data_queue_clear(agent->under_tx);
    MockBPA_data_queue_clear(agent->deliver);
    MockBPA_data_queue_clear(agent->forward);
}

static int bind_udp(int *sock, const struct sockaddr_in *addr)
{
    *sock = socket(addr->sin_family, SOCK_DGRAM, IPPROTO_UDP);
    if (*sock < 0)
    {
        BSL_LOG_ERR("Failed to open UDP socket");
        return 2;
    }
    {
        char nodebuf[INET_ADDRSTRLEN];
        inet_ntop(addr->sin_family, &addr->sin_addr, nodebuf, sizeof(nodebuf));
        BSL_LOG_DEBUG("Binding UDP socket to [%s]:%d", nodebuf, ntohs(addr->sin_port));

        int res = bind(*sock, (struct sockaddr *)addr, sizeof(*addr));
        if (res)
        {
            close(*sock);
            BSL_LOG_ERR("Failed to bind UDP socket, errno %d", errno);
            return 3;
        }
    }

    return 0;
}

/// Display form for counters
#define TLM_COUNTER_FMT "7" PRIu64
/** Aggregate and log telemetry from all BSL contexts.
 */
static void MockBPA_Agent_DumpTelemetry(MockBPA_Agent_t *agent)
{
    BSL_TlmCounters_t tlm = BSL_TLM_COUNTERS_ZERO;

    if (pthread_mutex_lock(&agent->tlm_mutex))
    {
        BSL_LOG_CRIT("failed to lock mutex");
        return;
    }
    {
        const BSL_LibCtx_t *bsls[] = {
            agent->bsl_appin,
            agent->bsl_appout,
            agent->bsl_clin,
            agent->bsl_clout,
        };
        for (size_t ix = 0; ix < sizeof(bsls) / sizeof(bsls[0]); ++ix)
        {
            const BSL_LibCtx_t *bsl = bsls[ix];

            int result = BSL_LibCtx_AccumulateTlmCounters(bsl, &tlm);
            if (result)
            {
                BSL_LOG_ERR("Error with reading telemetry from bsl context");
            }
        }
    }
    pthread_mutex_unlock(&agent->tlm_mutex);

    BSL_LOG_INFO("---------------------------------------------------------");
    BSL_LOG_INFO("---------------------TELEMETRY INFO----------------------");
    BSL_LOG_INFO("                     FAIL COUNT:%" TLM_COUNTER_FMT, tlm.counters[BSL_TLM_SECOP_FAIL_COUNT]);
    BSL_LOG_INFO("         BUNDLE INSPECTED COUNT:%" TLM_COUNTER_FMT, tlm.counters[BSL_TLM_BUNDLE_INSPECTED_COUNT]);
    BSL_LOG_INFO("               ASB DECODE COUNT:%" TLM_COUNTER_FMT, tlm.counters[BSL_TLM_ASB_DECODE_COUNT]);
    BSL_LOG_INFO("               ASB DECODE BYTES:%" TLM_COUNTER_FMT, tlm.counters[BSL_TLM_ASB_DECODE_BYTES]);
    BSL_LOG_INFO("               ASB ENCODE COUNT:%" TLM_COUNTER_FMT, tlm.counters[BSL_TLM_ASB_ENCODE_COUNT]);
    BSL_LOG_INFO("               ASB ENCODE BYTES:%" TLM_COUNTER_FMT, tlm.counters[BSL_TLM_ASB_ENCODE_BYTES]);
    BSL_LOG_INFO("             SECOP SOURCE COUNT:%" TLM_COUNTER_FMT, tlm.counters[BSL_TLM_SECOP_SOURCE_COUNT]);
    BSL_LOG_INFO("           SECOP VERIFIER COUNT:%" TLM_COUNTER_FMT, tlm.counters[BSL_TLM_SECOP_VERIFIER_COUNT]);
    BSL_LOG_INFO("           SECOP ACCEPTOR COUNT:%" TLM_COUNTER_FMT, tlm.counters[BSL_TLM_SECOP_ACCEPTOR_COUNT]);
    BSL_LOG_INFO("                TOTAL TLM COUNT:%" TLM_COUNTER_FMT, tlm.counters[BSL_TLM_TOTAL_COUNT]);
    BSL_LOG_INFO("---------------------------------------------------------");
}

/** Process a single bundle at one of the interaction points.
 *
 * @param[in] agent The agent state, which is not locked for the work thread.
 * @param[in,out] bsl The specific BSL instance to process with.
 * @param loc The interaction point for policy use.
 * @param[in,out] bundle The bundle to process.
 * @return Zero if successful.
 */
static int MockBPA_Agent_process(MockBPA_Agent_t *agent, BSL_LibCtx_t *bsl, BSL_PolicyLocation_e loc,
                                 MockBPA_Bundle_t *bundle)
{
    int returncode = 0;

    BSL_LOG_INFO("starting");
    BSL_SecurityActionSet_t   *malloced_action_set   = BSL_CALLOC(1, BSL_SecurityActionSet_Sizeof());
    BSL_SecurityResponseSet_t *malloced_response_set = BSL_CALLOC(1, BSL_SecurityResponseSet_Sizeof());

    BSL_BundleRef_t bundle_ref = { .data = bundle };
    BSL_LOG_INFO("calling BSL_API_QuerySecurity");
    returncode = BSL_API_QuerySecurity(bsl, malloced_action_set, &bundle_ref, loc);
    if (returncode != 0)
    {
        BSL_LOG_ERR("Failed to query security: code=%d", returncode);
    }

    if (!returncode)
    {
        BSL_LOG_INFO("calling BSL_API_ApplySecurity");
        returncode = BSL_API_ApplySecurity(bsl, malloced_response_set, &bundle_ref, malloced_action_set);
        if (returncode < 0)
        {
            BSL_LOG_ERR("Failed to apply security: code=%d", returncode);
        }
    }

    // Example telemetry dump to log
    MockBPA_Agent_DumpTelemetry(agent);

    BSL_SecurityActionSet_Deinit(malloced_action_set);
    BSL_FREE(malloced_action_set);
    BSL_FREE(malloced_response_set);
    BSL_LOG_INFO("result code %d", returncode);
    return returncode;
}

static void *MockBPA_Agent_work_over_rx(void *arg)
{
    MockBPA_Agent_t *agent = arg;
    BSL_LOG_INFO("started");
    while (true)
    {
        mock_bpa_ctr_t item;
        MockBPA_data_queue_pop(&item, agent->over_rx);
        if (item.encoded.len == 0)
        {
            mock_bpa_ctr_deinit(&item);
            break;
        }
        BSL_LOG_INFO("over_rx item");
        mock_bpa_decode(&item);

        MockBPA_Bundle_t *bundle = item.bundle_ref.data;
        if (MockBPA_Agent_process(agent, agent->bsl_appin, BSL_POLICYLOCATION_APPIN, bundle))
        {
            BSL_LOG_ERR("failed security processing");
            mock_bpa_ctr_deinit(&item);
            continue;
        }
        if (!bundle->retain)
        {
            BSL_LOG_ERR("bundle was marked to delete by BSL");
            mock_bpa_ctr_deinit(&item);
            continue;
        }

        // loopback
        MockBPA_data_queue_push(agent->deliver, item);
    }
    BSL_LOG_INFO("stopped");

    return NULL;
}

static void *MockBPA_Agent_work_under_rx(void *arg)
{
    MockBPA_Agent_t *agent = arg;
    BSL_LOG_INFO("started");
    while (true)
    {
        mock_bpa_ctr_t item;
        MockBPA_data_queue_pop(&item, agent->under_rx);
        if (item.encoded.len == 0)
        {
            mock_bpa_ctr_deinit(&item);
            break;
        }

        BSL_LOG_INFO("under_rx item");
        if (mock_bpa_decode(&item))
        {
            BSL_LOG_ERR("failed to decode bundle");
            mock_bpa_ctr_deinit(&item);
            continue;
        }

        MockBPA_Bundle_t *bundle = item.bundle_ref.data;
        if (MockBPA_Agent_process(agent, agent->bsl_clin, BSL_POLICYLOCATION_CLIN, bundle))
        {
            BSL_LOG_ERR("failed security processing");
            mock_bpa_ctr_deinit(&item);
            continue;
        }
        if (!bundle->retain)
        {
            BSL_LOG_ERR("bundle was marked to delete by BSL");
            mock_bpa_ctr_deinit(&item);
            continue;
        }

        // loopback
        MockBPA_data_queue_push(agent->forward, item);
    }
    BSL_LOG_INFO("stopped");

    return NULL;
}

static void *MockBPA_Agent_work_deliver(void *arg)
{
    MockBPA_Agent_t *agent = arg;
    BSL_LOG_INFO("started");
    while (true)
    {
        mock_bpa_ctr_t item;
        MockBPA_data_queue_pop(&item, agent->deliver);
        if (item.encoded.len == 0)
        {
            mock_bpa_ctr_deinit(&item);
            break;
        }
        BSL_LOG_INFO("deliver item");

        MockBPA_Bundle_t *bundle = item.bundle_ref.data;
        if (MockBPA_Agent_process(agent, agent->bsl_appout, BSL_POLICYLOCATION_APPOUT, bundle))
        {
            BSL_LOG_ERR("failed security processing");
            mock_bpa_ctr_deinit(&item);
            continue;
        }
        if (!bundle->retain)
        {
            BSL_LOG_ERR("bundle was marked to delete by BSL");
            mock_bpa_ctr_deinit(&item);
            continue;
        }

        mock_bpa_encode(&item);
        MockBPA_data_queue_push(agent->over_tx, item);
        {
            uint8_t buf    = 0;
            int     nbytes = write(agent->tx_notify_w, &buf, sizeof(buf));
            if (nbytes < 0)
            {
                BSL_LOG_ERR("Failed to write: %ld", nbytes);
            }
        }
    }
    BSL_LOG_INFO("stopped");

    return NULL;
}

static void *MockBPA_Agent_work_forward(void *arg)
{
    MockBPA_Agent_t *agent = arg;
    BSL_LOG_INFO("started");
    while (true)
    {
        mock_bpa_ctr_t item;
        MockBPA_data_queue_pop(&item, agent->forward);
        if (item.encoded.len == 0)
        {
            mock_bpa_ctr_deinit(&item);
            break;
        }
        BSL_LOG_INFO("forward item");

        MockBPA_Bundle_t *bundle = item.bundle_ref.data;
        if (MockBPA_Agent_process(agent, agent->bsl_clout, BSL_POLICYLOCATION_CLOUT, bundle))
        {
            BSL_LOG_ERR("failed security processing");
            mock_bpa_ctr_deinit(&item);
            continue;
        }
        if (!bundle->retain)
        {
            BSL_LOG_ERR("bundle was marked to delete by BSL");
            mock_bpa_ctr_deinit(&item);
            continue;
        }

        mock_bpa_encode(&item);
        MockBPA_data_queue_push(agent->under_tx, item);
        {
            uint8_t buf    = 0;
            int     nbytes = write(agent->tx_notify_w, &buf, sizeof(uint8_t));
            if (nbytes < 0)
            {
                BSL_LOG_ERR("Failed to write, got %ld", nbytes);
            }
        }
    }
    BSL_LOG_INFO("stopped");

    return NULL;
}

int MockBPA_Agent_Start(MockBPA_Agent_t *agent)
{
    if (pthread_create(&agent->thr_under_rx, NULL, MockBPA_Agent_work_under_rx, agent))
    {
        return 2;
    }
    if (pthread_create(&agent->thr_over_rx, NULL, MockBPA_Agent_work_over_rx, agent))
    {
        return 2;
    }
    if (pthread_create(&agent->thr_deliver, NULL, MockBPA_Agent_work_deliver, agent))
    {
        return 2;
    }
    if (pthread_create(&agent->thr_forward, NULL, MockBPA_Agent_work_forward, agent))
    {
        return 2;
    }
    return 0;
}

void MockBPA_Agent_Stop(MockBPA_Agent_t *agent)
{
    atomic_store(&agent->stop_state, true);

    uint8_t buf    = 0;
    int     nbytes = write(agent->tx_notify_w, &buf, sizeof(buf));
    if (nbytes < 0)
    {
        BSL_LOG_ERR("Failed to write: %ld", nbytes);
    }
}

int MockBPA_Agent_Exec(MockBPA_Agent_t *agent)
{
    int retval = 0;

    int over_sock, under_sock;
    if (bind_udp(&over_sock, &agent->over_addr))
    {
        return 3;
    }
    if (bind_udp(&under_sock, &agent->under_addr))
    {
        return 3;
    }

    struct pollfd pfds[] = {
        { .fd = agent->tx_notify_r, .events = POLLIN },
        { .fd = under_sock },
        { .fd = over_sock },
    };
    struct pollfd *const tx_notify_pfd = pfds;
    struct pollfd *const under_pfd     = pfds + 1;
    struct pollfd *const over_pfd      = pfds + 2;

    BSL_LOG_INFO("READY");

    while (!atomic_load(&agent->stop_state))
    {
        under_pfd->events = POLLIN;
        if (!MockBPA_data_queue_empty_p(agent->under_tx))
        {
            under_pfd->events |= POLLOUT;
        }

        over_pfd->events = POLLIN;
        if (!MockBPA_data_queue_empty_p(agent->over_tx))
        {
            over_pfd->events |= POLLOUT;
        }

        int res = poll(pfds, sizeof(pfds) / sizeof(struct pollfd), -1);
        if (res < 0)
        {
            BSL_LOG_ERR("poll failed with errno: %d", errno);
            if (errno != EINTR)
            {
                retval = 4;
            }
            break;
        }

        if (tx_notify_pfd->revents & POLLIN)
        {
            // no actual data, just clear the pipe
            uint8_t buf;
            int     nbytes = read(agent->tx_notify_r, &buf, sizeof(uint8_t));
            if (nbytes < 0)
            {
                BSL_LOG_ERR("Cannot read: %ld", nbytes);
            }
        }

        if (over_pfd->revents & POLLIN)
        {
            uint8_t      buf[65536];
            struct iovec iov = {
                .iov_base = buf,
                .iov_len  = sizeof(buf),
            };
            struct msghdr msg = {
                .msg_iovlen = 1,
                .msg_iov    = &iov,
            };
            ssize_t got = recvmsg(over_sock, &msg, 0);
            if (got > 0)
            {
                BSL_LOG_DEBUG("over_sock recv %zd", got);
                mock_bpa_ctr_t item;
                mock_bpa_ctr_init(&item);
                BSL_Data_AppendFrom(&item.encoded, got, buf);

                MockBPA_data_queue_push(agent->over_rx, item);
            }
        }
        if (over_pfd->revents & POLLOUT)
        {
            mock_bpa_ctr_t item;
            MockBPA_data_queue_pop(&item, agent->over_tx);

            BSL_LOG_DEBUG("over_sock send %zd", item.encoded.len);
            struct iovec iov = {
                .iov_base = item.encoded.ptr,
                .iov_len  = item.encoded.len,
            };
            struct msghdr msg = {
                .msg_name    = &agent->app_addr,
                .msg_namelen = sizeof(agent->app_addr),
                .msg_iovlen  = 1,
                .msg_iov     = &iov,
            };
            ssize_t got = sendmsg(over_sock, &msg, 0);
            if (got != (ssize_t)item.encoded.len)
            {
                BSL_LOG_ERR("over_sock failed to send all %zd bytes, only %zd sent: %d", item.encoded.len, got, errno);
            }
            mock_bpa_ctr_deinit(&item);
        }

        if (under_pfd->revents & POLLIN)
        {
            uint8_t      buf[65536];
            struct iovec iov = {
                .iov_base = buf,
                .iov_len  = sizeof(buf),
            };
            struct msghdr msg = {
                .msg_iovlen = 1,
                .msg_iov    = &iov,
            };
            ssize_t got = recvmsg(under_sock, &msg, 0);
            if (got > 0)
            {
                BSL_LOG_DEBUG("under_sock recv %zd", got);
                mock_bpa_ctr_t item;
                mock_bpa_ctr_init(&item);
                BSL_Data_AppendFrom(&item.encoded, got, buf);

                MockBPA_data_queue_push(agent->under_rx, item);
            }
        }
        if (under_pfd->revents & POLLOUT)
        {
            mock_bpa_ctr_t item;
            MockBPA_data_queue_pop(&item, agent->under_tx);

            BSL_LOG_DEBUG("under_sock send %zd", item.encoded.len);
            struct iovec iov = {
                .iov_base = item.encoded.ptr,
                .iov_len  = item.encoded.len,
            };
            struct msghdr msg = {
                .msg_name    = &agent->router_addr,
                .msg_namelen = sizeof(agent->router_addr),
                .msg_iovlen  = 1,
                .msg_iov     = &iov,
            };
            ssize_t got = sendmsg(under_sock, &msg, 0);
            if (got != (ssize_t)item.encoded.len)
            {
                BSL_LOG_ERR("under_sock failed to send all %zd bytes, only %zd sent", item.encoded.len, got);
            }
            mock_bpa_ctr_deinit(&item);
        }
    }

    close(over_sock);
    close(under_sock);
    return retval;
}

int MockBPA_Agent_Join(MockBPA_Agent_t *agent)
{
    int errors = 0;
    BSL_LOG_INFO("cleaning up");
    mock_bpa_ctr_t item;

    // join RX workers first
    mock_bpa_ctr_init(&item);
    MockBPA_data_queue_push(agent->under_rx, item);
    mock_bpa_ctr_init(&item);
    MockBPA_data_queue_push(agent->over_rx, item);
    if (pthread_join(agent->thr_under_rx, NULL))
    {
        BSL_LOG_ERR("Failed to join the work_under_rx");
        ++errors;
    }
    if (pthread_join(agent->thr_over_rx, NULL))
    {
        BSL_LOG_ERR("Failed to join the work_over_rx");
        ++errors;
    }

    // then delivery/forward workers after RX are all flushed
    mock_bpa_ctr_init(&item);
    MockBPA_data_queue_push(agent->forward, item);
    mock_bpa_ctr_init(&item);
    MockBPA_data_queue_push(agent->deliver, item);
    if (pthread_join(agent->thr_forward, NULL))
    {
        BSL_LOG_ERR("Failed to join the work_forward");
        ++errors;
    }
    if (pthread_join(agent->thr_deliver, NULL))
    {
        BSL_LOG_ERR("Failed to join the work_deliver");
        ++errors;
    }

    return errors;
}
