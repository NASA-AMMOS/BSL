/**
 * @file
 * @brief Local implementation of locally-defined data structures.
 * @ingroup example_pp
 */
#include <stddef.h>

#include "SamplePolicyProvider.h"
#include "backend/DynBundleContext.h"

bool BSLP_PolicyPredicate_IsConsistent(const BSLP_PolicyPredicate_t *self)
{
    assert(self != NULL);
    assert(self->location > 0);
    assert(self->dst_eid_pattern.handle != NULL);
    assert(self->src_eid_pattern.handle != NULL);
    assert(self->secsrc_eid_pattern.handle != NULL);
    return true;
}
void BSLP_PolicyPredicate_Init(BSLP_PolicyPredicate_t *self,
                               BSL_PolicyLocation_e location,
                               BSL_HostEIDPattern_t src_eid_pattern,
                               BSL_HostEIDPattern_t secsrc_eid_pattern,
                               BSL_HostEIDPattern_t dst_eid_pattern)
{
    // todo - eid patterns should be pointers since they are non-trivial copyable.
    assert(self != NULL);
    memset(self, 0, sizeof(*self));

    self->location = location;
    self->src_eid_pattern = src_eid_pattern;
    self->secsrc_eid_pattern = secsrc_eid_pattern;
    self->dst_eid_pattern = dst_eid_pattern;
    
    assert(BSLP_PolicyPredicate_IsConsistent(self));
}

bool BSLP_PolicyPredicate_IsMatch(const BSLP_PolicyPredicate_t *self, BSL_PolicyLocation_e location, BSL_HostEID_t src_eid, BSL_HostEID_t dst_eid)
{
    assert(BSLP_PolicyPredicate_IsConsistent(self));

    bool is_location_match = location == self->location;
    bool is_src_pattern_match = BSL_HostEIDPattern_IsMatch(&self->src_eid_pattern, &src_eid);
    bool is_dst_pattern_match = BSL_HostEIDPattern_IsMatch(&self->dst_eid_pattern, &dst_eid);

    BSL_LOG_DEBUG("Match: location=%d, src_pattern=%d, dst_pattern=%d",
                  is_location_match, is_src_pattern_match, is_dst_pattern_match);

    return is_location_match && is_src_pattern_match && is_dst_pattern_match;
}

/*
Example Rules:
 - Template: "If Bundle src/dst match PREDICATE, then (ADD|REMOVE|VALIDATE) SEC_BLOCK_TYPE using PARAM-KEY-VALUES"
 - "At ingress from the convergence layer, Bundles matching *.* must have a single BIB covering the primary and payload block using key 9"
 Step 1: Match the Bundle struct with all Rule structs to find a Rule that matches. If no match, reject
   - Things to match on:
     - Bitmask/something for HAS_BIB_ON_PRIMARY, HAS_BIB_ON_PAYLOAD, submasks for BIB_COVERS_PRIMARY, BIB_COVERS_TARGET
 Step 2: Populate security parameters unique to bundle and src/dst pair.
*/
int BSLP_PolicyRule_Init(BSLP_PolicyRule_t *self, const char *desc, BSLP_PolicyPredicate_t predicate, uint64_t context_id,
                         BSL_SecRole_e role, BSL_SecBlockType_e sec_block_type, BSL_BundleBlockTypeCode_e target_block_type)
{
    assert(self != NULL);
    memset(self, 0, sizeof(*self));
    strncpy(self->description, desc, sizeof(self->description)-1);
    self->sec_block_type = sec_block_type;
    self->target_block_type = target_block_type;
    self->predicate = predicate;
    self->context_id = context_id;
    // TODO(bvb) assert Role in expected range
    self->role = role;
    // NOLINTBEGIN
    BSL_SecParamList_init(self->params);
    // NOLINTEND
    
    assert(BSLP_PolicyRule_IsConsistent(self));
    return 0;
}

bool BSLP_PolicyRule_IsConsistent(const BSLP_PolicyRule_t *self)
{
    assert(self != NULL);
    assert(strlen(self->description) < sizeof(self->description));
    assert(self->role > 0);
    assert(self->sec_block_type > 0);
    assert(self->context_id > 0);
    // NOLINTBEGIN
    assert(BSL_SecParamList_size(self->params) < 10000);
    assert(BSLP_PolicyPredicate_IsConsistent(&self->predicate));
    // NOLINTEND
    return true;
}

void BSLP_PolicyRule_Deinit(BSLP_PolicyRule_t *self)
{
    assert(BSLP_PolicyRule_IsConsistent(self));
    BSL_LOG_INFO("BSLP_PolicyRule_Deinit: %s, nparams=%lu", self->description, BSL_SecParamList_size(self->params));
    BSL_HostEIDPattern_Deinit(&self->predicate.dst_eid_pattern);
    BSL_HostEIDPattern_Deinit(&self->predicate.src_eid_pattern);
    BSL_HostEIDPattern_Deinit(&self->predicate.secsrc_eid_pattern);
    // NOLINTBEGIN
    // while (BSL_SecParamList_size(self->params) > 0)
    // {
    //     BSL_SecParam_t *param = NULL;
    //     BSL_SecParamList_pop_back(param, self->params);
    //     assert(param != NULL);
    //     memset(param, 0, sizeof(*param));
    //     free(param);
    // }
    BSL_SecParamList_clear(self->params);
    // NOLINTEND
    memset(self, 0, sizeof(*self));
}

void BSLP_PolicyRule_AddParam(BSLP_PolicyRule_t *self, const BSL_SecParam_t *param)
{
    assert(BSL_SecParam_IsConsistent(param));
    assert(BSLP_PolicyRule_IsConsistent(self));

    BSL_SecParamList_push_back(self->params, *param);

    assert(BSLP_PolicyRule_IsConsistent(self));
}

int BSLP_PolicyRule_EvaluateAsSecOper(const BSLP_PolicyRule_t *self, BSL_SecOper_t *sec_oper, const BSL_BundleCtx_t *bundle, BSL_PolicyLocation_e location)
{
    assert(sec_oper != NULL);
    // assert(BSL_SecOper_IsConsistent(sec_oper));
    assert(BSLP_PolicyRule_IsConsistent(self));

    assert(bundle != NULL);
    memset(sec_oper, 0, sizeof(*sec_oper));

    BSL_HostEID_t src_eid = BSL_BundleCtx_GetSrcEID(bundle);
    BSL_HostEID_t dst_eid = BSL_BundleCtx_GetDstEID(bundle);

    bool is_match = BSLP_PolicyPredicate_IsMatch(&self->predicate, location, src_eid, dst_eid);
    if (!is_match)
    {
        BSL_LOG_WARNING("PolicyRule did not match");
        return -3;
    }

    uint64_t target_block_num;
    if (self->target_block_type == BSL_BLOCK_TYPE_PRIMARY)
    {
        target_block_num = 0;
    }
    else if (self->target_block_type == BSL_BLOCK_TYPE_PAYLOAD)
    {
        const BSL_BundleBlock_t *payload_block = BSL_BundleCtx_CGetPayloadBlock(bundle);
        assert(payload_block != NULL);
        target_block_num = payload_block->blk_num;
    }
    else
    {
        BSL_LOG_ERR("PolicyRule target block type can only be PRIMARY or PAYLOAD, got type %lu", self->target_block_type);
        return -2;
    }

    uint64_t sec_block_num = 0;
    if (self->role != BSL_SECROLE_SOURCE)
    {
        // todo - find the block number with given target block.
        const size_t nblocks = BSL_BundleCtx_GetNumBlocks(bundle);
        for (size_t i = 0; i < nblocks; i++)
        {
            const BSL_BundleBlock_t *block = BSL_BundleCtx_CGetBlockAtIndex(bundle, i);
            if (block->blk_type == self->sec_block_type)
            {
                BSL_AbsSecBlock_t asb;
                if (BSL_AbsSecBlock_DecodeFromCBOR(&asb, block->btsd) == 0)
                {
                    assert(BSL_AbsSecBlock_IsConsistent(&asb));
                    if (BSL_AbsSecBlock_ContainsTarget(&asb, target_block_num))
                    {
                        sec_block_num = block->blk_num;
                    }
                }
                BSL_AbsSecBlock_Deinit(&asb);
            }

            if (sec_block_num == 0)
            {
                BSL_LOG_ERR("Could not find security block with given target.");
                return -7;
            }
        }
    }

    // TODO(bvb) - search for target block matching block type (prim or paylaod)
    BSL_SecOper_Init(sec_oper, self->context_id, target_block_num, sec_block_num, self->sec_block_type, self->role);

    // NOLINTBEGIN
    for M_EACH(sec_param, self->params, LIST_OPLIST(BSL_SecParamList))
    {
        BSL_SecOper_AppendParam(sec_oper, sec_param);
    }
    // NOLINTEND
    
    return 0;
}
