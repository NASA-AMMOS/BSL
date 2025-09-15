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
 * @brief Implementation of the host BPA and its callback functions.
 * @ingroup backend_dyn
 */
#include <BPSecLib_Private.h>
#include "UtilDefs_SeqReadWrite.h"

// NOLINTNEXTLINE
static BSL_HostDescriptors_t HostDescriptorTable = { 0 };

int BSL_HostDescriptors_Set(BSL_HostDescriptors_t desc)
{
    CHK_PRECONDITION(desc.eid_init);
    CHK_PRECONDITION(desc.get_sec_src_eid_fn);
    CHK_PRECONDITION(desc.eid_deinit);
    CHK_PRECONDITION(desc.bundle_metadata_fn);
    CHK_PRECONDITION(desc.block_metadata_fn);
    CHK_PRECONDITION(desc.block_create_fn);
    CHK_PRECONDITION(desc.block_remove_fn);
    CHK_PRECONDITION(desc.block_realloc_btsd_fn);

    // Old-style callbacks
    CHK_PRECONDITION(desc.eid_from_cbor);
    CHK_PRECONDITION(desc.eid_from_text);
    CHK_PRECONDITION(desc.eidpat_init);
    CHK_PRECONDITION(desc.eidpat_deinit);
    CHK_PRECONDITION(desc.eidpat_from_text);
    CHK_PRECONDITION(desc.eidpat_match);

    HostDescriptorTable = desc;
    return BSL_SUCCESS;
}

int BSL_BundleCtx_GetBundleMetadata(const BSL_BundleRef_t *bundle, BSL_PrimaryBlock_t *result_primary_block)
{
    CHK_ARG_NONNULL(bundle);
    CHK_ARG_NONNULL(result_primary_block);

    CHK_PRECONDITION(HostDescriptorTable.bundle_metadata_fn != NULL);

    memset(result_primary_block, 0, sizeof(*result_primary_block));
    int result = HostDescriptorTable.bundle_metadata_fn(bundle, result_primary_block);
    return (result == 0) ? BSL_SUCCESS : BSL_ERR_HOST_CALLBACK_FAILED;
}

int BSL_BundleCtx_GetBlockMetadata(const BSL_BundleRef_t *bundle, uint64_t block_num,
                                   BSL_CanonicalBlock_t *result_block)
{
    CHK_ARG_NONNULL(bundle);
    CHK_ARG_NONNULL(result_block);
    CHK_ARG_EXPR(block_num > 0);

    CHK_PRECONDITION(HostDescriptorTable.block_metadata_fn != NULL);
    memset(result_block, 0, sizeof(*result_block));
    int result = HostDescriptorTable.block_metadata_fn(bundle, block_num, result_block);
    return (result == 0) ? BSL_SUCCESS : BSL_ERR_HOST_CALLBACK_FAILED;
}

int BSL_BundleCtx_CreateBlock(BSL_BundleRef_t *bundle, uint64_t block_type_code, uint64_t *block_num)
{
    CHK_ARG_NONNULL(bundle);
    CHK_ARG_EXPR(block_type_code > 0);
    CHK_ARG_NONNULL(block_num);

    *block_num = 0;
    CHK_PRECONDITION(HostDescriptorTable.block_create_fn != NULL);
    int result = HostDescriptorTable.block_create_fn(bundle, block_type_code, block_num);
    return (result == 0) ? BSL_SUCCESS : BSL_ERR_HOST_CALLBACK_FAILED;
}

int BSL_BundleCtx_RemoveBlock(BSL_BundleRef_t *bundle, uint64_t block_num)
{
    CHK_ARG_NONNULL(bundle);
    CHK_ARG_EXPR(block_num > 0);
    CHK_PRECONDITION(HostDescriptorTable.block_remove_fn != NULL);
    int result = HostDescriptorTable.block_remove_fn(bundle, block_num);
    return (result == 0) ? BSL_SUCCESS : BSL_ERR_HOST_CALLBACK_FAILED;
}

int BSL_BundleCtx_DeleteBundle(BSL_BundleRef_t *bundle, BSL_ReasonCode_t reason_code)
{
    CHK_ARG_NONNULL(bundle);
    CHK_PRECONDITION(HostDescriptorTable.bundle_delete_fn != NULL);
    int result = HostDescriptorTable.bundle_delete_fn(bundle, reason_code);
    return (result == 0) ? BSL_SUCCESS : BSL_ERR_HOST_CALLBACK_FAILED;
}

int BSL_BundleCtx_ReallocBTSD(BSL_BundleRef_t *bundle, uint64_t block_num, size_t bytesize)
{
    CHK_ARG_NONNULL(bundle);
    CHK_ARG_EXPR(block_num > 0);
    CHK_PRECONDITION(HostDescriptorTable.block_remove_fn != NULL);
    int result = HostDescriptorTable.block_realloc_btsd_fn(bundle, block_num, bytesize);
    return (result == 0) ? BSL_SUCCESS : BSL_ERR_HOST_CALLBACK_FAILED;
}

BSL_SeqReader_t *BSL_BundleCtx_ReadBTSD(const BSL_BundleRef_t *bundle, uint64_t block_num)
{
    if (!bundle || !HostDescriptorTable.block_read_btsd_fn)
    {
        return NULL;
    }
    return HostDescriptorTable.block_read_btsd_fn(bundle, block_num);
}

BSL_SeqWriter_t *BSL_BundleCtx_WriteBTSD(BSL_BundleRef_t *bundle, uint64_t block_num, size_t btsd_len)
{
    if (!bundle || !HostDescriptorTable.block_write_btsd_fn)
    {
        return NULL;
    }
    return HostDescriptorTable.block_write_btsd_fn(bundle, block_num, btsd_len);
}

void BSL_HostDescriptors_Get(BSL_HostDescriptors_t *desc)
{
    ASSERT_ARG_NONNULL(desc);
    *desc = HostDescriptorTable;
}

void BSL_HostDescriptors_Clear(void)
{
    HostDescriptorTable = (BSL_HostDescriptors_t) { 0 };
}

int BSL_HostEID_Init(BSL_HostEID_t *eid)
{
    CHK_ARG_NONNULL(eid);
    CHK_PRECONDITION(HostDescriptorTable.eid_init != NULL);
    return HostDescriptorTable.eid_init(HostDescriptorTable.user_data, eid);
}

void BSL_HostEID_Deinit(BSL_HostEID_t *eid)
{
    ASSERT_ARG_NONNULL(eid);
    ASSERT_PRECONDITION(HostDescriptorTable.eid_deinit != NULL);
    HostDescriptorTable.eid_deinit(HostDescriptorTable.user_data, eid);
}

int BSL_Host_GetSecSrcEID(BSL_HostEID_t *eid)
{
    CHK_ARG_NONNULL(eid);
    CHK_PRECONDITION(HostDescriptorTable.get_sec_src_eid_fn != NULL);
    return HostDescriptorTable.get_sec_src_eid_fn(HostDescriptorTable.user_data, eid);
}

int BSL_HostEID_EncodeToCBOR(const BSL_HostEID_t *eid, BSL_Data_t *encoded_bytes)
{
    CHK_ARG_NONNULL(eid);
    CHK_ARG_NONNULL(encoded_bytes);
    return HostDescriptorTable.eid_to_cbor(eid, encoded_bytes);
}

int BSL_HostEID_DecodeFromCBOR(const BSL_Data_t *encoded_bytes, BSL_HostEID_t *eid)
{
    CHK_ARG_NONNULL(eid);
    CHK_ARG_NONNULL(encoded_bytes);

    CHK_PRECONDITION(eid->handle != NULL);
    int ecode = HostDescriptorTable.eid_from_cbor(encoded_bytes, eid);
    return ecode;
}

int BSL_HostEID_DecodeFromText(BSL_HostEID_t *eid, const char *text)
{
    CHK_ARG_NONNULL(eid);
    CHK_ARG_NONNULL(text);

    CHK_PRECONDITION(eid->handle != NULL);
    CHK_PRECONDITION(HostDescriptorTable.eid_from_text != NULL);

    return HostDescriptorTable.eid_from_text(eid, text, HostDescriptorTable.user_data);
}

int BSL_HostEIDPattern_Init(BSL_HostEIDPattern_t *pat)
{
    CHK_ARG_NONNULL(pat);
    CHK_PRECONDITION(HostDescriptorTable.eidpat_init);
    return HostDescriptorTable.eidpat_init(pat, HostDescriptorTable.user_data);
}

void BSL_HostEIDPattern_Deinit(BSL_HostEIDPattern_t *pat)
{
    ASSERT_ARG_NONNULL(pat);
    HostDescriptorTable.eidpat_deinit(pat, HostDescriptorTable.user_data);
}

int BSL_HostEIDPattern_DecodeFromText(BSL_HostEIDPattern_t *pat, const char *text)
{
    CHK_ARG_NONNULL(pat);
    CHK_ARG_NONNULL(text);
    CHK_PRECONDITION(HostDescriptorTable.eidpat_from_text != NULL);
    return HostDescriptorTable.eidpat_from_text(pat, text, HostDescriptorTable.user_data);
}

bool BSL_HostEIDPattern_IsMatch(const BSL_HostEIDPattern_t *pat, const BSL_HostEID_t *eid)
{
    ASSERT_ARG_NONNULL(pat);
    ASSERT_ARG_NONNULL(eid);
    ASSERT_PRECONDITION(HostDescriptorTable.eidpat_match);
    return HostDescriptorTable.eidpat_match(pat, eid, HostDescriptorTable.user_data);
}
