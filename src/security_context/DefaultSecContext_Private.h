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
 * Contains functions only used internally, however, test utilities can include this to unit test them.
 * @ingroup example_security_context
 */

#ifndef BSLB_DEFAULT_SECURITY_CONTEXT_PRIVATE_H_
#define BSLB_DEFAULT_SECURITY_CONTEXT_PRIVATE_H_

#include <stdint.h>

#include <qcbor/qcbor_encode.h>

#include <BPSecLib_Private.h>
#include <BPSecLib_Public.h>
#include <CryptoInterface.h>

#include "rfc9173.h"

/*
 * Convenience struct containing metadata as a block.
 * Avoids the need to pass many arguments to functions.
 */
typedef struct BSLX_BlockMetadata_s
{
    uint64_t   blk_type;
    uint64_t   blk_num;
    uint64_t   flags;
    uint64_t   crc_type;
    BSL_Data_t btsd;
} BSLX_BlockMetadata_t;

typedef struct BSLX_BIB_s
{
    /// Bundle context associated with this operation
    const BSL_BundleRef_t *bundle;

    /// @brief set to external pointer which will outlive the BIB context
    const char          *key_id;
    BSL_PrimaryBlock_t   primary_block;
    BSL_CanonicalBlock_t target_block;
    BSL_CanonicalBlock_t sec_block;
    int64_t              integrity_scope_flags;
    int64_t              sha_variant;
    uint64_t             hash_size;
    uint64_t             sha_variant_uint;
    int64_t              _crypto_sha_variant;
    BSL_Data_t           wrapped_key;
    int64_t              keywrap;
    uint64_t             hmac_result_id;
    BSL_Data_t           hmac_result_val;
    bool                 is_source;
} BSLX_BIB_t;

int  BSLX_BIB_InitFromSecOper(BSLX_BIB_t *self, const BSL_BundleRef_t *bundle, const BSL_SecOper_t *sec_oper);
void BSLX_BIB_Deinit(BSLX_BIB_t *self);
int  BSLX_BIB_GenIPPT(const BSLX_BIB_t *self, BSL_Data_t *ippt_space);
int  BSLX_BIB_GenHMAC(BSLX_BIB_t *self, const BSL_Data_t *ippt_data);

/**
 * BCB encryption context with crypto primitives.
 */
typedef struct BSLX_BCB_s
{
    /// Bundle context associated with this operation
    BSL_BundleRef_t *bundle;

    size_t err_count;
    /// Pointer to text which will outlive this context
    const char *key_id;

    // Data wrappers and containers for borrowed and owned/allocated buffers
    // These will ALL be deinitialized at the end, so _Deinit MUST be called.
    BSL_Data_t authtag;
    BSL_Data_t iv;
    BSL_Data_t wrapped_key;
    BSL_Data_t debugstr;
    BSL_Data_t aad;

    // Cipher mode variants
    BSL_CipherMode_e          crypto_mode;
    rfc9173_bcb_aes_variant_e aes_variant;
    uint64_t                  aad_scope;

    // Metadata about bundles and blocks
    BSL_PrimaryBlock_t   primary_block;
    BSL_CanonicalBlock_t sec_block;
    BSL_CanonicalBlock_t target_block;

    int64_t keywrap;
    bool    success;
    bool    skip_aad_sec_block;
    bool    skip_aad_target_block;
    bool    skip_aad_prim_block;
} BSLX_BCB_t;

int BSLX_BCB_GetParams(const BSL_BundleRef_t *bundle, BSLX_BCB_t *bcb_context, const BSL_SecOper_t *sec_oper);

int  BSLX_BCB_Init(BSLX_BCB_t *bcb_context, BSL_BundleRef_t *bundle, const BSL_SecOper_t *sec_oper);
void BSLX_BCB_Deinit(BSLX_BCB_t *bcb_context);
int  BSLX_BCB_ComputeAAD(BSLX_BCB_t *bcb_context);
int  BSLX_BCB_Encrypt(BSLX_BCB_t *bcb_context);
void BSLX_EncodeHeader(const BSL_CanonicalBlock_t *block, QCBOREncodeContext *encoder);

#endif
