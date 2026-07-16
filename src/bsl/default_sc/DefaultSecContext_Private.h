/*
 * Copyright (c) 2025-2026 The Johns Hopkins University Applied Physics
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
 * @ingroup default_sc
 * Contains functions only used internally, however, test utilities can include this to unit test them.
 */

#ifndef BSLB_DEFAULT_SECURITY_CONTEXT_PRIVATE_H_
#define BSLB_DEFAULT_SECURITY_CONTEXT_PRIVATE_H_

#include <stdint.h>

#include <qcbor/qcbor_encode.h>

#include <bsl/BPSecLib_Private.h>
#include <bsl/BPSecLib_Public.h>
#include <bsl/crypto/CryptoInterface.h>

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

    /// True if this operation is the source role
    bool is_source;
    /// Error counter for procedure interruption
    size_t err_count;

    /// View on external text which will outlive the BIB context
    BSL_Data_t key_id;

    BSL_PrimaryBlock_t   primary_block;
    BSL_CanonicalBlock_t target_block;
    BSL_CanonicalBlock_t sec_block;
    /// True if #ippt_scope came from an option
    bool opt_ippt_scope;
    /// Required IPPT scope
    int64_t ippt_scope;
    /// True if #sha_variant came from an option
    bool opt_sha_variant;
    /// Required SHA variant
    int64_t sha_variant;
    /// Converted #sha_variant into enum value
    BSL_Crypto_SHAVariant_e crypto_sha_variant;

    BSL_Data_t wrapped_key;
    int64_t    keywrap;
    BSL_Data_t hmac_result_val;
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

    /// True if this operation is the source role
    bool is_source;
    /// Error counter for procedure interruption
    size_t err_count;

    /// View into to text which will outlive this context
    BSL_Data_t key_id;

    // Data wrappers and containers for borrowed and owned/allocated buffers
    // These will ALL be deinitialized at the end, so _Deinit MUST be called.
    BSL_Data_t authtag;
    BSL_Data_t iv;
    BSL_Data_t wrapped_key;
    BSL_Data_t aad;

    /// Cipher mode variants
    BSL_CipherMode_e crypto_mode;
    /// Required AES variant (external code point)
    int64_t aes_variant;
    /// Internal enumeration for #aes_variant
    BSL_Crypto_AESVariant_e bsl_aes;
    /// Required key size for #aes_variant
    size_t keysize;

    /// True if #aad_scope came from an option
    bool opt_aad_scope;
    /// Required AAD scope
    int64_t aad_scope;

    // Metadata about bundles and blocks
    BSL_PrimaryBlock_t   primary_block;
    BSL_CanonicalBlock_t sec_block;
    BSL_CanonicalBlock_t target_block;

    int64_t keywrap;
    bool    success;
    /// True if this is a source or acceptor role and target BTSD is replaced
    bool overwrite_btsd;
} BSLX_BCB_t;

/** Populate the BCB context with options from the operation.
 */
int BSLX_BCB_GetOptions(const BSL_BundleRef_t *bundle, BSLX_BCB_t *bcb_context, const BSL_SecOper_t *sec_oper);

int  BSLX_BCB_Init(BSLX_BCB_t *bcb_context, BSL_BundleRef_t *bundle, const BSL_SecOper_t *sec_oper);
void BSLX_BCB_Deinit(BSLX_BCB_t *bcb_context);
int  BSLX_BCB_ComputeAAD(BSLX_BCB_t *bcb_context);
int  BSLX_BCB_Encrypt(BSLX_BCB_t *bcb_context);
void BSLX_EncodeHeader(const BSL_CanonicalBlock_t *block, QCBOREncodeContext *encoder);

#endif
