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
 * Contains functions only used internally, however, test utilities can include this to unit test them.
 * @ingroup example_security_context
 */

#ifndef _DEFAULT_SEC_CONTEXT_PRIVATE_H_
#define _DEFAULT_SEC_CONTEXT_PRIVATE_H_

#include <BPSecLib.h>

/**
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

typedef struct BSLX_Bytestr_s
{
    uint8_t _bytes[BSL_DEFAULT_BYTESTR_LEN + 1];
    size_t  bytelen;
} BSLX_Bytestr_t;

size_t     BSLX_Bytestr_GetCapacity(void);
BSL_Data_t BSLX_Bytestr_AsData(BSLX_Bytestr_t *self);

typedef struct BSLX_BIBContext_s
{
    int64_t              key_id;
    BSLX_BlockMetadata_t target_block;
    BSLX_BlockMetadata_t sec_block;
    int64_t              integrity_scope_flags;
    int64_t              sha_variant;
    int64_t              _crypto_sha_variant;
    BSLX_Bytestr_t       wrapped_key;
    BSLX_Bytestr_t       override_key;
    uint64_t             hmac_result_id;
    BSLX_Bytestr_t       hmac_result_val;
} BSLX_BIBContext_t;

int BSLX_BIBContext_InitFromSecOper(BSLX_BIBContext_t *self, const BSL_SecOper_t *sec_oper);
int BSLX_BIBContext_GenIPPT(BSLX_BIBContext_t *self, BSL_Data_t ippt_space);
int BSLX_BIBContext_GenHMAC(BSLX_BIBContext_t *self, BSL_Data_t ippt_data);

/**
 * Convenience struct for common bundle block header values.
 */
typedef struct BSLX_BlockHeader_s
{
    uint64_t block_type;
    uint64_t block_num;
    uint64_t control_flags;
} BSLX_BlockHeader_t;

/**
 * Convenience struct for capturing all BCB options and parameters.
 */
typedef struct BSLX_BCBParams_s
{
    size_t                    err_count;
    BSL_Data_t                iv;
    BSL_Data_t                wrapped_key;
    BSL_CryptoCipherCtxMode_e crypto_mode;
    size_t                    aes_variant;
    uint64_t                  key_id;
    // Note, these use "negative" logic, because
    // we don't want a default value (0) to indicate
    // that we should skip it.
    bool               skip_aad_sec_block;
    bool               skip_aad_target_block;
    bool               skip_aad_prim_block;
    BSLX_BlockHeader_t sec_block;
    BSLX_BlockHeader_t target_block;
    //  TODO Field for prim block
} BSLX_BCBParams_t;

/**
 * BCB encryption context with crypto primitives.
 */
typedef struct BSLX_BCBEncryptCtx_s
{
    BSLX_BCBParams_t params;
    BSL_Data_t       debugstr;
    BSL_Data_t       aad;
    BSL_Data_t       plaintext;
    BSL_Data_t       ciphertext;
    BSL_Data_t       authtag;
    bool             success;
} BSLX_BCBEncryptCtx_t;

/**
 * Wrapper for large, variable-sized buffer holding all working data to compete a BCB operation.
 */
typedef struct BSLX_ScratchSpace_s
{
    uint8_t *buffer;
    size_t   size;
    size_t   position;
} BSLX_ScratchSpace_t;

/**
 * Initialize and allocate scratch space.
 */
int BSLX_ScratchSpace_Init(BSLX_ScratchSpace_t *scratch, uint8_t **ptr, size_t alloclen);

/**
 * This means "give me len bytes from the scratch space and increment a counter."
 * This is a convenience to assign space within the scratch space for certain structs.
 */
void                *BSLX_ScratchSpace_take(BSLX_ScratchSpace_t *scratch, size_t len);
BSLX_BCBEncryptCtx_t BSLX_BCBContext_Initialize(BSLX_BCBParams_t params, BSL_Data_t plaintext,
                                                BSLX_ScratchSpace_t *scratch_space);
BSLX_BCBEncryptCtx_t BSLX_BCBContext_ComputeAAD(const BSLX_BCBEncryptCtx_t bcb_input_context);
BSLX_BCBEncryptCtx_t BSLX_BCBContext_Encrypt(const BSLX_BCBEncryptCtx_t bcb_input_context);
BSLX_BCBEncryptCtx_t BSLX_BCBContext_Decrypt(const BSLX_BCBEncryptCtx_t bcb_input_context);

BSLX_BCBParams_t BSLX_GetBCBParams(const BSL_BundleCtx_t *bundle, const BSL_SecOper_t *sec_oper);


#endif
