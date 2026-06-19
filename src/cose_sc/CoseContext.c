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
 * @ingroup cose_sc
 * Implementation of the COSE context @cite draft-ietf-dtn-bpsec-cose.
 */
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include <BPSecLib_Private.h>
#include <CryptoInterface.h>
#include <backend/CBOR.h>

#include "CoseContext.h"

enum BSLX_COSE_Header_e {
    BSLX_COSE_HDR_ALG = 1,
};

typedef struct
{
    /// Bundle context associated with this operation
    const BSL_BundleRef_t *bundle;

    /// True if this operation is the source role
    bool is_source;
    /// Execution return value for procedure interruption
    int retval;

    /// True if #aad_scope came from an option
    bool opt_aad_scope;
    /// Required AAD scope
    int64_t aad_scope;

} BSLX_CoseSc_t;

static void BSLX_CoseSc_Init(BSLX_CoseSc_t *self)
{
    ASSERT_ARG_NONNULL(self);
    memset(self, 0, sizeof(*self));

    self->retval = BSL_SUCCESS;
}

static void BSLX_CoseSc_Deinit(BSLX_CoseSc_t *self)
{
    ASSERT_ARG_NONNULL(self);

    memset(self, 0, sizeof(*self));
}

static void BSLX_CoseSc_Prepare(BSLX_CoseSc_t *self, BSL_BundleRef_t *bundle, const BSL_SecOper_t *sec_oper)
{
    self->is_source = BSL_SecOper_IsRoleSource(sec_oper);
    (void)bundle;
}

static void BSLX_CoseSc_GetOptions(BSLX_CoseSc_t *self)
{
    (void)self;
}

typedef struct {
    int64_t alg;
} BSLX_CoseSc_Mac0_t;

/// Match ::BSL_CBOR_Encode_f signature
static int BSLX_CoseSc_Mac0_Encode(QCBOREncodeContext *enc, const BSLX_CoseSc_Mac0_t *obj)
{
    QCBOREncode_OpenArray(enc);
    {
        // protected bytes
        QCBOREncode_BstrWrap(enc);
        QCBOREncode_OpenMap(enc);

        QCBOREncode_AddInt64(enc, BSLX_COSE_HDR_ALG);
        QCBOREncode_AddInt64(enc, obj->alg);

        QCBOREncode_CloseMap(enc);
        QCBOREncode_CloseBstrWrap(enc, NULL);
    }
    {
        // unprotected
        QCBOREncode_OpenMap(enc);
        QCBOREncode_CloseMap(enc);
    }
    // detached payload
    QCBOREncode_AddNULL(enc);
    // MAC tag
    QCBOREncode_AddBytes(enc, (UsefulBufC){"hi", 2});

    QCBOREncode_CloseArray(enc);
    return BSL_SUCCESS;
}

bool BSLX_CoseSc_Validate(BSL_LibCtx_t *lib, BSL_BundleRef_t *bundle, BSL_SecOper_t *sec_oper)
{
    (void)lib;
    (void)bundle;
    (void)sec_oper;
    return true;
}

int BSLX_CoseSc_Execute(BSL_LibCtx_t *lib _U_, BSL_BundleRef_t *bundle, const BSL_SecOper_t *sec_oper,
                        BSL_SecOutcome_t *sec_outcome)
{
    BSLX_CoseSc_t ctx;
    BSLX_CoseSc_Init(&ctx);
    BSLX_CoseSc_Prepare(&ctx, bundle, sec_oper);

    if (BSL_SUCCESS == ctx.retval)
    {
        BSLX_CoseSc_GetOptions(&ctx);
    }

    if (BSL_SUCCESS == ctx.retval)
    {
        if (ctx.is_source)
        {
            BSLX_CoseSc_Mac0_t msg;
            //            BSLX_CoseSc_GetOptions(&ctx);
            BSL_Data_t msg_enc;
            BSL_Data_Init(&msg_enc);
            int res = BSL_CBOR_Encode_Twopass(&msg_enc, (BSL_CBOR_Encode_f)&BSLX_CoseSc_Mac0_Encode, &msg);
            if (res == BSL_SUCCESS)
            {
                BSL_IdValPair_t *result = BSL_SecOutcome_AppendResult(sec_outcome);
                BSL_IdValPair_SetBytestr(result, BXLS_COSESC_RESULT_COSE_MAC0, msg_enc);
            }
            BSL_Data_Deinit(&msg_enc);
        }
        else
        {}
    }

    int ret = ctx.retval;
    BSLX_CoseSc_Deinit(&ctx);
    return ret;
}
