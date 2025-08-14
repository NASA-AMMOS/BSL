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
 * Header for the implementation of an example default security context (RFC 9173).
 * @ingroup example_security_context
 */
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include <qcbor/qcbor_encode.h>
#include <qcbor/qcbor_spiffy_decode.h>

#include <BPSecLib_Private.h>
#include <CryptoInterface.h>

#include "DefaultSecContext.h"
#include "DefaultSecContext_Private.h"
#include "rfc9173.h"

void BSLX_EncodeHeader(const BSL_CanonicalBlock_t *block, QCBOREncodeContext *encoder)
{
    ASSERT_ARG_NONNULL(block);
    ASSERT_ARG_NONNULL(encoder);
    BSL_LOG_INFO("  >>> AAD Encoding: %"PRIu64", %"PRIu64", %"PRIu64, block->type_code, block->block_num, block->flags);
    QCBOREncode_AddUInt64(encoder, block->type_code);
    QCBOREncode_AddUInt64(encoder, block->block_num);
    QCBOREncode_AddUInt64(encoder, block->flags);
}

void *BSLX_ScratchSpace_take(BSLX_ScratchSpace_t *scratch, size_t len)
{
    ASSERT_ARG_NONNULL(scratch);
    ASSERT_ARG_EXPR(scratch->position + len < scratch->size);

    uint8_t *target = &scratch->buffer[scratch->position];
    memset(target, 0, len);
    // We give a padding of 16 bytes between objects for safety
    scratch->position += (len + 16);
    return target;
}
