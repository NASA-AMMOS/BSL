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
 * Header for the implementation of an example default security context (RFC 9173).
 * @ingroup example_security_context
 */
#include <time.h>
#include <stdio.h>

#include <qcbor/qcbor_encode.h>
#include <qcbor/qcbor_spiffy_decode.h>

#include <BPSecLib.h>
#include "DefaultSecContext.h"
#include "DefaultSecContext_Private.h"
#include "rfc9173.h"

int BSLX_ScratchSpace_Init(BSLX_ScratchSpace_t *scratch, uint8_t **ptr, size_t alloclen)
{
    assert(scratch != NULL);
    memset(scratch, 0, sizeof(*scratch));
    *ptr = malloc(alloclen);
    assert(*ptr != NULL);
    scratch->buffer = *ptr;
    assert(scratch->buffer != NULL);
    scratch->size = alloclen;
    // We start at 16 bytes in as a safety margin
    scratch->position = 16;

    return 0;
}

void *BSLX_ScratchSpace_take(BSLX_ScratchSpace_t *scratch, size_t len)
{
    assert(scratch != NULL);
    assert(scratch->position + len < scratch->size);

    uint8_t *target = &scratch->buffer[scratch->position];
    memset(target, 0, len);
    // We give a padding of 16 bytes between objects for safety
    scratch->position += (len + 16);
    return target;
}
