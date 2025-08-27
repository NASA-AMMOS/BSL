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
 * @ingroup backend_dyn
 * Implementation of flat-buffer sequential access.
 */

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <BPSecLib_Private.h>

#include "backend/UtilDefs_SeqReadWrite.h"

int BSL_SeqReader_Deinit(BSL_SeqReader_t *obj)
{
    CHK_ARG_NONNULL(obj);
    CHK_ARG_NONNULL(obj->deinit);

    obj->deinit(obj->user_data);
    return BSL_SUCCESS;
}

int BSL_SeqReader_Get(BSL_SeqReader_t *obj, uint8_t *buf, size_t *bufsize)
{
    CHK_ARG_NONNULL(obj);
    CHK_ARG_NONNULL(buf);
    CHK_ARG_NONNULL(bufsize);
    CHK_ARG_NONNULL(obj->read);

    return obj->read(obj->user_data, buf, bufsize);
}

int BSL_SeqWriter_Deinit(BSL_SeqWriter_t *obj)
{
    CHK_ARG_NONNULL(obj);
    CHK_ARG_NONNULL(obj->deinit);

    obj->deinit(obj->user_data);
    return BSL_SUCCESS;
}

int BSL_SeqWriter_Put(BSL_SeqWriter_t *obj, const uint8_t *buf, size_t bufsize)
{
    CHK_ARG_NONNULL(obj);
    CHK_ARG_NONNULL(buf);
    CHK_ARG_NONNULL(obj->write);

    return obj->write(obj->user_data, buf, bufsize);
}
