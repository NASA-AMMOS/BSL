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
 * @ingroup backend_dyn
 * Implementation of flat-buffer sequential access.
 */

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <TypeDefintions.h>

#include "backend/DynSeqReadWrite.h"

int BSL_SeqReader_Deinit(BSL_SeqReader_t *obj _U_)
{
    // nothing to do here
    return 0;
}

int BSL_SeqReader_InitFlat(BSL_SeqReader_t *obj, const uint8_t *buf, size_t bufsize)
{
    if (!obj)
    {
        return 2;
    }
    obj->cursor = buf;
    obj->remain = bufsize;

    return 0;
}

int BSL_SeqReader_Get(BSL_SeqReader_t *obj, uint8_t *buf, size_t *bufsize)
{
    CHKERR1(obj != NULL);
    CHKERR1(buf != NULL);
    CHKERR1(bufsize != NULL);

    const size_t got = (obj->remain < *bufsize ? obj->remain : *bufsize);
    if (got > 0)
    {
        memcpy(buf, obj->cursor, got);
        obj->cursor += got;
        obj->remain -= got;
    }
    *bufsize = got;
    return 0;
}

int BSL_SeqWriter_InitFlat(BSL_SeqWriter_t *obj, uint8_t **buf, size_t *bufsize)
{
    if (!obj)
    {
        return 1;
    }

    obj->fd = open_memstream((char **)buf, bufsize);
    if (!(obj->fd))
    {
        return 2;
    }

    return 0;
}

int BSL_SeqWriter_Deinit(BSL_SeqWriter_t *obj)
{
    if (!obj)
    {
        return 1;
    }
    fclose(obj->fd);
    obj->fd = NULL;

    return 0;
}

int BSL_SeqWriter_Put(BSL_SeqWriter_t *obj, const uint8_t *buf, size_t *bufsize)
{
    if (!obj || !buf || !bufsize)
    {
        return 1;
    }

    const size_t got = fwrite(buf, 1, *bufsize, obj->fd);
    if (got > 0)
    {
        *bufsize = got;
    }
    return 0;
}
