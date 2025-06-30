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
 * Implementation of the data containers for handling variable-sized buffers and ownership.
 */
#include <assert.h>
#include <string.h>

#include <DataContainers.h>
#include <TypeDefintions.h>

static void bsl_data_int_reset(BSL_Data_t *data)
{
    data->owned = false;
    data->ptr   = NULL;
    data->len   = 0;
    memset(data, 0, sizeof(*data));
}

static void bsl_data_int_free(BSL_Data_t *data)
{
    if (data->owned && data->ptr)
    {
        BSL_FREE(data->ptr);
    }
}

int BSL_Data_Init(BSL_Data_t *data)
{
    CHKERR1(data);
    bsl_data_int_reset(data);
    return 0;
}

int BSL_Data_InitBuffer(BSL_Data_t *data, size_t bytelen)
{
    assert(data != NULL);

    bsl_data_int_reset(data);
    data->ptr   = BSL_MALLOC(bytelen);
    data->len   = bytelen;
    data->owned = true;
    memset(data->ptr, 0, bytelen);

    assert(data->ptr != NULL);
    return 0;
}

int BSL_Data_InitViewOfSlice(BSL_Data_t *data, const BSL_Data_t source_data, size_t offset, size_t len)
{
    assert(data != NULL);

    bsl_data_int_reset(data);
    if (offset + len > source_data.len)
    {
        return -1;
    }
    data->owned = false;
    data->ptr   = &source_data.ptr[offset];
    data->len   = len;

    return 0;
}

int BSL_Data_InitView(BSL_Data_t *data, size_t len, const BSL_DataPtr_t src)
{
    CHKERR1(data);
    data->owned = false;
    data->ptr   = src;
    data->len   = len;
    return 0;
}

int BSL_Data_InitSet(BSL_Data_t *data, const BSL_Data_t *src)
{
    CHKERR1(data);
    CHKERR1(src);
    bsl_data_int_reset(data);
    return BSL_Data_CopyFrom(data, src->len, src->ptr);
}

void BSL_Data_InitMove(BSL_Data_t *data, BSL_Data_t *src)
{
    CHKVOID(data);
    CHKVOID(src);
    *data = *src;
    bsl_data_int_reset(src);
}

int BSL_Data_Deinit(BSL_Data_t *data)
{
    CHKERR1(data);
    bsl_data_int_free(data);
    return 0;
}

int BSL_Data_CopyFrom(BSL_Data_t *data, size_t len, BSL_DataConstPtr_t src)
{
    CHKERR1(data);

    if (len)
    {
        if (!data->owned)
        {
            data->ptr   = NULL;
            data->owned = true;
        }
        if (BSL_Data_Resize(data, len))
        {
            return 2;
        }
    }
    else
    {
        bsl_data_int_reset(data);
    }

    if (data->ptr && src)
    {
        memcpy(data->ptr, src, len);
    }

    return 0;
}

int BSL_Data_Copy(BSL_Data_t *data, const BSL_Data_t *src)
{
    CHKERR1(data);
    CHKERR1(src);

    bsl_data_int_free(data);
    return BSL_Data_CopyFrom(data, src->len, src->ptr);
}

int BSL_Data_Swap(BSL_Data_t *data, BSL_Data_t *other)
{
    CHKERR1(data);
    CHKERR1(other);
    BSL_Data_t tmp = *data;
    *data          = *other;
    *other         = tmp;
    return 0;
}

int BSL_Data_Clear(BSL_Data_t *data)
{
    CHKERR1(data);
    bsl_data_int_free(data);
    bsl_data_int_reset(data);
    return 0;
}

int BSL_Data_Resize(BSL_Data_t *data, size_t len)
{
    CHKERR1(data);

    if (len == data->len)
    {
        return 0;
    }
    else if (len == 0)
    {
        bsl_data_int_free(data);
        bsl_data_int_reset(data);
        return 0;
    }

    if (!data->owned)
    {
        data->ptr = NULL;
    }
    BSL_DataPtr_t got = BSL_REALLOC(data->ptr, len);
    if (UNLIKELY(!got))
    {
        bsl_data_int_reset(data);
        return 2;
    }
    data->owned = true;
    data->ptr   = got;
    data->len   = len;
    return 0;
}

int BSL_Data_ExtendFront(BSL_Data_t *data, ssize_t extra)
{
    CHKERR1(data);
    if (extra == 0)
    {
        return 0;
    }

    size_t origlen = data->len;
    if (extra > 0)
    {
        // adding size, reposition to front
        if (BSL_Data_Resize(data, origlen + extra))
        {
            return 2;
        }
        memmove(data->ptr, data->ptr + extra, origlen);
    }
    else
    {
        // removing size, reposition first
        memmove(data->ptr, data->ptr - extra, origlen + extra);
        if (BSL_Data_Resize(data, origlen + extra))
        {
            return 2;
        }
    }
    return 0;
}

int BSL_Data_AppendFrom(BSL_Data_t *data, size_t len, BSL_DataConstPtr_t src)
{
    CHKERR1(data);
    if (BSL_Data_ExtendBack(data, len))
    {
        return 2;
    }
    memcpy(data->ptr + data->len - len, src, len);
    return 0;
}

int BSL_Data_AppendByte(BSL_Data_t *data, uint8_t val)
{
    CHKERR1(data);
    if (BSL_Data_ExtendBack(data, 1))
    {
        return 2;
    }
    *(data->ptr + data->len - 1) = val;
    return 0;
}
