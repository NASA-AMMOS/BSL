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
 * @ingroup frontend
 * Implementation of the data containers for handling variable-sized buffers and ownership.
 */
#include "Data.h"
#include "BPSecLib_Private.h"
#include <string.h>

static void bsl_data_int_reset(BSL_Data_t *data)
{
    ASSERT_ARG_NONNULL(data);

    data->owned = false;
    data->ptr   = NULL;
    data->len   = 0;
    memset(data, 0, sizeof(*data));
}

static void bsl_data_int_free(BSL_Data_t *data)
{
    ASSERT_ARG_NONNULL(data);

    if (data->owned && data->ptr)
    {
        BSL_FREE(data->ptr);
    }
}

int BSL_Data_Init(BSL_Data_t *data)
{
    CHK_ARG_NONNULL(data);
    bsl_data_int_reset(data);
    return BSL_SUCCESS;
}

int BSL_Data_InitBuffer(BSL_Data_t *data, size_t bytelen)
{
    CHK_ARG_NONNULL(data);
    CHK_ARG_EXPR(bytelen > 0);

    bsl_data_int_reset(data);
    data->ptr   = BSL_MALLOC(bytelen);
    data->len   = bytelen;
    data->owned = true;
    memset(data->ptr, 0, bytelen);

    CHK_POSTCONDITION(data->ptr != NULL);
    return BSL_SUCCESS;
}

int BSL_Data_InitView(BSL_Data_t *data, size_t len, const BSL_DataPtr_t src)
{
    CHK_ARG_NONNULL(data);
    CHK_ARG_NONNULL(src);

    data->owned = false;
    data->ptr   = src;
    data->len   = len;
    return BSL_SUCCESS;
}

void BSL_Data_InitMove(BSL_Data_t *data, BSL_Data_t *src)
{
    ASSERT_ARG_NONNULL(data);
    ASSERT_ARG_NONNULL(src);
    *data = *src;
    bsl_data_int_reset(src);
}

int BSL_Data_Deinit(BSL_Data_t *data)
{
    CHK_ARG_NONNULL(data);
    bsl_data_int_free(data);
    memset(data, 0, sizeof(*data));
    return BSL_SUCCESS;
}

int BSL_Data_CopyFrom(BSL_Data_t *data, size_t len, BSL_DataConstPtr_t src)
{
    CHK_ARG_NONNULL(data);

    if (len)
    {
        if (!data->owned)
        {
            data->ptr   = NULL;
            data->owned = true;
        }
        int ecode = BSL_Data_Resize(data, len);
        if (ecode < 0)
        {
            BSL_LOG_ERR("Failed to resize data to %zu bytes", len);
            return ecode;
        }
    }
    else
    {
        bsl_data_int_reset(data);
    }

    if (data->ptr && src && len)
    {
        memcpy(data->ptr, src, len);
    }

    return BSL_SUCCESS;
}

int BSL_Data_Resize(BSL_Data_t *data, size_t len)
{
    CHK_ARG_NONNULL(data);

    if (len == data->len)
    {
        return BSL_SUCCESS;
    }

    if (len == 0)
    {
        bsl_data_int_free(data);
        bsl_data_int_reset(data);
        return BSL_SUCCESS;
    }

    if (!data->owned)
    {
        data->ptr = NULL;
    }
    BSL_DataPtr_t got = BSL_REALLOC(data->ptr, len);
    if (UNLIKELY(!got))
    {
        bsl_data_int_reset(data);
        BSL_LOG_ERR("Failed to realloc");
        return BSL_ERR_INSUFFICIENT_SPACE;
    }
    data->owned = true;
    data->ptr   = got;
    data->len   = len;
    return BSL_SUCCESS;
}

int BSL_Data_AppendFrom(BSL_Data_t *data, size_t len, BSL_DataConstPtr_t src)
{
    CHK_ARG_NONNULL(data);
    CHK_ARG_EXPR(len > 0);
    CHK_ARG_NONNULL(src);

    int ecode = 0;
    if ((ecode = BSL_Data_Resize(data, data->len + len)) < 0)
    {
        BSL_LOG_ERR("Failed to resize");
        return ecode;
    }
    if (len)
    {
        memcpy(&data->ptr[data->len - len], src, len);
    }
    return BSL_SUCCESS;
}
