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
 * @ingroup frontend
 * Managed memory interface using only C99 types and functions.
 */
#ifndef BSL_DATA_H_
#define BSL_DATA_H_

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/// Data pointer for BSL_Data_t
typedef uint8_t *BSL_DataPtr_t;
/// Pointer to constant data for BSL_Data_t
typedef const uint8_t *BSL_DataConstPtr_t;

/** Optional heap data storage and views.
 */
typedef struct BSL_Data_s
{
    /** Determine if the data is owned by this instance.
     * True if this data is allocated and deallocated with the lifetime
     * of this struct instance.
     * False if this data is a view onto some other, externally-managed data.
     */
    bool owned;
    /// @brief Pointer to the front of the buffer
    BSL_DataPtr_t ptr;
    /// @brief Size of the data buffer
    size_t len;
} BSL_Data_t;

/** Static initializer for a data store.
 * @sa BSL_Data_Init()
 */
#define BSL_DATA_INIT_NULL                    \
    (BSL_Data_t)                              \
    {                                         \
        .owned = false, .ptr = NULL, .len = 0 \
    }

/** Static initializer for a view on a static text string.
 * @sa BSL_Data_InitView() BSL_Data_SetViewCstr()
 */
#define BSL_DATA_INIT_VIEW_CSTR(cstr)                                                    \
    (BSL_Data_t)                                                                         \
    {                                                                                    \
        .owned = false, .ptr = (BSL_DataPtr_t)(cstr), .len = ((cstr) ? strlen(cstr) : 0) \
    }

/** Initialize an empty data struct.
 *
 * @param[in,out] data The data to initialize, which must not be NULL.
 * @sa BSL_DATA_INIT_NULL
 */
void BSL_Data_Init(BSL_Data_t *data);

/** Initialize with a dynamically-allocated owned buffer of size bytelen
 * *
 * @param[in,out] data The data to initialize.
 * @param[in] bytelen Length of buffer to dynamically allocate.
 * @return Zero upon success.
 */
int BSL_Data_InitBuffer(BSL_Data_t *data, size_t bytelen);

/** Initialize a data struct as an overlay on optional external data.
 *
 * @param[in,out] data The data to initialize, which must not be NULL.
 * @param[in] len The total length to allocate, which may be zero.
 * @param[in] src An optional source buffer to point to.
 */
void BSL_Data_InitView(BSL_Data_t *data, size_t len, BSL_DataPtr_t src);

/** Initialize a data struct with move semantics from an existing struct.
 */
void BSL_Data_InitMove(BSL_Data_t *data, BSL_Data_t *src);

/** De-initialize a data struct, freeing if necessary.
 *
 * @param[in,out] data The data to de-initialize, which must not be NULL.
 * @return Zero upon success.
 * @post The struct must be initialized before using again.
 */
void BSL_Data_Deinit(BSL_Data_t *data);

/** Resize the data, copying if necessary.
 *
 * @param[in,out] data The data to resize, which must not be NULL.
 * @param[in] len The new total size.
 * @return Zero upon success.
 */
int BSL_Data_Resize(BSL_Data_t *data, size_t len);

/** Set an initialized data struct to a given size.
 *
 * @param[in,out] data The data to copy into, which must not be NULL.
 * @param[in] len The total length to allocate, which may be non-zero.
 * @param[in] src An optional source buffer to copy from, from which @c len
 * bytes will be copied.
 * @return Zero upon success.
 */
int BSL_Data_CopyFrom(BSL_Data_t *data, size_t len, BSL_DataConstPtr_t src);

/** Append an initialized data struct with a given size.
 *
 * @param[in,out] data The data to copy into, which must not be NULL.
 * @param[in] len The total length to allocate, which may be non-zero.
 * @param[in] src An optional source buffer to copy from, from which @c len
 * bytes will be copied.
 * @return Zero upon success.
 */
int BSL_Data_AppendFrom(BSL_Data_t *data, size_t len, BSL_DataConstPtr_t src);

/** Set a data struct to be a view onto an existing external bytes.
 *
 * @param[in,out] data The data to create a view from, which must not be NULL.
 * @param[in] cstr The C string pointer to create a view on, which must not be NULL.
 * @return Zero upon success.
 */
int BSL_Data_SetView(BSL_Data_t *data, size_t len, BSL_DataPtr_t src);

/** Set a data struct to be a view onto an existing null-terminated string.
 *
 * @param[in,out] data The data to create a view from, which must not be NULL.
 * @param[in] cstr The C string pointer to create a view on, which must not be NULL.
 * @return Zero upon success.
 */
int BSL_Data_SetViewCstr(BSL_Data_t *data, const char *cstr);

/** Compare two data values returning 0 if equal, or -1 or 1 if not equal.
 * @warning This comparison is not constant time, see BSL_Crypto_compare()
 * for that need.
 *
 * @param[in] lhs The left side to compare.
 * @param[in] rhs The right side to compare.
 * @return Zero if equal, -1 if @c lhs is shorter or 1 if longer, and the
 * output of @c memcmp() if same length.
 */
int BSL_Data_Cmp(const BSL_Data_t *lhs, const BSL_Data_t *rhs);

#ifdef __cplusplus
} // extern C
#endif

#endif /* BSL_DATA_H_ */
