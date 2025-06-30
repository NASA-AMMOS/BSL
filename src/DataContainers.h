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
 * Abstract interface for containers managing variable-length data buffers and pointer ownership.
 * @ingroup frontend
 */
#ifndef BSL_DATA_H_
#define BSL_DATA_H_

#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <unistd.h>

#ifdef __cplusplus
extern "C" {
#endif

/// Data pointer for BSL_Data_t
typedef uint8_t *BSL_DataPtr_t;
/// Pointer to constant data for BSL_Data_t
typedef const uint8_t *BSL_DataConstPtr_t;

/** Heap data storage and views.
 */
typedef struct BSL_Data_s
{
    /// True if this data is a copy
    bool owned;
    /// Pointer to the front of the buffer
    BSL_DataPtr_t ptr;
    /// Size of the data buffer
    size_t len;
} BSL_Data_t;

/** Static initializer for a data store.
 * @sa BSL_Data_Init()
 */
#define BSL_DATA_INIT_NULL { .owned = false, .ptr = NULL, .len = 0 }

/** Initialize an empty data struct.
 *
 * @param[in,out] data The data to initialize, which must not be NULL.
 * @return Zero upon success.
 * @sa BSL_DATA_INIT_NULL
 */
int BSL_Data_Init(BSL_Data_t *data);

/** Initialize with an owned buffer of size bytelen
 *
 * @todo Clarify to indicate this calls MALLOC.
 * 
 * @param[in, out] data The data to initialize.
 * @param bytelen Length of buffer to allocate.
 * @return Zero upon success.
 */
int BSL_Data_InitBuffer(BSL_Data_t *data, size_t bytelen);

/** Initialize a data struct as an overlay on optional external data.
 *
 * @param[in,out] data The data to initialize, which must not be NULL.
 * @param len The total length to allocate, which may be zero.
 * @param src An optional source buffer to point to.
 * @return Zero upon success.
 */
int BSL_Data_InitView(BSL_Data_t *data, size_t len, BSL_DataPtr_t src);

/** View a slice of a buffer from a given offset and len
 *
 * @param[in,out] data The data to initialize as the slice
 * @param source_data The source data to read a slice from
 * @param offset The offset (in bytes) to start the read from
 * @param len The length (in bytes) of the data to read from the offset
 * @return Zero upon success, negative on error (such as when offset+len > source_data.len)
 */
int BSL_Data_InitViewOfSlice(BSL_Data_t *data, BSL_Data_t source_data, size_t offset, size_t len);

/** Initialize as a copy of other data.
 *
 * @param[in,out] data The data to initialize, which must not be NULL.
 * @param[in] src The source to copy from, which must not be NULL.
 * @return Zero upon success.
 */
int BSL_Data_InitSet(BSL_Data_t *data, const BSL_Data_t *src);

/// @overload
void BSL_Data_InitMove(BSL_Data_t *data, BSL_Data_t *src);

/** De-initialize a data struct, freeing if necessary.
 *
 * @param[in,out] data The data to de-initialize, which must not be NULL.
 * @return Zero upon success.
 * @post The struct must be initialized before using again.
 */
int BSL_Data_Deinit(BSL_Data_t *data);

/** Clear the data, freeing if necessary.
 *
 * @param[in,out] data The data to clear, which must not be NULL.
 * @return Zero upon success.
 */
int BSL_Data_Clear(BSL_Data_t *data);

/** Resize the data, copying if necessary.
 *
 * @param[in,out] data The data to resize, which must not be NULL.
 * @param len The new total size.
 * @return Zero upon success.
 */
int BSL_Data_Resize(BSL_Data_t *data, size_t len);

/** Alter the size at the back of the array by a difference value.
 *
 * @param[in,out] data The data to resize, which must not be NULL.
 * @param extra The difference of the desired size from the current size.
 * This may be negative to shrink the data.
 * @return Zero upon success.
 */
static inline int BSL_Data_ExtendBack(BSL_Data_t *data, ssize_t extra)
{
    return BSL_Data_Resize(data, data->len + extra);
}

/** Alter the size at the front of the array by a difference value.
 *
 * @param[in,out] data The data to resize, which must not be NULL.
 * @param extra The difference of the desired size from the current size.
 * This may be negative to shrink the data.
 * @return Zero upon success.
 */
int BSL_Data_ExtendFront(BSL_Data_t *data, ssize_t extra);

/** Set an initialized data struct to a given size.
 *
 * @param[in,out] data The data to copy into, which must not be NULL.
 * @param len The total length to allocate, which may be non-zero.
 * @param src An optional source buffer to copy from, from which @c len
 * bytes will be copied.
 * @return Zero upon success.
 */
int BSL_Data_CopyFrom(BSL_Data_t *data, size_t len, BSL_DataConstPtr_t src);

/** Append an initialized data struct with a given size.
 *
 * @param[in,out] data The data to copy into, which must not be NULL.
 * @param len The total length to allocate, which may be non-zero.
 * @param src An optional source buffer to copy from, from which @c len
 * bytes will be copied.
 * @return Zero upon success.
 */
int BSL_Data_AppendFrom(BSL_Data_t *data, size_t len, BSL_DataConstPtr_t src);

/** @overload
 */
int BSL_Data_AppendByte(BSL_Data_t *data, uint8_t val);

/** Copy between two data structs, both already initialized.
 *
 * @param[in,out] data The data to copy to, which must not be NULL.
 * @param src The data to copy from, which must not be NULL.
 * @return Zero upon success.
 */
int BSL_Data_Copy(BSL_Data_t *data, const BSL_Data_t *src);

/** Swap between two data structs, both already initialized.
 *
 * @param[in,out] data The data to swap to, which must not be NULL.
 * @param[in,out] other The data to swap with, which must not be NULL.
 * @return Zero upon success.
 */
int BSL_Data_Swap(BSL_Data_t *data, BSL_Data_t *other);

#ifdef __cplusplus
}
#endif

#endif /* BSL_DATA_H_ */
