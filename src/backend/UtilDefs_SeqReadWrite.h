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
 * @brief Flat buffer data reading and writing.
 * @ingroup backend_dyn
 */
#ifndef BSL_SEQ_DATA_FLAT_H_
#define BSL_SEQ_DATA_FLAT_H_

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include <BPSecLib_Private.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Definition of a simple flat buffer iterator.
 */
struct BSL_SeqReader_s
{
    /// Context from the BPA
    void *user_data;

    /** Called to read a block of data from the source.
     * This pointer must not be NULL.
     *
     * @param[in] user_data The context pointer.
     * @param[out] buf The buffer to read into, which must be large enough
     * to hold the initial value of @c size.
     * @param[in,out] size The input of the buffer size, and set to the actual
     * size of data read upon completion.
     * @return Zero if successful.
     */
    int (*read)(void *user_data, void *buf, size_t *size);

    /** Called to close this reader and free its resources.
     * This pointer must not be NULL.
     *
     * @param[in] user_data The context pointer.
     */
    void (*deinit)(void *user_data);
};

/** Definition of a sequential writer using callbacks.
 */
struct BSL_SeqWriter_s
{
    /// Context from the BPA
    void *user_data;

    /** Called to read a block of data from the source.
     * This pointer must not be NULL.
     *
     * @param[in] user_data The context pointer.
     * @param[in] buf The buffer to write from, with its size indicated by @c size.
     * @param size The input of the buffer size.
     * @return Zero if successful writing the entire size.
     */
    int (*write)(void *user_data, const void *buf, size_t size);

    /** Called to close this writer and free its resources.
     * This pointer must not be NULL.
     *
     * @param[in] user_data The context pointer.
     * @post The data written to the block is reflected in later reads and/or
     * block metadata.
     */
    void (*deinit)(void *user_data);
};

#ifdef __cplusplus
} // extern C
#endif

#endif // BSL_SEQ_DATA_FLAT_H_
