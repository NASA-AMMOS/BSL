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
    /// Current cursor into available data
    const uint8_t *cursor;
    /// Remaining available buffer
    size_t remain;
};

/** Initialize resources for a sequential reader.
 *
 * @param[in,out] obj The reader struct to allocate.
 * @param buf The flat buffer start.
 * @param bufsize The flat buffer total size.
 * @return Zero if successful.
 */
int BSL_SeqReader_InitFlat(BSL_SeqReader_t *obj, const uint8_t *buf, size_t bufsize);

/** Definition of a simple flat buffer iterator.
 */
struct BSL_SeqWriter_s
{
    /// Memory mapped file
    FILE *fd;
};

/** Initialize resources for a sequential writer.
 *
 * @param[in,out] obj The reader struct to allocate.
 * @param[out] buf The flat buffer pointer to update after the writer is released.
 * @param[out] bufsize The flat buffer total size pointer to update after the
 * writer is released.
 * @return Zero if successful.
 */
int BSL_SeqWriter_InitFlat(BSL_SeqWriter_t *obj, uint8_t **buf, size_t *bufsize);

#ifdef __cplusplus
} // extern C
#endif

#endif // BSL_SEQ_DATA_FLAT_H_
