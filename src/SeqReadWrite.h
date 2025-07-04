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
 * Abstract interface for sequential data reading and writing.
 * @ingroup frontend
 */
#ifndef BSL_SEQ_DATA_H_
#define BSL_SEQ_DATA_H_

#include "LibContext.h"
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/// Forward declaration for this type
typedef struct BSL_SeqReader BSL_SeqReader_t;

/** Release resources from a sequential reader.
 *
 * @param[in,out] obj The reader handle.
 * @return Zero if successful.
 */
int BSL_SeqReader_Deinit(BSL_SeqReader_t *obj);

/** Iterate a sequential reader.
 *
 * @param obj The reader handle.
 * @param[out] buf The output buffer to fill.
 * @param[in,out] bufsize The available output buffer size as input,
 * set to the used buffer size as output.
 * @return Zero if successful.
 */
int BSL_SeqReader_Get(BSL_SeqReader_t *obj, uint8_t *buf, size_t *bufsize);

/// Forward declaration for this type
typedef struct BSL_SeqWriter BSL_SeqWriter_t;

/** Release resources from a sequential writer.
 *
 * @param[in,out] obj The writer handle.
 * @return Zero if successful.
 */
int BSL_SeqWriter_Deinit(BSL_SeqWriter_t *obj);

/** Iterate a sequential writer.
 *
 * @param obj The writer handle.
 * @param[in] buf The input buffer to copy from.
 * @param[in,out] bufsize The available input buffer size as input,
 * set to the used buffer size as output.
 * @return Zero if successful.
 */
int BSL_SeqWriter_Put(BSL_SeqWriter_t *obj, const uint8_t *buf, size_t *bufsize);

#ifdef __cplusplus
} // extern C
#endif

#endif // BSL_SEQ_DATA_H_
