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
 * Sequential reader interface.
 */
#ifndef BSL_SEQWRITER_H_
#define BSL_SEQWRITER_H_

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// Forward-declaration for file-like interface for a sequential writer.
typedef struct BSL_SeqWriter_s BSL_SeqWriter_t;

/** Release resources from a sequential writer and possibly commit the writes.
 * This also frees memory of the instance itself.
 *
 * @param[in,out] obj The writer handle.
 * @param success Set true if all of the writing succeeded.
 */
void BSL_SeqWriter_Destroy(BSL_SeqWriter_t *obj, bool success);

/** Iterate a sequential writer.
 *
 * @param obj The writer handle.
 * @param[in] buf The input buffer to copy from.
 * @param[in,out] bufsize The available input buffer size as input,
 * set to the used buffer size as output.
 * @return Zero if successful.
 */
int BSL_SeqWriter_Put(BSL_SeqWriter_t *obj, const uint8_t *buf, size_t bufsize);

#ifdef __cplusplus
} // extern C
#endif

#endif /* BSL_SEQWRITER_H_ */
