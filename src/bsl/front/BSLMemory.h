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
 * Memory management function declarations.
 */

#ifndef BSL_BSLMEMORY_H_
#define BSL_BSLMEMORY_H_

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/** @brief Dynamic memory allocation.
 * @note This has the same signature as libc @c malloc().
 *
 * @param size size of allocation.
 * @return valid heap pointer or null if failed.
 */
void *BSL_malloc(size_t size);

/** @brief Dynamic memory reallocation.
 * @note This has the same signature as libc @c realloc().
 *
 * @param[in] ptr Optional existing dynamic memory pointer
 * @param size new allocation size
 * @return valid heap pointer or null if failed.
 */
void *BSL_realloc(void *ptr, size_t size);

/** @brief Contiguous dynamic memory allocation
 * @note This has the same signature as libc @c calloc().
 *
 * @param nmemb number of members to allocate
 * @param size size of each member
 * @return valid heap pointer or null if failed.
 */
void *BSL_calloc(size_t nmemb, size_t size);

/** @brief Free dynamically allocated memory.
 * @note This has the same signature as libc @c free().
 *
 * @param ptr pointer to memory to free.
 * This pointer may be null, which is a do-nothing behavior.
 */
void BSL_free(void *ptr);

#ifdef __cplusplus
} // extern C
#endif

#endif /* BSL_BSLMEMORY_H_ */
